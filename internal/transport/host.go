package transport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"tailscale.com/client/tailscale"
	"tailscale.com/tsnet"

	"github.com/changhoon-sung/tsok/overlay"
	"github.com/changhoon-sung/tsok/tsserver"
)

type UDPHandler func(ctx context.Context, conn net.Conn, port uint16)

type HostOptions struct {
	CommonOptions
	UDPHandler UDPHandler
	AuthState  *overlay.ReceiveState
}

type udpPort struct {
	listener net.Listener
	sessions map[string]struct{}
}

type Host struct {
	ctx        context.Context
	cancel     context.CancelFunc
	receive    *overlay.Receive
	control    interface{ Close() error }
	ts         *tsnet.Server
	lc         *tailscale.LocalClient
	logf       Logf
	udpHandler UDPHandler
	listenUDP  func(port uint16) (net.Listener, error)
	udpMu      sync.Mutex
	udpPorts   map[uint16]*udpPort
	// tcpPeers gates new fallback connections, while tcpConns lets overlay
	// session closure interrupt already-established userspace TCP flows.
	tcpMu    sync.Mutex
	tcpConns map[netip.Addr]map[net.Conn]struct{}
	tcpPeers map[netip.Addr]struct{}
	close    sync.Once
}

func StartHost(ctx context.Context, opts HostOptions) (_ *Host, err error) {
	opts.CommonOptions = normalizeOptions(opts.CommonOptions)
	if opts.DERPMap == nil {
		return nil, errors.New("DERP map is required")
	}
	hostCtx, cancel := context.WithCancel(ctx)
	h := &Host{
		ctx: hostCtx, cancel: cancel, logf: opts.Logf, udpHandler: opts.UDPHandler,
		udpPorts: make(map[uint16]*udpPort), tcpConns: make(map[netip.Addr]map[net.Conn]struct{}),
		tcpPeers: make(map[netip.Addr]struct{}),
	}
	defer func() {
		if err != nil {
			_ = h.Close()
		}
	}()

	if opts.AuthState == nil {
		h.receive = overlay.NewReceiveOverlay(opts.Logger, overlay.Logf(opts.Logf), opts.DERPMap)
		if err := h.receive.PickDERPHome(hostCtx); err != nil {
			return nil, err
		}
	} else {
		h.receive, err = overlay.NewReceiveOverlayWithState(opts.Logger, overlay.Logf(opts.Logf), opts.DERPMap, *opts.AuthState)
		if err != nil {
			return nil, err
		}
	}
	h.receive.SetOpenUDPHandler(h.openUDP)
	h.receive.SetSessionUpdatedHandler(h.updateSession)
	h.receive.SetSessionClosedHandler(h.closeSession)

	control, err := tsserver.NewServer(hostCtx, opts.Logger, h.receive, opts.DERPMap)
	if err != nil {
		return nil, err
	}
	h.control = control
	go func() {
		if runErr := control.ListenAndServe(hostCtx); runErr != nil && hostCtx.Err() == nil {
			opts.Logger.Error("local control server stopped", "err", runErr)
		}
	}()
	h.ts, err = newTSNet("receive", opts.CommonOptions, control.ControlURL())
	if err != nil {
		return nil, err
	}
	if _, err := h.ts.Up(hostCtx); err != nil {
		return nil, fmt.Errorf("bring WireGuard up: %w", err)
	}
	h.listenUDP = func(port uint16) (net.Listener, error) {
		return h.ts.Listen("udp", fmt.Sprintf(":%d", port))
	}
	h.lc, err = h.ts.LocalClient()
	if err != nil {
		return nil, err
	}
	go func() {
		if runErr := h.receive.ListenOverlayDERP(hostCtx); runErr != nil && hostCtx.Err() == nil {
			opts.Logger.Error("DERP overlay stopped", "err", runErr)
		}
	}()
	return h, nil
}

func (h *Host) AuthKey() string { return h.receive.ClientAuth().AuthKey() }

func (h *Host) AuthState() overlay.ReceiveState { return h.receive.State() }

func (h *Host) Listen(network, address string) (net.Listener, error) {
	return h.ts.Listen(network, address)
}

func (h *Host) RegisterFallbackTCPHandler(handler func(src, dst netip.AddrPort) (func(net.Conn), bool)) func() {
	return h.ts.RegisterFallbackTCPHandler(func(src, dst netip.AddrPort) (func(net.Conn), bool) {
		connHandler, intercept := handler(src, dst)
		if !intercept || connHandler == nil {
			return connHandler, intercept
		}
		return func(conn net.Conn) {
			if !h.trackTCPConn(src.Addr(), conn) {
				_ = conn.Close()
				return
			}
			defer h.untrackTCPConn(src.Addr(), conn)
			connHandler(conn)
		}, true
	})
}

func (h *Host) LocalClient() *tailscale.LocalClient { return h.lc }

func (h *Host) openUDP(sessionID string, port uint16) error {
	if h.udpHandler == nil {
		return errors.New("UDP forwarding is disabled")
	}
	if h.listenUDP == nil {
		return errors.New("UDP listener is unavailable")
	}
	h.udpMu.Lock()
	defer h.udpMu.Unlock()
	if current := h.udpPorts[port]; current != nil {
		current.sessions[sessionID] = struct{}{}
		return nil
	}
	listener, err := h.listenUDP(port)
	if err != nil {
		return fmt.Errorf("listen on peer UDP port %d: %w", port, err)
	}
	state := &udpPort{listener: listener, sessions: map[string]struct{}{sessionID: {}}}
	h.udpPorts[port] = state
	go h.acceptUDP(port, state)
	return nil
}

func (h *Host) acceptUDP(port uint16, state *udpPort) {
	for {
		conn, err := state.listener.Accept()
		if err != nil {
			if h.ctx.Err() == nil && !errors.Is(err, net.ErrClosed) {
				h.logf("UDP listener on port %d stopped: %s", port, err)
			}
			return
		}
		go h.udpHandler(h.ctx, conn, port)
	}
}

func (h *Host) closeUDPSession(sessionID string) {
	h.udpMu.Lock()
	defer h.udpMu.Unlock()
	for port, state := range h.udpPorts {
		delete(state.sessions, sessionID)
		if len(state.sessions) == 0 {
			_ = state.listener.Close()
			delete(h.udpPorts, port)
		}
	}
}

func (h *Host) updateSession(_ string, peerIPs []netip.Addr) {
	h.tcpMu.Lock()
	defer h.tcpMu.Unlock()
	if h.tcpPeers == nil {
		h.tcpPeers = make(map[netip.Addr]struct{})
	}
	for _, peerIP := range peerIPs {
		h.tcpPeers[peerIP] = struct{}{}
	}
}

func (h *Host) trackTCPConn(peerIP netip.Addr, conn net.Conn) bool {
	h.tcpMu.Lock()
	defer h.tcpMu.Unlock()
	if _, active := h.tcpPeers[peerIP]; !active {
		return false
	}
	if h.tcpConns == nil {
		h.tcpConns = make(map[netip.Addr]map[net.Conn]struct{})
	}
	conns := h.tcpConns[peerIP]
	if conns == nil {
		conns = make(map[net.Conn]struct{})
		h.tcpConns[peerIP] = conns
	}
	conns[conn] = struct{}{}
	return true
}

func (h *Host) untrackTCPConn(peerIP netip.Addr, conn net.Conn) {
	h.tcpMu.Lock()
	defer h.tcpMu.Unlock()
	conns := h.tcpConns[peerIP]
	delete(conns, conn)
	if len(conns) == 0 {
		delete(h.tcpConns, peerIP)
	}
}

func (h *Host) closeTCPPeers(peerIPs []netip.Addr) {
	var conns []net.Conn
	h.tcpMu.Lock()
	for _, peerIP := range peerIPs {
		delete(h.tcpPeers, peerIP)
		for conn := range h.tcpConns[peerIP] {
			conns = append(conns, conn)
		}
		delete(h.tcpConns, peerIP)
	}
	h.tcpMu.Unlock()
	for _, conn := range conns {
		_ = conn.Close()
	}
}

func (h *Host) closeSession(sessionID string, peerIPs []netip.Addr) {
	h.closeUDPSession(sessionID)
	h.closeTCPPeers(peerIPs)
}

func (h *Host) closeAllTCP() {
	var conns []net.Conn
	h.tcpMu.Lock()
	for peerIP, peerConns := range h.tcpConns {
		for conn := range peerConns {
			conns = append(conns, conn)
		}
		delete(h.tcpConns, peerIP)
	}
	clear(h.tcpPeers)
	h.tcpMu.Unlock()
	for _, conn := range conns {
		_ = conn.Close()
	}
}

func (h *Host) Close() error {
	var closeErr error
	h.close.Do(func() {
		h.cancel()
		h.closeAllTCP()
		h.udpMu.Lock()
		for port, state := range h.udpPorts {
			closeErr = errors.Join(closeErr, state.listener.Close())
			delete(h.udpPorts, port)
		}
		h.udpMu.Unlock()
		if h.ts != nil {
			closeErr = errors.Join(closeErr, h.ts.Close())
		}
		if h.control != nil {
			closeErr = errors.Join(closeErr, h.control.Close())
		}
	})
	return closeErr
}
