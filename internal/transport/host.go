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
	// tcpPeerSessions gates new fallback connections, while tcpConns lets
	// overlay session closure interrupt established userspace TCP flows.
	tcpMu           sync.Mutex
	tcpConns        map[netip.Addr]map[net.Conn]struct{}
	tcpSessions     map[string]map[netip.Addr]struct{}
	tcpPeerSessions map[netip.Addr]map[string]struct{}
	close           sync.Once
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
		tcpSessions:     make(map[string]map[netip.Addr]struct{}),
		tcpPeerSessions: make(map[netip.Addr]map[string]struct{}),
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

func (h *Host) updateSession(sessionID string, peerIPs []netip.Addr) {
	current := make(map[netip.Addr]struct{}, len(peerIPs))
	for _, peerIP := range peerIPs {
		current[peerIP] = struct{}{}
	}

	var conns []net.Conn
	h.tcpMu.Lock()
	if h.tcpSessions == nil {
		h.tcpSessions = make(map[string]map[netip.Addr]struct{})
	}
	if h.tcpPeerSessions == nil {
		h.tcpPeerSessions = make(map[netip.Addr]map[string]struct{})
	}
	for peerIP := range h.tcpSessions[sessionID] {
		if _, retained := current[peerIP]; retained {
			continue
		}
		sessions := h.tcpPeerSessions[peerIP]
		delete(sessions, sessionID)
		if len(sessions) == 0 {
			delete(h.tcpPeerSessions, peerIP)
			for conn := range h.tcpConns[peerIP] {
				conns = append(conns, conn)
			}
			delete(h.tcpConns, peerIP)
		}
	}
	for peerIP := range current {
		sessions := h.tcpPeerSessions[peerIP]
		if sessions == nil {
			sessions = make(map[string]struct{})
			h.tcpPeerSessions[peerIP] = sessions
		}
		sessions[sessionID] = struct{}{}
	}
	h.tcpSessions[sessionID] = current
	h.tcpMu.Unlock()
	closeConns(conns)
}

func (h *Host) trackTCPConn(peerIP netip.Addr, conn net.Conn) bool {
	h.tcpMu.Lock()
	defer h.tcpMu.Unlock()
	if len(h.tcpPeerSessions[peerIP]) == 0 {
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

func (h *Host) closeTCPSession(sessionID string, peerIPs []netip.Addr) {
	var conns []net.Conn
	h.tcpMu.Lock()
	peers := h.tcpSessions[sessionID]
	for _, peerIP := range peerIPs {
		if peers == nil {
			peers = make(map[netip.Addr]struct{}, len(peerIPs))
		}
		peers[peerIP] = struct{}{}
	}
	for peerIP := range peers {
		sessions := h.tcpPeerSessions[peerIP]
		delete(sessions, sessionID)
		if len(sessions) != 0 {
			continue
		}
		delete(h.tcpPeerSessions, peerIP)
		for conn := range h.tcpConns[peerIP] {
			conns = append(conns, conn)
		}
		delete(h.tcpConns, peerIP)
	}
	delete(h.tcpSessions, sessionID)
	h.tcpMu.Unlock()
	closeConns(conns)
}

func (h *Host) closeSession(sessionID string, peerIPs []netip.Addr) {
	h.closeUDPSession(sessionID)
	h.closeTCPSession(sessionID, peerIPs)
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
	clear(h.tcpSessions)
	clear(h.tcpPeerSessions)
	h.tcpMu.Unlock()
	closeConns(conns)
}

func closeConns(conns []net.Conn) {
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
