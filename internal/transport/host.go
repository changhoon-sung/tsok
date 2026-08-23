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

	"github.com/coder/wush/overlay"
	"github.com/coder/wush/tsserver"
)

type UDPHandler func(ctx context.Context, conn net.Conn, port uint16)

type HostOptions struct {
	CommonOptions
	UDPHandler UDPHandler
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
	close      sync.Once
}

func StartHost(ctx context.Context, opts HostOptions) (_ *Host, err error) {
	opts.CommonOptions = normalizeOptions(opts.CommonOptions)
	if opts.DERPMap == nil {
		return nil, errors.New("DERP map is required")
	}
	hostCtx, cancel := context.WithCancel(ctx)
	h := &Host{ctx: hostCtx, cancel: cancel, logf: opts.Logf, udpHandler: opts.UDPHandler, udpPorts: make(map[uint16]*udpPort)}
	defer func() {
		if err != nil {
			_ = h.Close()
		}
	}()

	h.receive = overlay.NewReceiveOverlay(opts.Logger, overlay.Logf(opts.Logf), opts.DERPMap)
	if err := h.receive.PickDERPHome(hostCtx); err != nil {
		return nil, err
	}
	h.receive.SetOpenUDPHandler(h.openUDP)
	h.receive.SetSessionClosedHandler(h.closeUDPSession)

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

func (h *Host) Listen(network, address string) (net.Listener, error) {
	return h.ts.Listen(network, address)
}

func (h *Host) RegisterFallbackTCPHandler(handler func(src, dst netip.AddrPort) (func(net.Conn), bool)) func() {
	return h.ts.RegisterFallbackTCPHandler(tsnet.FallbackTCPHandler(handler))
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

func (h *Host) Close() error {
	var closeErr error
	h.close.Do(func() {
		h.cancel()
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
