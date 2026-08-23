package transport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"tailscale.com/client/tailscale"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"

	"github.com/changhoon-sung/tsok/overlay"
	"github.com/changhoon-sung/tsok/tsserver"
)

type ClientOptions struct {
	CommonOptions
	AuthKey    string
	WaitDirect bool
}

type Route struct {
	IP       netip.Addr
	Relay    string
	Direct   bool
	Endpoint string
}

type Client struct {
	ctx     context.Context
	cancel  context.CancelFunc
	send    *overlay.Send
	control interface{ Close() error }
	ts      *tsnet.Server
	lc      *tailscale.LocalClient
	route   Route
	close   sync.Once
}

func Connect(ctx context.Context, opts ClientOptions) (_ *Client, err error) {
	opts.CommonOptions = normalizeOptions(opts.CommonOptions)
	if opts.DERPMap == nil {
		return nil, errors.New("DERP map is required")
	}
	authKey := strings.TrimSpace(opts.AuthKey)
	if parsedURL, parseErr := url.Parse(authKey); parseErr == nil && parsedURL.Fragment != "" {
		authKey = parsedURL.Fragment
	}
	var auth overlay.ClientAuth
	if err := auth.Parse(authKey); err != nil {
		return nil, fmt.Errorf("parse auth key: %w", err)
	}
	if opts.DERPMap.Regions[int(auth.ReceiverDERPRegionID)] == nil {
		return nil, fmt.Errorf("auth key references unknown DERP region %d", auth.ReceiverDERPRegionID)
	}

	clientCtx, cancel := context.WithCancel(ctx)
	c := &Client{ctx: clientCtx, cancel: cancel}
	defer func() {
		if err != nil {
			_ = c.Close()
		}
	}()

	c.send = overlay.NewSendOverlay(opts.Logger, opts.DERPMap)
	c.send.Auth = auth
	auth.PrintDebug(opts.Logf, opts.DERPMap)

	control, err := tsserver.NewServer(clientCtx, opts.Logger, c.send, opts.DERPMap)
	if err != nil {
		return nil, err
	}
	c.control = control
	go func() {
		if runErr := control.ListenAndServe(clientCtx); runErr != nil && clientCtx.Err() == nil {
			opts.Logger.Error("local control server stopped", "err", runErr)
		}
	}()
	go func() {
		if runErr := c.send.ListenOverlayDERP(clientCtx); runErr != nil && clientCtx.Err() == nil {
			opts.Logger.Error("DERP overlay stopped", "err", runErr)
		}
	}()

	c.ts, err = newTSNet("send", opts.CommonOptions, control.ControlURL())
	if err != nil {
		return nil, err
	}
	opts.Logf("Bringing WireGuard up..")
	if _, err := c.ts.Up(clientCtx); err != nil {
		return nil, fmt.Errorf("bring WireGuard up: %w", err)
	}
	opts.Logf("WireGuard is ready!")
	c.lc, err = c.ts.LocalClient()
	if err != nil {
		return nil, err
	}
	c.route, err = waitForPeer(clientCtx, opts.Logf, c.lc)
	if err != nil {
		return nil, err
	}
	if opts.WaitDirect && !c.route.Direct {
		if err := c.WaitDirect(clientCtx, opts.Logf); err != nil {
			return nil, err
		}
		c.route.Direct = true
	}
	return c, nil
}

func (c *Client) Route() Route { return c.route }

func (c *Client) Dial(ctx context.Context, network string, port uint16) (net.Conn, error) {
	if port == 0 {
		return nil, errors.New("port cannot be zero")
	}
	addr := netip.AddrPortFrom(c.route.IP, port)
	return c.ts.Dial(ctx, network, addr.String())
}

func (c *Client) DialTCP(ctx context.Context, port uint16) (net.Conn, error) {
	return c.Dial(ctx, "tcp", port)
}

func (c *Client) DialUDP(ctx context.Context, port uint16) (net.Conn, error) {
	if err := c.OpenUDP(ctx, port); err != nil {
		return nil, fmt.Errorf("open peer UDP port %d: %w", port, err)
	}
	return c.Dial(ctx, "udp", port)
}

func (c *Client) OpenUDP(ctx context.Context, port uint16) error {
	return c.send.OpenUDP(ctx, port)
}

func (c *Client) HTTPClient() *http.Client { return c.ts.HTTPClient() }

func (c *Client) WaitDirect(ctx context.Context, logf Logf) error {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	for {
		status, err := c.lc.Status(ctx)
		if err == nil {
			peers := status.Peers()
			if len(peers) > 0 {
				if peer, ok := status.Peer[peers[0]]; ok && len(peer.TailscaleIPs) > 0 {
					pingCtx, cancel := context.WithTimeout(ctx, time.Second)
					pong, pingErr := c.lc.Ping(pingCtx, peer.TailscaleIPs[0], tailcfg.PingDisco)
					cancel()
					if pingErr == nil && pong.Endpoint != "" {
						c.route.Direct = true
						c.route.Endpoint = pong.Endpoint
						return nil
					}
					if pingErr != nil && !errors.Is(pingErr, context.DeadlineExceeded) && !errors.Is(pingErr, context.Canceled) {
						logf("ping failed: %s", pingErr)
					}
				}
			}
		} else {
			logf("error getting local status: %s", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
}

func (c *Client) Close() error {
	var closeErr error
	c.close.Do(func() {
		c.cancel()
		if c.send != nil {
			c.send.Close()
		}
		if c.ts != nil {
			closeErr = errors.Join(closeErr, c.ts.Close())
		}
		if c.control != nil {
			closeErr = errors.Join(closeErr, c.control.Close())
		}
	})
	return closeErr
}

type peerStatusClient interface {
	Status(context.Context) (*ipnstate.Status, error)
}

func waitForPeer(ctx context.Context, logf Logf, lc peerStatusClient) (Route, error) {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	for {
		select {
		case <-ctx.Done():
			return Route{}, ctx.Err()
		case <-time.After(time.Second):
		}
		status, err := lc.Status(ctx)
		if err != nil {
			logf("error getting local status: %s", err)
			continue
		}
		peers := status.Peers()
		if len(peers) == 0 {
			logf("No peer yet")
			continue
		}
		peer, ok := status.Peer[peers[0]]
		if !ok || len(peer.TailscaleIPs) == 0 {
			logf("peer status is incomplete")
			continue
		}
		relay := peer.Relay
		if relay == "" {
			relay = peer.PeerRelay
		}
		route := Route{IP: peer.TailscaleIPs[0], Relay: relay, Direct: peer.CurAddr != "", Endpoint: peer.CurAddr}
		if !route.Direct && route.Relay == "" {
			logf("peer has no connection path yet")
			continue
		}
		logf("Received peer")
		return route, nil
	}
}
