package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"time"

	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"

	"github.com/coder/serpent"
	"github.com/coder/wush/cliui"
	"github.com/coder/wush/overlay"
	"github.com/coder/wush/tsserver"
	xssh "github.com/coder/wush/xssh"
)

const sshDirectNegotiationTimeout = 5 * time.Second

type peerStatusClient interface {
	Status(context.Context) (*ipnstate.Status, error)
	Ping(context.Context, netip.Addr, tailcfg.PingType) (*ipnstate.PingResult, error)
}

func sshCmd() *serpent.Command {
	var (
		verbose   bool
		quiet     bool
		derpmapFi string
		logger    = new(slog.Logger)
		logf      = func(str string, args ...any) {}

		dm          = new(tailcfg.DERPMap)
		overlayOpts = new(sendOverlayOpts)
		send        = new(overlay.Send)
	)
	return &serpent.Command{
		Use:     "ssh",
		Aliases: []string{},
		Short:   "Open a SSH connection to a wush server.",
		Long:    "Use " + cliui.Code("wush serve") + " on the computer you would like to connect to.",
		Middleware: serpent.Chain(
			initLogger(&verbose, &quiet, logger, &logf),
			initAuth(&overlayOpts.authKey, &overlayOpts.clientAuth),
			derpMap(&derpmapFi, dm),
			sendOverlayMW(overlayOpts, &send, logger, dm, &logf),
		),
		Handler: func(inv *serpent.Invocation) error {
			ctx := inv.Context()

			s, err := tsserver.NewServer(ctx, logger, send, dm)
			if err != nil {
				return err
			}
			defer s.Close()

			go send.ListenOverlayDERP(ctx)

			go func() {
				if err := s.ListenAndServe(ctx); err != nil {
					logger.Error("local control server stopped", "err", err)
				}
			}()
			ts, err := newTSNet("send", verbose, s.ControlURL())
			if err != nil {
				return err
			}
			defer ts.Close()

			logf("Bringing WireGuard up..")
			if _, err := ts.Up(ctx); err != nil {
				return fmt.Errorf("bring wireguard up: %w", err)
			}
			logf("WireGuard is ready!")

			lc, err := ts.LocalClient()
			if err != nil {
				return err
			}

			ip, relay, direct, err := waitUntilHasPeerHasIPAndPath(ctx, logf, lc)
			if err != nil {
				return err
			}

			if !direct && (!quiet || overlayOpts.waitP2P) {
				if err := negotiateSSHDirectConnection(ctx, logf, lc, relay, overlayOpts.waitP2P, sshDirectNegotiationTimeout); err != nil {
					return err
				}
			}

			return xssh.TailnetSSH(ctx, inv, ts, netip.AddrPortFrom(ip, 3).String(), quiet)
		},
		Options: []serpent.Option{
			{
				Flag:        "auth-key",
				Env:         "WUSH_AUTH_KEY",
				Description: "The auth key returned by " + cliui.Code("wush serve") + ". If not provided, it will be asked for on startup.",
				Default:     "",
				Value:       serpent.StringOf(&overlayOpts.authKey),
			},
			{
				Flag:        "derp-config-file",
				Description: "File which specifies the DERP config to use. In the structure of https://pkg.go.dev/tailscale.com/tailcfg#DERPMap.",
				Default:     "",
				Value:       serpent.StringOf(&derpmapFi),
			},
			{
				Flag:        "quiet",
				Description: "Silences all output.",
				Default:     "false",
				Value:       serpent.BoolOf(&quiet),
			},
			{
				Flag:        "wait-p2p",
				Description: waitDirectDescription,
				Default:     "false",
				Value:       serpent.BoolOf(&overlayOpts.waitP2P),
			},
			{
				Flag:          "verbose",
				FlagShorthand: "v",
				Description:   "Enable verbose logging.",
				Default:       "false",
				Value:         serpent.BoolOf(&verbose),
			},
		},
	}
}

func waitUntilHasPeerHasIP(ctx context.Context, logF func(str string, args ...any), lc peerStatusClient) (netip.Addr, error) {
	ip, _, _, err := waitUntilHasPeerHasIPAndPath(ctx, logF, lc)
	return ip, err
}

func waitUntilHasPeerHasIPAndPath(ctx context.Context, logF func(str string, args ...any), lc peerStatusClient) (netip.Addr, string, bool, error) {
	for {
		select {
		case <-ctx.Done():
			return netip.Addr{}, "", false, ctx.Err()
		case <-time.After(time.Second):
		}

		stat, err := lc.Status(ctx)
		if err != nil {
			logF("error getting local status: %s", err)
			continue
		}

		peers := stat.Peers()
		if len(peers) == 0 {
			logF("No peer yet")
			continue
		}

		logF("Received peer")

		peer, ok := stat.Peer[peers[0]]
		if !ok {
			logF("have peers but not found in map (developer error)")
			continue
		}

		if len(peer.TailscaleIPs) == 0 {
			logF("peer has no ips (developer error)")
			continue
		}

		if peer.CurAddr != "" {
			logF("Peer connection: %s", cliui.Code("direct"))
			return peer.TailscaleIPs[0], peer.Relay, true, nil
		}
		if peer.Relay == "" {
			logF("peer has no connection path yet")
			continue
		}

		logF("Peer reachable via relay (%s)", cliui.Code(peer.Relay))
		return peer.TailscaleIPs[0], peer.Relay, false, nil
	}
}

func negotiateSSHDirectConnection(ctx context.Context, logF func(str string, args ...any), lc peerStatusClient, relay string, wait bool, timeout time.Duration) error {
	logF("Negotiating direct connection...")
	if wait {
		return waitUntilHasP2P(ctx, logF, lc)
	}

	negotiationCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if err := waitUntilHasP2P(negotiationCtx, logF, lc); err != nil {
		if errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil {
			logF("Direct connection unavailable; continuing via relay (%s)", cliui.Code(relay))
			return nil
		}
		return err
	}
	return nil
}

func waitUntilHasP2P(ctx context.Context, logF func(str string, args ...any), lc peerStatusClient) error {
	for {
		stat, err := lc.Status(ctx)
		if err != nil {
			logF("error getting lc status: %s", err)
		} else {
			peers := stat.Peers()
			if len(peers) == 0 {
				logF("No peer yet")
			} else if peer, ok := stat.Peer[peers[0]]; !ok {
				logF("no peer found in map while waiting p2p (developer error)")
			} else if len(peer.TailscaleIPs) == 0 {
				logF("peer has no ips (developer error)")
			} else {
				pingCancel, cancel := context.WithTimeout(ctx, time.Second)
				pong, pingErr := lc.Ping(pingCancel, peer.TailscaleIPs[0], tailcfg.PingDisco)
				cancel()
				if pingErr != nil {
					if !errors.Is(pingErr, context.DeadlineExceeded) && !errors.Is(pingErr, context.Canceled) {
						logF("ping failed: %s", pingErr)
					}
				} else if pong.Endpoint != "" {
					logF("Peer connection: %s", cliui.Code("direct"))
					return nil
				}
			}
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
}
