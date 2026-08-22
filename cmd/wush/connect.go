package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"

	"tailscale.com/tailcfg"

	"github.com/coder/serpent"
	"github.com/coder/wush/cliui"
	"github.com/coder/wush/overlay"
	"github.com/coder/wush/tsserver"
)

func connectCmd() *serpent.Command {
	var (
		stdio      bool
		verbose    bool
		quiet      bool
		derpmapFi  string
		logger     = new(slog.Logger)
		logf       = func(str string, args ...any) {}
		targetPort uint16

		dm          = new(tailcfg.DERPMap)
		overlayOpts = new(sendOverlayOpts)
		send        = new(overlay.Send)
	)
	return &serpent.Command{
		Use:   "connect --stdio <host:port>",
		Short: "Connect stdin and stdout to a TCP port on the wush server.",
		Long: formatExamples(
			example{
				Description: "Connect stdio to the SSH port on the server",
				Command:     "wush connect --stdio --auth-key <key> 127.0.0.1:22",
			},
		),
		Middleware: serpent.Chain(
			serpent.RequireNArgs(1),
			requireStdio(&stdio),
			parseConnectTarget(&targetPort),
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

			ip, err := waitUntilHasPeerHasIP(ctx, logf, lc)
			if err != nil {
				return err
			}

			if overlayOpts.waitP2P {
				if err := waitUntilHasP2P(ctx, logf, lc); err != nil {
					return err
				}
			}

			addr := netip.AddrPortFrom(ip, targetPort)
			conn, err := ts.Dial(ctx, "tcp", addr.String())
			if err != nil {
				return fmt.Errorf("dial tcp endpoint %q in peer: %w", inv.Args[0], err)
			}

			return bridgeStdio(ctx, conn, inv.Stdin, inv.Stdout)
		},
		Options: []serpent.Option{
			{
				Flag:        "stdio",
				Description: "Bridge the remote TCP connection to stdin and stdout.",
				Default:     "false",
				Value:       serpent.BoolOf(&stdio),
			},
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
				Description: "Silences diagnostic output.",
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

func parseConnectTarget(port *uint16) serpent.MiddlewareFunc {
	return func(next serpent.HandlerFunc) serpent.HandlerFunc {
		return func(inv *serpent.Invocation) error {
			parsed, err := connectTargetPort(inv.Args[0])
			if err != nil {
				return err
			}
			*port = parsed
			return next(inv)
		}
	}
}

func requireStdio(stdio *bool) serpent.MiddlewareFunc {
	return func(next serpent.HandlerFunc) serpent.HandlerFunc {
		return func(inv *serpent.Invocation) error {
			if !*stdio {
				return errors.New("--stdio is required")
			}
			return next(inv)
		}
	}
}

func connectTargetPort(target string) (uint16, error) {
	host, portString, err := net.SplitHostPort(target)
	if err != nil {
		return 0, fmt.Errorf("parse TCP endpoint %q: %w", target, err)
	}

	if !strings.EqualFold(host, "localhost") {
		addr, err := netip.ParseAddr(host)
		if err != nil {
			return 0, fmt.Errorf("parse TCP endpoint host %q: %w", host, err)
		}
		if !addr.IsLoopback() {
			return 0, fmt.Errorf("TCP endpoint host %q is not loopback", host)
		}
	}

	port, err := parsePort(portString)
	if err != nil {
		return 0, fmt.Errorf("parse TCP endpoint port from %q: %w", target, err)
	}
	return port, nil
}

func bridgeStdio(ctx context.Context, conn net.Conn, stdin io.Reader, stdout io.Writer) error {
	defer conn.Close()

	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-done:
		}
	}()

	stdinErr := make(chan error, 1)
	go func() {
		_, err := io.Copy(conn, stdin)
		if err == nil {
			if closeWriter, ok := conn.(interface{ CloseWrite() error }); ok {
				err = closeWriter.CloseWrite()
			}
		}
		stdinErr <- err
		if err != nil {
			_ = conn.Close()
		}
	}()

	_, stdoutErr := io.Copy(stdout, conn)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	select {
	case err := <-stdinErr:
		if err != nil {
			return fmt.Errorf("copy stdin to remote connection: %w", err)
		}
	default:
	}
	if stdoutErr != nil {
		return fmt.Errorf("copy remote connection to stdout: %w", stdoutErr)
	}
	return nil
}
