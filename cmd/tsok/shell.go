package main

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"tailscale.com/tailcfg"

	"github.com/changhoon-sung/tsok/cliui"
	transportcore "github.com/changhoon-sung/tsok/internal/transport"
	xssh "github.com/changhoon-sung/tsok/xssh"
	"github.com/coder/serpent"
)

const shellDirectNegotiationTimeout = 5 * time.Second

func shellCmd() *serpent.Command {
	var (
		verbose   bool
		quiet     bool
		derpmapFi string
		logger    = new(slog.Logger)
		logf      = func(str string, args ...any) {}

		dm         *tailcfg.DERPMap
		clientOpts = new(clientCLIOptions)
	)
	return &serpent.Command{
		Use:     "shell [command...]",
		Aliases: []string{},
		Short:   "Open a zero-configuration shell on a tsok server.",
		Long: "Open an interactive shell or run one command as the user running " + cliui.Code("tsok serve") + "." +
			"\n\nThe auth key grants that user's shell privileges. If " + cliui.Code("tsok serve") +
			" runs as root, the auth key grants a root shell." +
			"\n\nFor SFTP, agent forwarding, per-user SSH authentication, SSH certificates, or SSH port forwarding," +
			" use system OpenSSH with " + cliui.Code("tsok forward --tcp-stdio") + "." +
			"\n\n" + formatExamples(
			example{
				Description: "Open an interactive shell",
				Command:     "TSOK_AUTH_KEY=<auth-key> tsok shell",
			},
			example{
				Description: "Run one remote command",
				Command:     "TSOK_AUTH_KEY=<auth-key> tsok shell -- uname -a",
			},
		),
		Middleware: serpent.Chain(
			initLogger(&verbose, &quiet, logger, &logf),
			initAuth(&clientOpts.authKey),
			derpMap(&derpmapFi, &dm),
		),
		Handler: func(inv *serpent.Invocation) error {
			ctx := inv.Context()

			client, err := connectTransport(ctx, clientTransportOptions{
				authKey: clientOpts.authKey, derpMap: dm, verbose: verbose,
				logger: logger, logf: logf, logWriter: inv.Stderr,
			})
			if err != nil {
				return err
			}
			defer client.Close()

			route := client.Route()
			if route.Direct {
				logf("Peer connection: %s", cliui.Code("direct"))
			} else {
				logf("Peer reachable via relay (%s)", cliui.Code(route.Relay))
			}

			if !route.Direct && (!quiet || clientOpts.waitP2P) {
				if err := negotiateShellDirectConnection(ctx, logf, client, route.Relay, clientOpts.waitP2P, shellDirectNegotiationTimeout); err != nil {
					return err
				}
			}

			conn, err := client.DialTCP(ctx, 3)
			if err != nil {
				return err
			}
			return xssh.SSH(ctx, inv, conn)
		},
		Options: []serpent.Option{
			{
				Flag:        "auth-key",
				Env:         "TSOK_AUTH_KEY",
				Description: "The auth key returned by " + cliui.Code("tsok serve") + ". If not provided, it will be asked for on startup.",
				Default:     "",
				Value:       serpent.StringOf(&clientOpts.authKey),
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
				Value:       serpent.BoolOf(&clientOpts.waitP2P),
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

type directWaiter interface {
	WaitDirect(context.Context, transportcore.Logf) error
}

func negotiateShellDirectConnection(ctx context.Context, logF func(str string, args ...any), client directWaiter, relay string, wait bool, timeout time.Duration) error {
	logF("Negotiating direct connection...")
	if wait {
		if err := client.WaitDirect(ctx, transportcore.Logf(logF)); err != nil {
			return err
		}
		logF("Peer connection: %s", cliui.Code("direct"))
		return nil
	}

	negotiationCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if err := client.WaitDirect(negotiationCtx, transportcore.Logf(logF)); err != nil {
		if errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil {
			logF("Direct connection unavailable; continuing via relay (%s)", cliui.Code(relay))
			return nil
		}
		return err
	}
	logF("Peer connection: %s", cliui.Code("direct"))
	return nil
}
