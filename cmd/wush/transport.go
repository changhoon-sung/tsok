package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"

	"github.com/charmbracelet/huh"
	"github.com/coder/serpent"
	transportcore "github.com/coder/wush/internal/transport"
	"tailscale.com/tailcfg"
)

type clientTransportOptions struct {
	authKey   string
	waitP2P   bool
	derpMap   *tailcfg.DERPMap
	verbose   bool
	logger    *slog.Logger
	logf      func(string, ...any)
	logWriter io.Writer
}

func initLogger(verbose, quiet *bool, slogger *slog.Logger, logf *func(str string, args ...any)) serpent.MiddlewareFunc {
	return func(next serpent.HandlerFunc) serpent.HandlerFunc {
		return func(i *serpent.Invocation) error {
			if *verbose {
				*slogger = *slog.New(slog.NewTextHandler(i.Stderr, nil))
			} else {
				*slogger = *slog.New(slog.NewTextHandler(io.Discard, nil))
			}

			*logf = func(str string, args ...any) {
				if !*quiet {
					_, _ = fmt.Fprintf(i.Stderr, str+"\n", args...)
				}
			}

			return next(i)
		}
	}
}

func initAuth(authFlag *string) serpent.MiddlewareFunc {
	return func(next serpent.HandlerFunc) serpent.HandlerFunc {
		return func(i *serpent.Invocation) error {
			if *authFlag == "" {
				if err := huh.NewInput().
					Title("Enter your Auth ID:").
					Value(authFlag).
					Run(); err != nil {
					return fmt.Errorf("get auth id: %w", err)
				}
			}
			return next(i)
		}
	}
}

func derpMap(path *string, dm **tailcfg.DERPMap) serpent.MiddlewareFunc {
	return func(next serpent.HandlerFunc) serpent.HandlerFunc {
		return func(i *serpent.Invocation) error {
			loaded, err := transportcore.LoadDERPMap(i.Context(), *path)
			if err != nil {
				return err
			}
			*dm = loaded
			return next(i)
		}
	}
}

func connectTransport(ctx context.Context, opts clientTransportOptions) (*transportcore.Client, error) {
	return transportcore.Connect(ctx, transportcore.ClientOptions{
		CommonOptions: transportcore.CommonOptions{
			DERPMap:   opts.derpMap,
			Logger:    opts.logger,
			Logf:      transportcore.Logf(opts.logf),
			Verbose:   opts.verbose,
			LogWriter: opts.logWriter,
		},
		AuthKey:    opts.authKey,
		WaitDirect: opts.waitP2P,
	})
}
