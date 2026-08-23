package transport

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"

	"tailscale.com/ipn/store"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
)

type Logf func(format string, args ...any)

type CommonOptions struct {
	DERPMap   *tailcfg.DERPMap
	Logger    *slog.Logger
	Logf      Logf
	Verbose   bool
	LogWriter io.Writer
}

func normalizeOptions(opts CommonOptions) CommonOptions {
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if opts.Logf == nil {
		opts.Logf = func(string, ...any) {}
	}
	if opts.LogWriter == nil {
		opts.LogWriter = io.Discard
	}
	return opts
}

func LoadDERPMap(ctx context.Context, path string) (*tailcfg.DERPMap, error) {
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read DERP config file: %w", err)
		}
		dm := new(tailcfg.DERPMap)
		if err := json.Unmarshal(data, dm); err != nil {
			return nil, fmt.Errorf("unmarshal DERP config: %w", err)
		}
		return dm, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://controlplane.tailscale.com/derpmap/default", nil)
	if err != nil {
		return nil, fmt.Errorf("make Tailscale DERP map request: %w", err)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("get Tailscale DERP map: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode < http.StatusOK || res.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("get Tailscale DERP map: %s", res.Status)
	}
	dm := new(tailcfg.DERPMap)
	if err := json.NewDecoder(io.LimitReader(res.Body, 4<<20)).Decode(dm); err != nil {
		return nil, fmt.Errorf("decode Tailscale DERP map: %w", err)
	}
	return dm, nil
}

func newTSNet(direction string, opts CommonOptions, controlURL string) (*tsnet.Server, error) {
	srv := &tsnet.Server{
		Dir:        os.TempDir(),
		Hostname:   "wush-" + direction,
		Ephemeral:  true,
		AuthKey:    direction,
		ControlURL: controlURL,
		Logf:       func(string, ...any) {},
		UserLogf:   func(string, ...any) {},
	}
	if opts.Verbose {
		logf := func(format string, args ...any) {
			_, _ = fmt.Fprintf(opts.LogWriter, format+"\n", args...)
		}
		srv.Logf = logf
		srv.UserLogf = logf
	}

	state, err := store.New(func(string, ...any) {}, "mem:wush")
	if err != nil {
		return nil, fmt.Errorf("create state store: %w", err)
	}
	srv.Store = state
	return srv, nil
}
