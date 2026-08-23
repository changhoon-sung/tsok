package main

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/changhoon-sung/tsok/cliui"
	"github.com/coder/serpent"
	"github.com/schollz/progressbar/v3"
	"tailscale.com/tailcfg"
	"tailscale.com/types/ptr"
)

type clientCLIOptions struct {
	authKey string
	waitP2P bool
}

const waitDirectDescription = "Waits until a direct connection is established instead of continuing over a relay."

func cpCmd() *serpent.Command {
	var (
		verbose   bool
		derpmapFi string
		logger    = new(slog.Logger)
		logf      = func(str string, args ...any) {}

		dm         *tailcfg.DERPMap
		clientOpts = new(clientCLIOptions)
	)
	return &serpent.Command{
		Use:   "cp <file>",
		Short: "Transfer files to a tsok server.",
		Long: formatExamples(
			example{
				Description: "Copy a local file to the server",
				Command:     "tsok cp local-file.txt",
			},
		),
		Middleware: serpent.Chain(
			serpent.RequireNArgs(1),
			initLogger(&verbose, ptr.To(false), logger, &logf),
			initAuth(&clientOpts.authKey),
			derpMap(&derpmapFi, &dm),
		),
		Handler: func(inv *serpent.Invocation) error {
			ctx := inv.Context()
			fiPath := inv.Args[0]
			fiName := filepath.Base(fiPath)

			fi, err := os.Open(fiPath)
			if err != nil {
				return fmt.Errorf("open upload file: %w", err)
			}
			defer fi.Close()

			fiStat, err := fi.Stat()
			if err != nil {
				return fmt.Errorf("stat upload file: %w", err)
			}
			if !fiStat.Mode().IsRegular() {
				return fmt.Errorf("upload path %q is not a regular file", fiPath)
			}

			client, err := connectTransport(ctx, clientTransportOptions{
				authKey: clientOpts.authKey, waitP2P: clientOpts.waitP2P,
				derpMap: dm, verbose: verbose, logger: logger, logf: logf, logWriter: inv.Stderr,
			})
			if err != nil {
				return err
			}
			defer client.Close()

			bar := progressbar.DefaultBytes(
				fiStat.Size(),
				fmt.Sprintf("Uploading %q", fiPath),
			)
			defer bar.Close()
			barReader := progressbar.NewReader(fi, bar)

			hc := client.HTTPClient()
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, fileUploadURL(client.Route().IP, fiName), &barReader)
			if err != nil {
				return err
			}
			req.ContentLength = fiStat.Size()

			res, err := hc.Do(req)
			if err != nil {
				return err
			}
			defer res.Body.Close()

			body, err := readUploadResponse(res)
			if err != nil {
				return err
			}
			if len(body) > 0 {
				_, _ = fmt.Fprintln(inv.Stdout, body)
			}

			return nil
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
				Description: "File which specifies the DERP config to use. In the structure of https://pkg.go.dev/tailscale.com/tailcfg#DERPMap. By default, https://controlplane.tailscale.com/derpmap/default is used.",
				Default:     "",
				Value:       serpent.StringOf(&derpmapFi),
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

func fileUploadURL(ip netip.Addr, fileName string) string {
	u := url.URL{
		Scheme: "http",
		Host:   net.JoinHostPort(ip.String(), "4444"),
		Path:   "/" + fileName,
	}
	return u.String()
}

func readUploadResponse(res *http.Response) (string, error) {
	body, err := io.ReadAll(io.LimitReader(res.Body, 64<<10))
	if err != nil {
		return "", fmt.Errorf("read upload response: %w", err)
	}
	message := strings.TrimSpace(string(body))
	if res.StatusCode < http.StatusOK || res.StatusCode >= http.StatusMultipleChoices {
		return "", fmt.Errorf("upload failed: %s: %s", res.Status, message)
	}
	return message, nil
}
