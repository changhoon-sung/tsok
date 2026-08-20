package main

import (
	"encoding/json"
	"errors"
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

	"github.com/charmbracelet/huh"
	"github.com/coder/serpent"
	"github.com/coder/wush/cliui"
	"github.com/coder/wush/overlay"
	"github.com/coder/wush/tsserver"
	"github.com/schollz/progressbar/v3"
	"tailscale.com/net/netns"
	"tailscale.com/tailcfg"
	"tailscale.com/types/ptr"
)

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
					fmt.Fprintf(i.Stderr, str+"\n", args...)
				}
			}

			return next(i)
		}
	}
}

func initAuth(authFlag *string, ca *overlay.ClientAuth) serpent.MiddlewareFunc {
	return func(next serpent.HandlerFunc) serpent.HandlerFunc {
		return func(i *serpent.Invocation) error {
			if *authFlag == "" {
				err := huh.NewInput().
					Title("Enter your Auth ID:").
					Value(authFlag).
					Run()
				if err != nil {
					return fmt.Errorf("get auth id: %w", err)
				}
			}

			// If the user provided a URL, extract the auth key from the fragment.
			authKey := *authFlag
			if u, err := url.Parse(*authFlag); err == nil && u.Fragment != "" {
				authKey = u.Fragment
			}

			err := ca.Parse(strings.TrimSpace(authKey))
			if err != nil {
				return fmt.Errorf("parse auth key: %w", err)
			}

			return next(i)
		}
	}
}

func sendOverlayMW(opts *sendOverlayOpts, send **overlay.Send, logger *slog.Logger, dm *tailcfg.DERPMap, logf *func(str string, args ...any)) serpent.MiddlewareFunc {
	return func(next serpent.HandlerFunc) serpent.HandlerFunc {
		return func(i *serpent.Invocation) error {
			var err error

			if regionID := opts.clientAuth.ReceiverDERPRegionID; regionID != 0 && dm.Regions[int(regionID)] == nil {
				return fmt.Errorf("auth key references unknown DERP region %d", regionID)
			}

			newSend := overlay.NewSendOverlay(logger, dm)
			newSend.Auth = opts.clientAuth
			if opts.stunAddrOverride != "" {
				newSend.STUNIPOverride, err = netip.ParseAddr(opts.stunAddrOverride)
				if err != nil {
					return fmt.Errorf("parse stun addr override: %w", err)
				}
			}

			newSend.Auth.PrintDebug(*logf, dm)

			*send = newSend
			return next(i)
		}
	}
}

func derpMap(fi *string, dm *tailcfg.DERPMap) serpent.MiddlewareFunc {
	return func(next serpent.HandlerFunc) serpent.HandlerFunc {
		return func(i *serpent.Invocation) error {
			if *fi == "" {
				_dm, err := tsserver.DERPMapTailscale(i.Context())
				if err != nil {
					return fmt.Errorf("request derpmap from tailscale: %w", err)
				}
				*dm = *_dm
			} else {
				data, err := os.ReadFile(*fi)
				if err != nil {
					return fmt.Errorf("read derp config file: %w", err)
				}
				if err := json.Unmarshal(data, dm); err != nil {
					return fmt.Errorf("unmarshal derp config: %w", err)
				}
			}

			return next(i)
		}
	}
}

type sendOverlayOpts struct {
	authKey          string
	clientAuth       overlay.ClientAuth
	waitP2P          bool
	stunAddrOverride string
}

func cpCmd() *serpent.Command {
	var (
		verbose   bool
		derpmapFi string
		logger    = new(slog.Logger)
		logf      = func(str string, args ...any) {}

		dm          = new(tailcfg.DERPMap)
		overlayOpts = new(sendOverlayOpts)
		send        = new(overlay.Send)
	)
	return &serpent.Command{
		Use:   "cp <file>",
		Short: "Transfer files to a wush server.",
		Long: formatExamples(
			example{
				Description: "Copy a local file to the server",
				Command:     "wush cp local-file.txt",
			},
		),
		Middleware: serpent.Chain(
			serpent.RequireNArgs(1),
			initLogger(&verbose, ptr.To(false), logger, &logf),
			initAuth(&overlayOpts.authKey, &overlayOpts.clientAuth),
			derpMap(&derpmapFi, dm),
			sendOverlayMW(overlayOpts, &send, logger, dm, &logf),
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

			s, err := tsserver.NewServer(ctx, logger, send, dm)
			if err != nil {
				return err
			}

			if send.Auth.ReceiverDERPRegionID != 0 {
				go send.ListenOverlayDERP(ctx)
			} else if send.Auth.ReceiverStunAddr.IsValid() {
				go send.ListenOverlaySTUN(ctx)
			} else {
				return errors.New("auth key provided neither DERP nor STUN")
			}

			go s.ListenAndServe(ctx)

			netns.SetDialerOverride(s.Dialer())
			ts, err := newTSNet("send", verbose)
			if err != nil {
				return err
			}

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
				err := waitUntilHasP2P(ctx, logf, lc)
				if err != nil {
					return err
				}
			}

			bar := progressbar.DefaultBytes(
				fiStat.Size(),
				fmt.Sprintf("Uploading %q", fiPath),
			)
			defer bar.Close()
			barReader := progressbar.NewReader(fi, bar)

			hc := ts.HTTPClient()
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, fileUploadURL(ip, fiName), &barReader)
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
				Env:         "WUSH_AUTH_KEY",
				Description: "The auth key returned by " + cliui.Code("wush serve") + ". If not provided, it will be asked for on startup.",
				Default:     "",
				Value:       serpent.StringOf(&overlayOpts.authKey),
			},
			{
				Flag:        "derp-config-file",
				Description: "File which specifies the DERP config to use. In the structure of https://pkg.go.dev/tailscale.com/tailcfg#DERPMap. By default, https://controlplane.tailscale.com/derpmap/default is used.",
				Default:     "",
				Value:       serpent.StringOf(&derpmapFi),
			},
			{
				Flag:    "stun-ip-override",
				Default: "",
				Value:   serpent.StringOf(&overlayOpts.stunAddrOverride),
			},
			{
				Flag:        "wait-p2p",
				Description: "Waits for the connection to be p2p.",
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
