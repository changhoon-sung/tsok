package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"github.com/schollz/progressbar/v3"
	"golang.org/x/term"
	"tailscale.com/ipn/store"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"

	"github.com/coder/pretty"
	"github.com/coder/serpent"
	"github.com/coder/wush/cliui"
	"github.com/coder/wush/overlay"
	"github.com/coder/wush/tsserver"
	"github.com/coder/wush/xssh"
)

func serveCmd() *serpent.Command {
	var (
		overlayType string
		verbose     bool
		enabled     = []string{}
		disabled    = []string{}
		derpmapFi   string

		dm = new(tailcfg.DERPMap)
	)
	return &serpent.Command{
		Use:   "serve",
		Short: "Run the wush server. Allow wush clients to connect.",
		Middleware: serpent.Chain(
			derpMap(&derpmapFi, dm),
		),
		Handler: func(inv *serpent.Invocation) error {
			ctx := inv.Context()
			var logSink io.Writer = io.Discard
			if verbose {
				logSink = inv.Stderr
			}
			logger := slog.New(slog.NewTextHandler(logSink, nil))
			hlog := func(format string, args ...any) {
				fmt.Fprintf(inv.Stderr, format+"\n", args...)
			}
			r := overlay.NewReceiveOverlay(logger, hlog, dm)

			var err error
			switch overlayType {
			case "derp":
				err = r.PickDERPHome(ctx)
				if err != nil {
					return err
				}
				go r.ListenOverlayDERP(ctx)

			case "stun":
				waitStun, err := r.ListenOverlaySTUN(ctx)
				if err != nil {
					return fmt.Errorf("get stun addr: %w", err)
				}
				<-waitStun

			default:
				return fmt.Errorf("unknown overlay type: %s", overlayType)
			}

			authKey := r.ClientAuth().AuthKey()
			portForwardEnabled := slices.Contains(enabled, "port-forward") && !slices.Contains(disabled, "port-forward")

			// Ensure we always print the auth key on stdout.
			if term.IsTerminal(int(os.Stdout.Fd())) {
				hlog("Your auth key is:")
				fmt.Println("  >", cliui.Code(authKey))
				hlog("Use this key to authenticate other " + cliui.Code("wush") + " commands to this instance.")
				if portForwardEnabled {
					hlog("\n%s", serveOpenSSHHelp(authKey, serveUsername()))
				}
			} else {
				fmt.Println(cliui.Code(authKey))
				hlog("The auth key has been printed to stdout")
			}

			s, err := tsserver.NewServer(ctx, logger, r, dm)
			if err != nil {
				return err
			}
			defer s.Close()

			go func() {
				if err := s.ListenAndServe(ctx); err != nil {
					logger.Error("local control server stopped", "err", err)
				}
			}()
			ts, err := newTSNet("receive", verbose, s.ControlURL())
			if err != nil {
				return err
			}
			defer ts.Close()

			_, err = ts.Up(ctx)
			if err != nil {
				return fmt.Errorf("bring wireguard up: %w", err)
			}
			// hlog("WireGuard is ready")

			closers := []io.Closer{}

			if slices.Contains(enabled, "ssh") && !slices.Contains(disabled, "ssh") {
				sshSrv, err := xssh.NewServer()
				if err != nil {
					return err
				}
				closers = append(closers, sshSrv)

				sshListener, err := ts.Listen("tcp", ":3")
				if err != nil {
					return err
				}
				closers = append(closers, sshListener)

				// TODO: replace these logs with all of the options in the beginning.
				// hlog("SSH server " + pretty.Sprint(cliui.DefaultStyles.Enabled, "enabled"))
				go func() {
					err := sshSrv.Serve(sshListener)
					if err != nil {
						hlog("SSH server exited: " + err.Error())
					}
				}()
			} else {
				hlog("SSH server " + pretty.Sprint(cliui.DefaultStyles.Disabled, "disabled"))
			}

			if slices.Contains(enabled, "cp") && !slices.Contains(disabled, "cp") {
				cpListener, err := ts.Listen("tcp", ":4444")
				if err != nil {
					return err
				}
				closers = append([]io.Closer{cpListener}, closers...)

				// hlog("File transfer server " + pretty.Sprint(cliui.DefaultStyles.Enabled, "enabled"))
				go func() {
					err := http.Serve(cpListener, http.HandlerFunc(cpHandler))
					if err != nil {
						hlog("File transfer server exited: " + err.Error())
					}
				}()
			} else {
				hlog("File transfer server " + pretty.Sprint(cliui.DefaultStyles.Disabled, "disabled"))
			}

			if portForwardEnabled {
				ts.RegisterFallbackTCPHandler(func(src, dst netip.AddrPort) (handler func(net.Conn), intercept bool) {
					return func(src net.Conn) {
						dst, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", dst.Port()))
						if err != nil {
							hlog(pretty.Sprint(cliui.DefaultStyles.Warn, "Failed to dial forwarded connection:", err.Error()))
							src.Close()
							return
						}

						bicopy(ctx, src, dst)
					}, true
				})
				// hlog("Port-forward server " + pretty.Sprint(cliui.DefaultStyles.Enabled, "enabled"))
			} else {
				hlog("Port-forward server " + pretty.Sprint(cliui.DefaultStyles.Disabled, "disabled"))
			}

			ctx, ctxCancel := inv.SignalNotifyContext(ctx, os.Interrupt)
			defer ctxCancel()

			closers = append(closers, ts)
			<-ctx.Done()
			for _, closer := range closers {
				closer.Close()
			}
			return nil
		},
		Options: []serpent.Option{
			{
				Flag:    "overlay-type",
				Default: "derp",
				Value:   serpent.EnumOf(&overlayType, "derp", "stun"),
			},
			{
				Flag:          "verbose",
				FlagShorthand: "v",
				Description:   "Enable verbose logging.",
				Default:       "false",
				Value:         serpent.BoolOf(&verbose),
			},
			{
				Flag:        "enable",
				Description: "Server options to enable.",
				Default:     "ssh,cp,port-forward",
				Value:       serpent.EnumArrayOf(&enabled, "ssh", "cp", "port-forward"),
			},
			{
				Flag:        "disable",
				Description: "Server options to disable.",
				Default:     "",
				Value:       serpent.EnumArrayOf(&disabled, "ssh", "cp", "port-forward"),
			},
			{
				Flag:        "derp-config-file",
				Description: "File which specifies the DERP config to use. In the structure of https://pkg.go.dev/tailscale.com/tailcfg#DERPMap.",
				Default:     "",
				Value:       serpent.StringOf(&derpmapFi),
			},
		},
	}
}

func serveUsername() string {
	if username := os.Getenv("USER"); username != "" {
		return username
	}
	if username := os.Getenv("USERNAME"); username != "" {
		return username
	}
	return "user"
}

func serveOpenSSHHelp(authKey, username string) string {
	return fmt.Sprintf(`Connect with OpenSSH:
WUSH_AUTH_KEY=%s ssh -o 'ProxyCommand=wush connect --stdio --quiet 127.0.0.1:%%p' %s@wush

Or add this block to ~/.ssh/config:
Host wush
  HostName wush
  User %s
  ProxyCommand env WUSH_AUTH_KEY=%s wush connect --stdio --quiet 127.0.0.1:%%p`, authKey, username, username, authKey)
}

func newTSNet(direction string, verbose bool, controlURL string) (*tsnet.Server, error) {
	var err error
	tmp := os.TempDir()
	srv := new(tsnet.Server)
	srv.Dir = tmp
	srv.Hostname = "wush-" + direction
	srv.Ephemeral = true
	srv.AuthKey = direction
	srv.ControlURL = controlURL
	srv.Logf = func(format string, args ...any) {}
	srv.UserLogf = func(format string, args ...any) {}
	if verbose {
		logf := func(format string, args ...any) {
			fmt.Fprintf(os.Stderr, format+"\n", args...)
		}
		srv.Logf = logf
		srv.UserLogf = logf
	}

	srv.Store, err = store.New(func(format string, args ...any) {}, "mem:wush")
	if err != nil {
		return nil, fmt.Errorf("create state store: %w", err)
	}

	return srv, nil
}

func bicopy(ctx context.Context, c1, c2 io.ReadWriteCloser) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	defer func() {
		_ = c1.Close()
		_ = c2.Close()
	}()

	var wg sync.WaitGroup
	copyFunc := func(dst io.WriteCloser, src io.Reader) {
		defer func() {
			wg.Done()
			// If one side of the copy fails, ensure the other one exits as
			// well.
			cancel()
		}()
		_, _ = io.Copy(dst, src)
	}

	wg.Add(2)
	go copyFunc(c1, c2)
	go copyFunc(c2, c1)

	// Convert waitgroup to a channel so we can also wait on the context.
	done := make(chan struct{})
	go func() {
		defer close(done)
		wg.Wait()
	}()

	select {
	case <-ctx.Done():
	case <-done:
	}
}

func cpHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
		return
	}

	fiName, err := uploadFileName(r.URL.Path)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	fi, err := os.OpenFile(fiName, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0644)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer fi.Close()

	bar := progressbar.DefaultBytes(
		r.ContentLength,
		fmt.Sprintf("Downloading %q", fiName),
	)
	defer bar.Close()
	_, err = io.Copy(io.MultiWriter(fi, bar), r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf("File %q written", fiName)))
	fmt.Printf("Received file %s from %s\n", fiName, r.RemoteAddr)
}

func uploadFileName(requestPath string) (string, error) {
	name := strings.TrimPrefix(requestPath, "/")
	if name == "" || name == "." || name == ".." || strings.Contains(name, `\`) || name != path.Base(name) || name != filepath.Base(name) {
		return "", fmt.Errorf("invalid upload filename %q", requestPath)
	}
	return name, nil
}
