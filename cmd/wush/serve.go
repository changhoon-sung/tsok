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
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/schollz/progressbar/v3"
	"golang.org/x/term"
	"tailscale.com/client/tailscale"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/ipn/store"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
	"tailscale.com/types/key"

	"github.com/coder/pretty"
	"github.com/coder/serpent"
	"github.com/coder/wush/cliui"
	"github.com/coder/wush/overlay"
	"github.com/coder/wush/tsserver"
	"github.com/coder/wush/xssh"
)

func serveCmd() *serpent.Command {
	var (
		verbose   bool
		enabled   = []string{}
		disabled  = []string{}
		derpmapFi string

		dm = new(tailcfg.DERPMap)
	)
	return &serpent.Command{
		Use:   "serve",
		Short: "Run the wush server. Allow wush clients to connect.",
		Middleware: serpent.Chain(
			derpMap(&derpmapFi, dm),
		),
		Handler: func(inv *serpent.Invocation) error {
			ctx, ctxCancel := inv.SignalNotifyContext(inv.Context(), os.Interrupt)
			defer ctxCancel()
			humanLog := serveHumanLog{out: inv.Stderr, now: time.Now}
			plainf := func(format string, args ...any) {
				fmt.Fprintf(inv.Stderr, format+"\n", args...)
			}
			var logSink io.Writer = io.Discard
			if verbose {
				logSink = inv.Stderr
			}
			logger := slog.New(slog.NewTextHandler(logSink, nil))
			r := overlay.NewReceiveOverlay(logger, humanLog.info, dm)

			if err := r.PickDERPHome(ctx); err != nil {
				return err
			}
			go r.ListenOverlayDERP(ctx)

			authKey := r.ClientAuth().AuthKey()
			portForwardEnabled := slices.Contains(enabled, "port-forward") && !slices.Contains(disabled, "port-forward")

			// Ensure we always print the auth key on stdout.
			if term.IsTerminal(int(os.Stdout.Fd())) {
				plainf("\n%s", cliui.Bold("Your auth key is:"))
				fmt.Println("  >", cliui.Code(authKey))
				plainf("Use this key to authenticate other wush commands to this instance.")
				if portForwardEnabled {
					plainf("\n%s", serveOpenSSHHelp(authKey, serveUsername()))
				}
			} else {
				fmt.Println(cliui.Code(authKey))
				humanLog.info("The auth key has been printed to stdout")
			}

			s, err := tsserver.NewServer(ctx, logger, r, dm)
			if err != nil {
				return err
			}
			defer s.Close()

			go func() {
				if err := s.ListenAndServe(ctx); err != nil && ctx.Err() == nil {
					humanLog.error("Local control server exited: %s", err)
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

				go func() {
					err := sshSrv.Serve(sshListener)
					if err != nil && ctx.Err() == nil {
						humanLog.error("SSH server exited: %s", err)
					}
				}()
			} else {
				humanLog.warn("SSH server %s", pretty.Sprint(cliui.DefaultStyles.Disabled, "disabled"))
			}

			if slices.Contains(enabled, "cp") && !slices.Contains(disabled, "cp") {
				cpListener, err := ts.Listen("tcp", ":4444")
				if err != nil {
					return err
				}
				closers = append([]io.Closer{cpListener}, closers...)

				go func() {
					err := http.Serve(cpListener, cpHandler(humanLog.info))
					if err != nil && ctx.Err() == nil {
						humanLog.error("File transfer server exited: %s", err)
					}
				}()
			} else {
				humanLog.warn("File transfer server %s", pretty.Sprint(cliui.DefaultStyles.Disabled, "disabled"))
			}

			if portForwardEnabled {
				ts.RegisterFallbackTCPHandler(func(src, dst netip.AddrPort) (handler func(net.Conn), intercept bool) {
					return func(src net.Conn) {
						dst, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", dst.Port()))
						if err != nil {
							humanLog.error("Failed to dial forwarded connection: %s", err)
							src.Close()
							return
						}

						bicopy(ctx, src, dst)
					}, true
				})
			} else {
				humanLog.warn("Port-forward server %s", pretty.Sprint(cliui.DefaultStyles.Disabled, "disabled"))
			}

			lc, err := ts.LocalClient()
			if err != nil {
				return fmt.Errorf("get local client: %w", err)
			}
			go monitorPeerConnections(ctx, lc, dm, humanLog)

			closers = append(closers, ts)
			<-ctx.Done()
			for _, closer := range closers {
				closer.Close()
			}
			return nil
		},
		Options: []serpent.Option{
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

type serveHumanLog struct {
	out io.Writer
	now func() time.Time
}

func (log serveHumanLog) write(format string, args ...any) {
	fmt.Fprintf(log.out, "%s %s\n", cliui.Timestamp(log.now()), fmt.Sprintf(format, args...))
}

func (log serveHumanLog) info(format string, args ...any) {
	log.write(format, args...)
}

func (log serveHumanLog) warn(format string, args ...any) {
	log.write(format, args...)
}

func (log serveHumanLog) error(format string, args ...any) {
	log.write(format, args...)
}

type peerConnectionPathKind uint8

const (
	peerConnectionPathDirect peerConnectionPathKind = iota + 1
	peerConnectionPathDERP
	peerConnectionPathPeerRelay
)

type peerConnectionPath struct {
	kind     peerConnectionPathKind
	endpoint string
}

type peerConnectionEvent struct {
	peer string
	path peerConnectionPath
}

type peerConnectionTracker map[key.NodePublic]peerConnectionPath

func (tracker peerConnectionTracker) update(status *ipnstate.Status) []peerConnectionEvent {
	seen := make(map[key.NodePublic]bool, len(status.Peer))
	events := make([]peerConnectionEvent, 0)
	for nodeKey, peer := range status.Peer {
		seen[nodeKey] = true
		path, active := currentPeerConnectionPath(peer)
		if !active {
			delete(tracker, nodeKey)
			continue
		}
		if tracker[nodeKey] == path {
			continue
		}
		tracker[nodeKey] = path

		peerLabel := nodeKey.ShortString()
		if len(peer.TailscaleIPs) > 0 {
			peerLabel = peer.TailscaleIPs[0].String()
		}
		events = append(events, peerConnectionEvent{
			peer: peerLabel,
			path: path,
		})
	}
	for nodeKey := range tracker {
		if !seen[nodeKey] {
			delete(tracker, nodeKey)
		}
	}
	sort.Slice(events, func(i, j int) bool {
		if events[i].peer == events[j].peer {
			if events[i].path.kind == events[j].path.kind {
				return events[i].path.endpoint < events[j].path.endpoint
			}
			return events[i].path.kind < events[j].path.kind
		}
		return events[i].peer < events[j].peer
	})
	return events
}

func currentPeerConnectionPath(peer *ipnstate.PeerStatus) (peerConnectionPath, bool) {
	if peer == nil || !peer.Active {
		return peerConnectionPath{}, false
	}
	if peer.Relay != "" && peer.CurAddr == "" && peer.PeerRelay == "" {
		return peerConnectionPath{kind: peerConnectionPathDERP, endpoint: peer.Relay}, true
	}
	if peer.CurAddr != "" {
		return peerConnectionPath{kind: peerConnectionPathDirect, endpoint: peer.CurAddr}, true
	}
	if peer.PeerRelay != "" {
		return peerConnectionPath{kind: peerConnectionPathPeerRelay, endpoint: peer.PeerRelay}, true
	}
	return peerConnectionPath{}, false
}

func monitorPeerConnections(ctx context.Context, lc *tailscale.LocalClient, dm *tailcfg.DERPMap, humanLog serveHumanLog) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	tracker := make(peerConnectionTracker)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			status, err := lc.Status(ctx)
			if err != nil {
				continue
			}
			for _, event := range tracker.update(status) {
				logPeerConnectionPath(humanLog, dm, event)
			}
		}
	}
}

func logPeerConnectionPath(humanLog serveHumanLog, dm *tailcfg.DERPMap, event peerConnectionEvent) {
	switch event.path.kind {
	case peerConnectionPathDirect:
		humanLog.write("Peer %s connected directly via %s", event.peer, event.path.endpoint)
	case peerConnectionPathDERP:
		humanLog.write("Peer %s relayed via %s", event.peer, cliui.Code(derpRegionLabel(dm, event.path.endpoint)))
	case peerConnectionPathPeerRelay:
		humanLog.write("Peer %s relayed via %s", event.peer, event.path.endpoint)
	}
}

func derpRegionLabel(dm *tailcfg.DERPMap, code string) string {
	if dm != nil {
		for _, region := range dm.Regions {
			if region != nil && strings.EqualFold(region.RegionCode, code) {
				return fmt.Sprintf("%s (%s)", region.RegionName, region.RegionCode)
			}
		}
	}
	return code
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
	authAssignment := "WUSH_AUTH_KEY=" + authKey
	proxyOption := "'ProxyCommand=wush connect --stdio --quiet 127.0.0.1:%p'"
	command := fmt.Sprintf("%s ssh -o %s %s@wush", authAssignment, proxyOption, username)
	proxyCommand := fmt.Sprintf("env %s wush connect --stdio --quiet 127.0.0.1:%%p", authAssignment)
	return fmt.Sprintf(`%s
%s

%s
%s
  HostName wush
  User %s
  %s %s
`,
		cliui.Bold("Connect with OpenSSH:"),
		command,
		cliui.Bold("Or add this block to ~/.ssh/config:"),
		cliui.Bold("Host wush"),
		username,
		"ProxyCommand", proxyCommand,
	)
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

func cpHandler(hlog func(string, ...any)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		hlog("Received file %s from %s", fiName, r.RemoteAddr)
	})
}

func uploadFileName(requestPath string) (string, error) {
	name := strings.TrimPrefix(requestPath, "/")
	if name == "" || name == "." || name == ".." || strings.Contains(name, `\`) || name != path.Base(name) || name != filepath.Base(name) {
		return "", fmt.Errorf("invalid upload filename %q", requestPath)
	}
	return name, nil
}
