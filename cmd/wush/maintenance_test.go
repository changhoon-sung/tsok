package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func TestConnectTargetPort(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		target  string
		want    uint16
		wantErr bool
	}{
		{target: "127.0.0.1:22", want: 22},
		{target: "localhost:2222", want: 2222},
		{target: "[::1]:65535", want: 65535},
		{target: "192.0.2.1:22", wantErr: true},
		{target: "127.0.0.1:0", wantErr: true},
		{target: "127.0.0.1", wantErr: true},
	} {
		t.Run(tc.target, func(t *testing.T) {
			t.Parallel()
			got, err := connectTargetPort(tc.target)
			if (err != nil) != tc.wantErr {
				t.Fatalf("connectTargetPort(%q) error = %v, wantErr %v", tc.target, err, tc.wantErr)
			}
			if got != tc.want {
				t.Fatalf("connectTargetPort(%q) = %d, want %d", tc.target, got, tc.want)
			}
		})
	}
}

func TestBridgeStdio(t *testing.T) {
	t.Parallel()

	client, server := net.Pipe()
	defer server.Close()

	remoteErr := make(chan error, 1)
	go func() {
		request := make([]byte, len("request"))
		if _, err := io.ReadFull(server, request); err != nil {
			remoteErr <- fmt.Errorf("read request: %w", err)
			return
		}
		if string(request) != "request" {
			remoteErr <- fmt.Errorf("request = %q", request)
			return
		}
		if _, err := io.WriteString(server, "response"); err != nil {
			remoteErr <- fmt.Errorf("write response: %w", err)
			return
		}
		remoteErr <- server.Close()
	}()

	var stdout bytes.Buffer
	if err := bridgeStdio(context.Background(), client, strings.NewReader("request"), &stdout); err != nil {
		t.Fatalf("bridge stdio: %v", err)
	}
	if err := <-remoteErr; err != nil {
		t.Fatalf("remote: %v", err)
	}
	if got := stdout.String(); got != "response" {
		t.Fatalf("stdout = %q, want %q", got, "response")
	}
}

func TestBridgeStdioConcurrent(t *testing.T) {
	t.Parallel()

	const connectionCount = 2
	type bridgeResult struct {
		id     int
		stdout string
		err    error
	}

	bridgeResults := make(chan bridgeResult, connectionCount)
	remoteErrors := make(chan error, connectionCount)
	for id := range connectionCount {
		client, server := net.Pipe()
		request := fmt.Sprintf("request-%d", id)
		response := fmt.Sprintf("response-%d", id)

		go func() {
			defer server.Close()
			got := make([]byte, len(request))
			if _, err := io.ReadFull(server, got); err != nil {
				remoteErrors <- fmt.Errorf("connection %d read request: %w", id, err)
				return
			}
			if string(got) != request {
				remoteErrors <- fmt.Errorf("connection %d request = %q, want %q", id, got, request)
				return
			}
			if _, err := io.WriteString(server, response); err != nil {
				remoteErrors <- fmt.Errorf("connection %d write response: %w", id, err)
				return
			}
			remoteErrors <- nil
		}()

		go func() {
			var stdout bytes.Buffer
			err := bridgeStdio(context.Background(), client, strings.NewReader(request), &stdout)
			bridgeResults <- bridgeResult{id: id, stdout: stdout.String(), err: err}
		}()
	}

	seen := make(map[int]bool, connectionCount)
	for range connectionCount {
		if err := <-remoteErrors; err != nil {
			t.Fatal(err)
		}
		result := <-bridgeResults
		if result.err != nil {
			t.Fatalf("connection %d bridge stdio: %v", result.id, result.err)
		}
		want := fmt.Sprintf("response-%d", result.id)
		if result.stdout != want {
			t.Fatalf("connection %d stdout = %q, want %q", result.id, result.stdout, want)
		}
		seen[result.id] = true
	}
	if len(seen) != connectionCount {
		t.Fatalf("completed connection count = %d, want %d", len(seen), connectionCount)
	}
}

func TestBridgeStdioCancellation(t *testing.T) {
	t.Parallel()

	client, server := net.Pipe()
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := bridgeStdio(ctx, client, strings.NewReader(""), io.Discard)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("bridgeStdio() error = %v, want context.Canceled", err)
	}
}

func TestServeOpenSSHHelp(t *testing.T) {
	t.Parallel()

	got := serveOpenSSHHelp("test-auth-key", "alice")
	want := `Connect with OpenSSH:
WUSH_AUTH_KEY=test-auth-key ssh -o 'ProxyCommand=wush connect --stdio --quiet 127.0.0.1:%p' alice@wush

Or add this block to ~/.ssh/config:
Host wush
  HostName wush
  User alice
  ProxyCommand env WUSH_AUTH_KEY=test-auth-key wush connect --stdio --quiet 127.0.0.1:%p
`
	if got != want {
		t.Fatalf("OpenSSH help:\n%s\nwant:\n%s", got, want)
	}
	if !strings.HasSuffix(got, "\n") {
		t.Fatal("OpenSSH help must leave a blank line after the config block")
	}
	if strings.Contains(got, "--auth-key") {
		t.Fatal("OpenSSH help passes the auth key in argv")
	}
}

func TestLicenseReportURL(t *testing.T) {
	t.Parallel()

	const commitHash = "0123456789abcdef0123456789abcdef01234567"
	if got, want := licenseReportURL(commitHash), "https://github.com/changhoon-sung/wush/blob/"+commitHash+"/licenses/wush.md"; got != want {
		t.Fatalf("license report URL = %q, want %q", got, want)
	}
	if got, want := licenseReportURL(strings.Repeat("0", 40)), "https://github.com/changhoon-sung/wush/blob/main/licenses/wush.md"; got != want {
		t.Fatalf("development license report URL = %q, want %q", got, want)
	}
}

func TestPeerConnectionTracker(t *testing.T) {
	t.Parallel()

	nodeKey := key.NewNode().Public()
	peerIP := netip.MustParseAddr("fd7a:115c:a1e0::2")
	tracker := make(peerConnectionTracker)
	status := &ipnstate.Status{Peer: map[key.NodePublic]*ipnstate.PeerStatus{
		nodeKey: {
			TailscaleIPs: []netip.Addr{peerIP},
			CurAddr:      "192.0.2.1:41641",
			Relay:        "sea",
			Active:       true,
		},
	}}

	want := []peerConnectionEvent{{
		peer: peerIP.String(),
		path: peerConnectionPath{kind: peerConnectionPathDirect, endpoint: "192.0.2.1:41641"},
	}}
	if got := tracker.update(status); !reflect.DeepEqual(got, want) {
		t.Fatalf("initial direct events = %#v, want %#v", got, want)
	}
	if got := tracker.update(status); len(got) != 0 {
		t.Fatalf("unchanged direct events = %#v, want none", got)
	}

	status.Peer[nodeKey].CurAddr = ""
	want = []peerConnectionEvent{{
		peer: peerIP.String(),
		path: peerConnectionPath{kind: peerConnectionPathDERP, endpoint: "sea"},
	}}
	if got := tracker.update(status); !reflect.DeepEqual(got, want) {
		t.Fatalf("DERP events = %#v, want %#v", got, want)
	}

	status.Peer[nodeKey].Relay = ""
	status.Peer[nodeKey].PeerRelay = "fd7a:115c:a1e0::3:1:2"
	want = []peerConnectionEvent{{
		peer: peerIP.String(),
		path: peerConnectionPath{kind: peerConnectionPathPeerRelay, endpoint: "fd7a:115c:a1e0::3:1:2"},
	}}
	if got := tracker.update(status); !reflect.DeepEqual(got, want) {
		t.Fatalf("peer relay events = %#v, want %#v", got, want)
	}

	status.Peer[nodeKey].Active = false
	status.Peer[nodeKey].CurAddr = "203.0.113.3:41641"
	if got := tracker.update(status); len(got) != 0 {
		t.Fatalf("inactive peer events = %#v, want none", got)
	}
	if len(tracker) != 0 {
		t.Fatalf("tracker retained %d inactive peers", len(tracker))
	}

	status.Peer = map[key.NodePublic]*ipnstate.PeerStatus{}
	if got := tracker.update(status); len(got) != 0 {
		t.Fatalf("removed peer events = %#v, want none", got)
	}
	if len(tracker) != 0 {
		t.Fatalf("tracker retained %d removed peers", len(tracker))
	}
}

func TestPeerConnectionLog(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	humanLog := serveHumanLog{
		out: &output,
		now: func() time.Time {
			return time.Date(2026, time.August, 22, 1, 2, 3, 0, time.UTC)
		},
	}
	dm := &tailcfg.DERPMap{Regions: map[int]*tailcfg.DERPRegion{
		10: {RegionCode: "sea", RegionName: "Seattle"},
	}}

	logPeerConnectionPath(humanLog, dm, peerConnectionEvent{
		peer: "fd7a:115c:a1e0::2",
		path: peerConnectionPath{kind: peerConnectionPathDirect, endpoint: "192.0.2.1:41641"},
	})
	logPeerConnectionPath(humanLog, dm, peerConnectionEvent{
		peer: "fd7a:115c:a1e0::2",
		path: peerConnectionPath{kind: peerConnectionPathDERP, endpoint: "sea"},
	})

	want := "01:02:03 Peer fd7a:115c:a1e0::2 connected directly via 192.0.2.1:41641\n" +
		"01:02:03 Peer fd7a:115c:a1e0::2 relayed via Seattle (sea)\n"
	if got := output.String(); got != want {
		t.Fatalf("connection log = %q, want %q", got, want)
	}
}

func TestBicopyCancellationClosesConnections(t *testing.T) {
	t.Parallel()

	left, leftPeer := net.Pipe()
	right, rightPeer := net.Pipe()
	defer leftPeer.Close()
	defer rightPeer.Close()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		bicopy(ctx, left, right)
		close(done)
	}()
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("bicopy did not exit after cancellation")
	}
}

func TestParsePortRangeIncludesMaximumPort(t *testing.T) {
	t.Parallel()

	got, err := parsePortRange("65534-65535")
	if err != nil {
		t.Fatalf("parse range: %v", err)
	}
	want := []uint16{65534, 65535}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ports = %v, want %v", got, want)
	}
}

func TestUploadFileName(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		path    string
		want    string
		wantErr bool
	}{
		{path: "/report.txt", want: "report.txt"},
		{path: "/report with spaces.txt", want: "report with spaces.txt"},
		{path: "report.txt", want: "report.txt"},
		{path: "/", wantErr: true},
		{path: "/../secret", wantErr: true},
		{path: "/subdir/secret", wantErr: true},
		{path: `\..\secret`, wantErr: true},
		{path: "/..", wantErr: true},
	} {
		t.Run(tc.path, func(t *testing.T) {
			t.Parallel()
			got, err := uploadFileName(tc.path)
			if (err != nil) != tc.wantErr {
				t.Fatalf("uploadFileName(%q) error = %v, wantErr %v", tc.path, err, tc.wantErr)
			}
			if got != tc.want {
				t.Fatalf("uploadFileName(%q) = %q, want %q", tc.path, got, tc.want)
			}
		})
	}
}

func TestFileUploadURL(t *testing.T) {
	t.Parallel()

	raw := fileUploadURL(netip.MustParseAddr("fd7a:115c:a1e0::1"), "report #1?.txt")
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse upload URL: %v", err)
	}
	if u.Host != "[fd7a:115c:a1e0::1]:4444" {
		t.Fatalf("host = %q", u.Host)
	}
	if u.Path != "/report #1?.txt" {
		t.Fatalf("path = %q", u.Path)
	}
}

func TestReadUploadResponse(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name       string
		statusCode int
		body       string
		want       string
		wantErr    string
	}{
		{name: "success", statusCode: http.StatusCreated, body: "written\n", want: "written"},
		{name: "server error", statusCode: http.StatusInternalServerError, body: "disk full\n", wantErr: "500 Internal Server Error: disk full"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			res := &http.Response{
				StatusCode: tc.statusCode,
				Status:     fmt.Sprintf("%d %s", tc.statusCode, http.StatusText(tc.statusCode)),
				Body:       io.NopCloser(strings.NewReader(tc.body)),
			}
			got, err := readUploadResponse(res)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("readUploadResponse() error = %v, want containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("readUploadResponse() error = %v", err)
			}
			if got != tc.want {
				t.Fatalf("readUploadResponse() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestBuildRsyncArgsPreservesBoundariesAndForwardsOptions(t *testing.T) {
	t.Parallel()

	opts := &sendOverlayOpts{
		waitP2P: true,
	}
	forwarded := []string{"local file.txt", ":/remote path", "; touch /tmp/not-run"}
	got := buildRsyncArgs("/Applications/wush's bin/wush", forwarded, opts, true)
	want := []string{
		"-e",
		`'/Applications/wush'"'"'s bin/wush' 'ssh' '--quiet' '--wait-p2p' '--verbose' '--'`,
		"local file.txt",
		":/remote path",
		"; touch /tmp/not-run",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("buildRsyncArgs() = %#v, want %#v", got, want)
	}
}
