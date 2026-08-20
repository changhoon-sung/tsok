package main

import (
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

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
		stunAddrOverride: "192.0.2.10",
		waitP2P:          true,
	}
	forwarded := []string{"local file.txt", ":/remote path", "; touch /tmp/not-run"}
	got := buildRsyncArgs("/Applications/wush's bin/wush", forwarded, opts, true)
	want := []string{
		"-e",
		`'/Applications/wush'"'"'s bin/wush' 'ssh' '--quiet' '--stun-ip-override' '192.0.2.10' '--wait-p2p' '--verbose' '--'`,
		"local file.txt",
		":/remote path",
		"; touch /tmp/not-run",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("buildRsyncArgs() = %#v, want %#v", got, want)
	}
}
