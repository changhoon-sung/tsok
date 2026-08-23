package tsserver

import (
	"context"
	"encoding/hex"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/changhoon-sung/tsok/overlay"
	"tailscale.com/client/tailscale"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/ipn/store"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
	"tailscale.com/types/key"
	"tailscale.com/types/ptr"
)

type integrationOverlay struct {
	recv    chan overlay.PeerUpdate
	updates chan *tailcfg.Node
}

func (o *integrationOverlay) Recv() <-chan overlay.PeerUpdate {
	return o.recv
}

func (o *integrationOverlay) SendTailscaleNodeUpdate(node *tailcfg.Node) {
	o.updates <- node.Clone()
}

func (o *integrationOverlay) IPs() []netip.Addr {
	return []netip.Addr{netip.MustParseAddr("fd7a:115c:a1e0::1")}
}

func TestUpstreamTSNetHandshake(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	ov := &integrationOverlay{
		recv:    make(chan overlay.PeerUpdate),
		updates: make(chan *tailcfg.Node, 1),
	}
	s, err := NewServer(ctx, slog.Default(), ov, &tailcfg.DERPMap{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })

	controlURL, err := url.Parse(s.ControlURL())
	if err != nil {
		t.Fatal(err)
	}
	controlToken := strings.TrimPrefix(controlURL.Path, "/")
	if len(controlToken) != 64 {
		t.Fatalf("control path token length = %d, want 64", len(controlToken))
	}
	if _, err := hex.DecodeString(controlToken); err != nil {
		t.Fatalf("control path token is not hexadecimal: %v", err)
	}

	go func() { _ = s.ListenAndServe(ctx) }()

	ts, lc := startIntegrationTSNet(t, s, "initial")

	select {
	case node := <-ov.updates:
		if len(node.Addresses) == 0 {
			t.Fatal("registered node has no assigned address")
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for the control server to register the tsnet node")
	}
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-ov.updates:
			}
		}
	}()

	waitForIntegrationStatus(t, ctx, lc, func(status *ipnstate.Status) bool {
		return len(status.TailscaleIPs) > 0
	}, "tsnet to consume the streamed network map")

	peerKey := key.NewNode().Public()
	peerIP := netip.MustParseAddr("fd7a:115c:a1e0::2")
	peerPrefix := netip.PrefixFrom(peerIP, peerIP.BitLen())
	ov.recv <- overlay.PeerUpdate{ID: "peer-a", Node: &tailcfg.Node{
		ID:                tailcfg.NodeID(2),
		StableID:          tailcfg.StableNodeID("cached-peer"),
		Name:              "cached-peer",
		User:              tailcfg.UserID(123),
		Machine:           key.NewMachine().Public(),
		Key:               peerKey,
		DiscoKey:          key.NewDisco().Public(),
		Addresses:         []netip.Prefix{peerPrefix},
		AllowedIPs:        []netip.Prefix{peerPrefix},
		Online:            ptr.To(true),
		MachineAuthorized: true,
	}}
	secondPeerKey := key.NewNode().Public()
	secondPeerIP := netip.MustParseAddr("fd7a:115c:a1e0::3")
	secondPeerPrefix := netip.PrefixFrom(secondPeerIP, secondPeerIP.BitLen())
	ov.recv <- overlay.PeerUpdate{ID: "peer-b", Node: &tailcfg.Node{
		ID:                tailcfg.NodeID(3),
		StableID:          tailcfg.StableNodeID("second-peer"),
		Name:              "second-peer",
		User:              tailcfg.UserID(123),
		Machine:           key.NewMachine().Public(),
		Key:               secondPeerKey,
		DiscoKey:          key.NewDisco().Public(),
		Addresses:         []netip.Prefix{secondPeerPrefix},
		AllowedIPs:        []netip.Prefix{secondPeerPrefix},
		Online:            ptr.To(true),
		MachineAuthorized: true,
	}}
	waitForIntegrationStatus(t, ctx, lc, func(status *ipnstate.Status) bool {
		return status.Peer[peerKey] != nil && status.Peer[secondPeerKey] != nil
	}, "initial tsnet to receive both overlay peers")

	ov.recv <- overlay.PeerUpdate{ID: "peer-a"}
	waitForIntegrationStatus(t, ctx, lc, func(status *ipnstate.Status) bool {
		return status.Peer[peerKey] == nil && status.Peer[secondPeerKey] != nil
	}, "initial tsnet to remove the disconnected overlay peer")

	if err := ts.Close(); err != nil {
		t.Fatal(err)
	}
	_, reconnectedClient := startIntegrationTSNet(t, s, "reconnected")
	waitForIntegrationStatus(t, ctx, reconnectedClient, func(status *ipnstate.Status) bool {
		return status.Peer[peerKey] == nil && status.Peer[secondPeerKey] != nil
	}, "reconnected tsnet to receive only the active cached overlay peer")
}

func startIntegrationTSNet(t *testing.T, s *server, name string) (*tsnet.Server, *tailscale.LocalClient) {
	t.Helper()
	logf := func(string, ...any) {}
	state, err := store.New(logf, "mem:tsok-upstream-integration-"+name)
	if err != nil {
		t.Fatal(err)
	}
	ts := &tsnet.Server{
		Dir:        t.TempDir(),
		Store:      state,
		Hostname:   "tsok-upstream-integration-" + name,
		Ephemeral:  true,
		AuthKey:    "integration-test-" + name,
		ControlURL: s.ControlURL(),
		Logf:       logf,
		UserLogf:   logf,
	}
	t.Cleanup(func() { _ = ts.Close() })
	if err := ts.Start(); err != nil {
		t.Fatal(err)
	}
	lc, err := ts.LocalClient()
	if err != nil {
		t.Fatal(err)
	}
	return ts, lc
}

func waitForIntegrationStatus(t *testing.T, ctx context.Context, lc *tailscale.LocalClient, ready func(*ipnstate.Status) bool, description string) {
	t.Helper()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		status, err := lc.Status(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if ready(status) {
			return
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			t.Fatalf("timed out waiting for %s", description)
		}
	}
}

func TestApplyPeerChangePreservesLegacyDERP(t *testing.T) {
	node := &tailcfg.Node{}
	applyPeerChange(node, tailcfg.PeerChange{DERPRegion: 7})

	if got, want := node.HomeDERP, 7; got != want {
		t.Fatalf("HomeDERP = %d, want %d", got, want)
	}
	if got, want := node.LegacyDERPString, tailcfg.DerpMagicIP+":7"; got != want {
		t.Fatalf("LegacyDERPString = %q, want %q", got, want)
	}
}

func TestNoiseUpgradeRejectsSecondActiveConnection(t *testing.T) {
	s := &server{}
	s.noiseActive.Store(true)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/ts2021", nil)
	s.NoiseUpgradeHandler(recorder, request)
	if got, want := recorder.Code, http.StatusServiceUnavailable; got != want {
		t.Fatalf("status = %d, want %d", got, want)
	}
}
