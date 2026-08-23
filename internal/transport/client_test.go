package transport

import (
	"context"
	"net/netip"
	"testing"

	"tailscale.com/ipn/ipnstate"
	"tailscale.com/types/key"
)

type staticStatusClient struct {
	status *ipnstate.Status
}

func (c staticStatusClient) Status(context.Context) (*ipnstate.Status, error) {
	return c.status, nil
}

func TestWaitForPeerReportsRelayRoute(t *testing.T) {
	t.Parallel()

	peerIP := netip.MustParseAddr("fd7a:115c:a1e0::2")
	nodeKey := key.NewNode().Public()
	status := &ipnstate.Status{Peer: map[key.NodePublic]*ipnstate.PeerStatus{
		nodeKey: {TailscaleIPs: []netip.Addr{peerIP}, Relay: "lax", Active: true},
	}}
	route, err := waitForPeer(context.Background(), nil, staticStatusClient{status: status})
	if err != nil {
		t.Fatal(err)
	}
	if route.IP != peerIP || route.Relay != "lax" || route.Direct {
		t.Fatalf("route = %#v, want relay lax to %s", route, peerIP)
	}
}

func TestWaitForPeerReportsDirectRoute(t *testing.T) {
	t.Parallel()

	peerIP := netip.MustParseAddr("fd7a:115c:a1e0::2")
	nodeKey := key.NewNode().Public()
	status := &ipnstate.Status{Peer: map[key.NodePublic]*ipnstate.PeerStatus{
		nodeKey: {TailscaleIPs: []netip.Addr{peerIP}, Relay: "lax", CurAddr: "192.0.2.1:41641", Active: true},
	}}
	route, err := waitForPeer(context.Background(), nil, staticStatusClient{status: status})
	if err != nil {
		t.Fatal(err)
	}
	if route.IP != peerIP || !route.Direct || route.Endpoint != "192.0.2.1:41641" {
		t.Fatalf("route = %#v, want direct route", route)
	}
}
