package overlay

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"testing"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func TestSendRejectsMalformedOverlayMessage(t *testing.T) {
	t.Parallel()

	receiverPrivate := key.NewNode()
	overlayPrivate := key.NewNode()
	send := &Send{
		Logger:    slog.Default(),
		SessionID: "session-a",
		Auth: ClientAuth{
			OverlayPrivateKey: overlayPrivate,
			ReceiverPublicKey: receiverPrivate.Public(),
		},
	}
	sealed := receiverPrivate.SealTo(overlayPrivate.Public(), []byte("{"))
	if _, err := send.handleNextMessage(sealed); err == nil {
		t.Fatal("handleNextMessage() succeeded for malformed JSON")
	}
}

func TestNewSendOverlayInitializesLogger(t *testing.T) {
	t.Parallel()

	logger := slog.Default()
	send := NewSendOverlay(logger, &tailcfg.DERPMap{})
	if send.Logger != logger {
		t.Fatal("send overlay did not retain its logger")
	}
}

func TestSendIgnoresLegacyWebRTCResponseField(t *testing.T) {
	t.Parallel()

	receiverPrivate := key.NewNode()
	overlayPrivate := key.NewNode()
	send := &Send{
		Logger:    slog.Default(),
		SessionID: "session-a",
		Auth: ClientAuth{
			OverlayPrivateKey: overlayPrivate,
			ReceiverPublicKey: receiverPrivate.Public(),
		},
		in: make(chan PeerUpdate, 1),
	}
	legacyResponse := []byte(`{"Typ":4,"Node":{},"WebrtcDescription":{"type":"answer","sdp":"legacy"}}`)
	sealed := receiverPrivate.SealTo(overlayPrivate.Public(), legacyResponse)
	if _, err := send.handleNextMessage(sealed); err != nil {
		t.Fatalf("handle legacy hello response: %v", err)
	}
	if len(send.in) != 1 {
		t.Fatalf("received node count = %d, want 1", len(send.in))
	}
}

func TestSendRejectsResponseForAnotherSession(t *testing.T) {
	t.Parallel()

	receiverPrivate := key.NewNode()
	overlayPrivate := key.NewNode()
	send := &Send{
		Logger:    slog.Default(),
		SessionID: "session-a",
		Auth: ClientAuth{
			OverlayPrivateKey: overlayPrivate,
			ReceiverPublicKey: receiverPrivate.Public(),
		},
	}
	raw, err := json.Marshal(overlayMessage{Typ: messageTypePong, SessionID: "session-b"})
	if err != nil {
		t.Fatal(err)
	}
	sealed := receiverPrivate.SealTo(overlayPrivate.Public(), raw)
	if _, err := send.handleNextMessage(sealed); err == nil || !strings.Contains(err.Error(), "another session") {
		t.Fatalf("handleNextMessage() error = %v, want another session", err)
	}
}

func TestReceiveRejectsMalformedOverlayMessage(t *testing.T) {
	t.Parallel()

	receive := &Receive{
		SelfPriv: key.NewNode(),
		PeerPriv: key.NewNode(),
	}
	sealed := receive.PeerPriv.SealTo(receive.SelfPriv.Public(), []byte("{"))
	if _, err := receive.handleNextMessage(testPeerSource(10001), sealed, "test"); err == nil {
		t.Fatal("handleNextMessage() succeeded for malformed JSON")
	}
}

func TestReceiveTracksMultipleActivePeersAndGoodbye(t *testing.T) {
	t.Parallel()

	receive := newTestReceive()
	for i, sessionID := range []string{"session-a", "session-b"} {
		hello := sealReceiveMessage(t, receive, overlayMessage{Typ: messageTypeHello, SessionID: sessionID})
		if _, err := receive.handleNextMessage(testPeerSource(10001+i), hello, "test"); err != nil {
			t.Fatalf("accept %s: %v", sessionID, err)
		}
		node := tailcfg.Node{ID: tailcfg.NodeID(i + 1), Key: key.NewNode().Public()}
		update := sealReceiveMessage(t, receive, overlayMessage{
			Typ:       messageTypeNodeUpdate,
			SessionID: sessionID,
			Node:      node,
		})
		if _, err := receive.handleNextMessage(testPeerSource(10001+i), update, "test"); err != nil {
			t.Fatalf("update from %s: %v", sessionID, err)
		}
	}
	if got := len(receive.peers); got != 2 {
		t.Fatalf("active peer count = %d, want 2", got)
	}
	if got := len(receive.in); got != 2 {
		t.Fatalf("received update count = %d, want 2", got)
	}

	goodbye := sealReceiveMessage(t, receive, overlayMessage{
		Typ:       messageTypeGoodbye,
		SessionID: "session-a",
	})
	if _, err := receive.handleNextMessage(testPeerSource(10001), goodbye, "test"); err != nil {
		t.Fatalf("goodbye: %v", err)
	}
	if got := len(receive.peers); got != 1 {
		t.Fatalf("active peer count after goodbye = %d, want 1", got)
	}
	var removal PeerUpdate
	for len(receive.in) > 0 {
		removal = <-receive.in
	}
	if removal.ID != "session-a" || removal.Node != nil {
		t.Fatalf("removal = %#v, want nil update for session-a", removal)
	}
}

func TestReceiveRequiresHelloBeforeNodeUpdate(t *testing.T) {
	t.Parallel()

	receive := newTestReceive()
	update := sealReceiveMessage(t, receive, overlayMessage{
		Typ:       messageTypeNodeUpdate,
		SessionID: "session-a",
		Node:      tailcfg.Node{ID: 1, Key: key.NewNode().Public()},
	})
	if _, err := receive.handleNextMessage(testPeerSource(10001), update, "test"); err == nil || !strings.Contains(err.Error(), "must be hello") {
		t.Fatalf("first update error = %v, want hello requirement", err)
	}
	if len(receive.in) != 0 {
		t.Fatalf("received node count = %d, want 0", len(receive.in))
	}
}

func TestReceiveTracksSessionAcrossAddressChange(t *testing.T) {
	t.Parallel()

	receive := newTestReceive()
	hello := sealReceiveMessage(t, receive, overlayMessage{
		Typ:       messageTypeHello,
		SessionID: "session-a",
	})
	if _, err := receive.handleNextMessage(testPeerSource(10001), hello, "test"); err != nil {
		t.Fatal(err)
	}
	ping := sealReceiveMessage(t, receive, overlayMessage{
		Typ:       messageTypePing,
		SessionID: "session-a",
	})
	if _, err := receive.handleNextMessage(testPeerSource(10002), ping, "test"); err != nil {
		t.Fatal(err)
	}
	peers := receive.stunPeers()
	if len(peers) != 1 || peers[0].addr.Port() != 10002 {
		t.Fatalf("STUN peers = %#v, want session on updated port 10002", peers)
	}
}

func TestReceiveExpiresInactivePeers(t *testing.T) {
	t.Parallel()

	receive := newTestReceive()
	now := time.Now()
	receive.peers["expired"] = receivePeer{lastSeen: now.Add(-peerInactiveTimeout)}
	receive.peers["active"] = receivePeer{lastSeen: now}
	receive.expirePeers(now)

	if _, ok := receive.peers["expired"]; ok {
		t.Fatal("expired peer remains active")
	}
	if _, ok := receive.peers["active"]; !ok {
		t.Fatal("active peer was removed")
	}
	update := <-receive.in
	if update.ID != "expired" || update.Node != nil {
		t.Fatalf("expiry update = %#v, want removal for expired", update)
	}
}

func newTestReceive() *Receive {
	return &Receive{
		Logger:    slog.Default(),
		HumanLogf: func(string, ...any) {},
		SelfPriv:  key.NewNode(),
		PeerPriv:  key.NewNode(),
		peers:     make(map[string]receivePeer),
		in:        make(chan PeerUpdate, 8),
	}
}

func testPeerSource(port int) peerSource {
	return peerSource{
		transport: peerTransportSTUN,
		stunAddr:  netip.MustParseAddrPort("127.0.0.1:" + fmt.Sprint(port)),
	}
}

func sealReceiveMessage(t *testing.T, receive *Receive, msg overlayMessage) []byte {
	t.Helper()
	raw, err := json.Marshal(msg)
	if err != nil {
		t.Fatal(err)
	}
	return receive.PeerPriv.SealTo(receive.SelfPriv.Public(), raw)
}
