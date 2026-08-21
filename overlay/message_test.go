package overlay

import (
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func TestSendRejectsMalformedOverlayMessage(t *testing.T) {
	t.Parallel()

	receiverPrivate := key.NewNode()
	overlayPrivate := key.NewNode()
	send := &Send{
		Logger: slog.Default(),
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

func TestSendIgnoresLegacyWebRTCResponseField(t *testing.T) {
	t.Parallel()

	receiverPrivate := key.NewNode()
	overlayPrivate := key.NewNode()
	send := &Send{
		Logger: slog.Default(),
		Auth: ClientAuth{
			OverlayPrivateKey: overlayPrivate,
			ReceiverPublicKey: receiverPrivate.Public(),
		},
		in: make(chan *tailcfg.Node, 1),
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

func TestReceiveRejectsMalformedOverlayMessage(t *testing.T) {
	t.Parallel()

	receive := &Receive{
		SelfPriv: key.NewNode(),
		PeerPriv: key.NewNode(),
	}
	sealed := receive.PeerPriv.SealTo(receive.SelfPriv.Public(), []byte("{"))
	if _, err := receive.handleNextMessage("peer-a", sealed, "test"); err == nil {
		t.Fatal("handleNextMessage() succeeded for malformed JSON")
	}
}

func TestReceiveAcceptsOnlyOneOverlayPeer(t *testing.T) {
	t.Parallel()

	receive := &Receive{
		Logger:    slog.Default(),
		HumanLogf: func(string, ...any) {},
		SelfPriv:  key.NewNode(),
		PeerPriv:  key.NewNode(),
		in:        make(chan *tailcfg.Node, 1),
	}
	hello := sealReceiveMessage(t, receive, overlayMessage{Typ: messageTypeHello})
	if _, err := receive.handleNextMessage("peer-a", hello, "test"); err != nil {
		t.Fatalf("accept first peer: %v", err)
	}
	if _, err := receive.handleNextMessage("peer-b", hello, "test"); err == nil || !strings.Contains(err.Error(), "already connected") {
		t.Fatalf("second peer error = %v, want already connected", err)
	}

	node := tailcfg.Node{ID: 1, Key: key.NewNode().Public()}
	update := sealReceiveMessage(t, receive, overlayMessage{Typ: messageTypeNodeUpdate, Node: node})
	if _, err := receive.handleNextMessage("peer-a", update, "test"); err != nil {
		t.Fatalf("update from first peer: %v", err)
	}
	if len(receive.in) != 1 {
		t.Fatalf("received node count = %d, want 1", len(receive.in))
	}
}

func TestReceiveRequiresHelloBeforeNodeUpdate(t *testing.T) {
	t.Parallel()

	receive := &Receive{
		Logger:    slog.Default(),
		HumanLogf: func(string, ...any) {},
		SelfPriv:  key.NewNode(),
		PeerPriv:  key.NewNode(),
		in:        make(chan *tailcfg.Node, 1),
	}
	update := sealReceiveMessage(t, receive, overlayMessage{
		Typ:  messageTypeNodeUpdate,
		Node: tailcfg.Node{ID: 1, Key: key.NewNode().Public()},
	})
	if _, err := receive.handleNextMessage("peer-a", update, "test"); err == nil || !strings.Contains(err.Error(), "must be hello") {
		t.Fatalf("first update error = %v, want hello requirement", err)
	}
	if len(receive.in) != 0 {
		t.Fatalf("received node count = %d, want 0", len(receive.in))
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
