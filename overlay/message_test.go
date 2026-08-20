package overlay

import (
	"log/slog"
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
	if _, _, err := receive.handleNextMessage(key.NodePublic{}, sealed, "test"); err == nil {
		t.Fatal("handleNextMessage() succeeded for malformed JSON")
	}
}
