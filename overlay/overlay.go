package overlay

import (
	"net/netip"

	"github.com/google/uuid"
	"tailscale.com/tailcfg"
)

type Logf func(format string, args ...any)

// Overlay specifies the mechanism by which senders and receivers exchange
// Tailscale nodes over a sidechannel.
type Overlay interface {
	// listenOverlay(ctx context.Context, kind string) error
	Recv() <-chan PeerUpdate
	SendTailscaleNodeUpdate(node *tailcfg.Node)
	IPs() []netip.Addr
}

// PeerUpdate adds or updates an active overlay peer. A nil Node removes it.
// ID is scoped to the lifetime of the overlay process that emitted the update.
type PeerUpdate struct {
	ID   string
	Node *tailcfg.Node
}

type messageType int

const (
	messageTypePing messageType = 1 + iota
	messageTypePong
	messageTypeHello
	messageTypeHelloResponse
	messageTypeNodeUpdate
	messageTypeGoodbye
)

type overlayMessage struct {
	Typ       messageType
	SessionID string

	HostInfo HostInfo
	Node     tailcfg.Node
}

type HostInfo struct {
	Username string
	Hostname string
}

var TailscaleServicePrefix6 = [6]byte{0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0}

func randv6() netip.Addr {
	uid := uuid.New()
	copy(uid[:], TailscaleServicePrefix6[:])
	return netip.AddrFrom16(uid)
}
