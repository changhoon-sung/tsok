package overlay

import (
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcutil/base58"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func TestClientAuthRoundTrip(t *testing.T) {
	t.Parallel()

	for _, stunAddr := range []netip.AddrPort{
		{},
		netip.MustParseAddrPort("192.0.2.1:12345"),
		netip.MustParseAddrPort("[2001:db8::1]:54321"),
	} {
		stunAddr := stunAddr
		t.Run(stunAddr.String(), func(t *testing.T) {
			t.Parallel()

			receiverPrivate := key.NewNode()
			original := ClientAuth{
				OverlayPrivateKey:    key.NewNode(),
				ReceiverPublicKey:    receiverPrivate.Public(),
				ReceiverStunAddr:     stunAddr,
				ReceiverDERPRegionID: 21,
			}

			encoded := original.AuthKey()
			raw := base58.Decode(encoded)
			if len(raw) < 2 || raw[0] != authKeyVersion || raw[1] != authKeyPeerTypeCLI {
				t.Fatalf("auth key header = %v, want version %d and CLI type %d", raw[:min(len(raw), 2)], authKeyVersion, authKeyPeerTypeCLI)
			}

			var parsed ClientAuth
			if err := parsed.Parse(encoded); err != nil {
				t.Fatalf("parse auth key: %v", err)
			}
			if !reflect.DeepEqual(parsed, original) {
				t.Fatalf("parsed auth = %#v, want %#v", parsed, original)
			}
		})
	}
}

func TestClientAuthParsesLegacyCLIKey(t *testing.T) {
	t.Parallel()

	original := ClientAuth{
		OverlayPrivateKey:    key.NewNode(),
		ReceiverPublicKey:    key.NewNode().Public(),
		ReceiverDERPRegionID: 21,
	}
	raw := base58.Decode(original.AuthKey())
	raw[0] = authKeyVersionLegacy

	var parsed ClientAuth
	if err := parsed.Parse(base58.Encode(raw)); err != nil {
		t.Fatalf("parse legacy auth key: %v", err)
	}
	if !reflect.DeepEqual(parsed, original) {
		t.Fatalf("parsed legacy auth = %#v, want %#v", parsed, original)
	}
}

func TestClientAuthRejectsUnsupportedTypesAndTrailingData(t *testing.T) {
	t.Parallel()

	auth := ClientAuth{
		OverlayPrivateKey:    key.NewNode(),
		ReceiverPublicKey:    key.NewNode().Public(),
		ReceiverDERPRegionID: 1,
	}
	raw := base58.Decode(auth.AuthKey())

	for _, tc := range []struct {
		name string
		edit func([]byte) []byte
		want string
	}{
		{
			name: "unknown version",
			edit: func(raw []byte) []byte {
				raw[0] = authKeyVersion + 1
				return raw
			},
			want: "unsupported authkey version",
		},
		{
			name: "browser",
			edit: func(raw []byte) []byte {
				raw[1] = authKeyPeerTypeWeb
				return raw
			},
			want: "browser auth keys are not supported",
		},
		{
			name: "legacy browser",
			edit: func(raw []byte) []byte {
				raw[0] = authKeyVersionLegacy
				raw[1] = authKeyPeerTypeWeb
				return raw
			},
			want: "browser auth keys are not supported",
		},
		{
			name: "unknown peer type",
			edit: func(raw []byte) []byte {
				raw[1] = 2
				return raw
			},
			want: "unsupported authkey peer type",
		},
		{
			name: "zero receiver key",
			edit: func(raw []byte) []byte {
				clear(raw[5:37])
				return raw
			},
			want: "receiver public key is zero",
		},
		{
			name: "zero overlay key",
			edit: func(raw []byte) []byte {
				clear(raw[37:69])
				return raw
			},
			want: "overlay private key is zero",
		},
		{
			name: "trailing data",
			edit: func(raw []byte) []byte {
				return append(raw, 0)
			},
			want: "trailing data",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			candidate := append([]byte(nil), raw...)
			before := ClientAuth{ReceiverDERPRegionID: 99}
			parsed := before
			err := parsed.Parse(base58.Encode(tc.edit(candidate)))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Parse() error = %v, want containing %q", err, tc.want)
			}
			if !reflect.DeepEqual(parsed, before) {
				t.Fatalf("failed Parse() mutated receiver: got %#v, want %#v", parsed, before)
			}
		})
	}
}

func TestClientAuthRejectsEveryTruncation(t *testing.T) {
	t.Parallel()

	auth := ClientAuth{
		OverlayPrivateKey:    key.NewNode(),
		ReceiverPublicKey:    key.NewNode().Public(),
		ReceiverStunAddr:     netip.MustParseAddrPort("192.0.2.1:12345"),
		ReceiverDERPRegionID: 1,
	}
	raw := base58.Decode(auth.AuthKey())
	for length := 0; length < len(raw); length++ {
		var parsed ClientAuth
		if err := parsed.Parse(base58.Encode(raw[:length])); err == nil {
			t.Fatalf("Parse() succeeded with %d of %d bytes", length, len(raw))
		}
	}
}

func TestClientAuthPrintDebugUnknownDERPRegion(t *testing.T) {
	t.Parallel()

	var output strings.Builder
	auth := ClientAuth{
		OverlayPrivateKey:    key.NewNode(),
		ReceiverPublicKey:    key.NewNode().Public(),
		ReceiverDERPRegionID: 999,
	}
	auth.PrintDebug(func(format string, args ...any) {
		output.WriteString(fmt.Sprintf(format, args...))
	}, &tailcfg.DERPMap{Regions: map[int]*tailcfg.DERPRegion{}})
	if !strings.Contains(output.String(), "Unknown (999)") {
		t.Fatalf("debug output = %q, want unknown DERP region", output.String())
	}
}
