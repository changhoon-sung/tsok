package overlay

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/btcsuite/btcd/btcutil/base58"
	"github.com/changhoon-sung/tsok/cliui"
	"go4.org/mem"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

type ClientAuth struct {
	// OverlayPrivateKey is the main auth mechanism used to secure the overlay.
	// Peers are sent this private key to encrypt node communication to the
	// receiver. Leaking this private key would allow anyone to connect.
	OverlayPrivateKey key.NodePrivate
	// ReceiverPublicKey is the public key of the receiver. Node messages are
	// encrypted to this public key.
	ReceiverPublicKey key.NodePublic
	// ReceiverDERPRegionID is the region id that the receiver is reachable over
	// DERP.
	ReceiverDERPRegionID uint16
}

const (
	authKeyVersionLegacy = 1
	authKeyVersion       = 2
	authKeyPeerTypeCLI   = 0
	authKeyPeerTypeWeb   = 1
)

func (ca *ClientAuth) PrintDebug(logf func(str string, args ...any), dm *tailcfg.DERPMap) {
	logf("Auth information:")
	derpStr := "Disabled"
	if ca.ReceiverDERPRegionID > 0 {
		region := dm.Regions[int(ca.ReceiverDERPRegionID)]
		if region == nil {
			derpStr = fmt.Sprintf("Unknown (%d)", ca.ReceiverDERPRegionID)
		} else {
			derpStr = region.RegionName
		}
	}
	logf("\t> Server overlay DERP home:    %s", cliui.Code(derpStr))
	logf("\t> Server overlay public key:   %s", cliui.Code(ca.ReceiverPublicKey.ShortString()))
	logf("\t> Server overlay auth key:     %s", cliui.Code(ca.OverlayPrivateKey.Public().ShortString()))
}

func (ca *ClientAuth) AuthKey() string {
	buf := bytes.NewBuffer(nil)

	buf.WriteByte(authKeyVersion)
	// Keep the peer-type byte so v1 CLI auth keys remain parseable. Browser
	// peers used value 1 and are no longer supported.
	buf.WriteByte(authKeyPeerTypeCLI)

	// Keep the legacy STUN address-length byte in the wire format so DERP-based
	// v1 and v2 auth keys remain compatible. New keys always encode no address.
	buf.WriteByte(0)

	derpBuf := [2]byte{}
	binary.BigEndian.PutUint16(derpBuf[:], ca.ReceiverDERPRegionID)
	buf.Write(derpBuf[:])

	pub := ca.ReceiverPublicKey.Raw32()
	buf.Write(pub[:])

	priv := ca.OverlayPrivateKey.Raw32()
	buf.Write(priv[:])

	return base58.Encode(buf.Bytes())
}

func (ca *ClientAuth) Parse(authKey string) error {
	if len(authKey) == 0 {
		return errors.New("auth key should not be empty")
	}

	decoded := base58.Decode(authKey)
	if len(decoded) == 0 {
		return errors.New("decode auth key")
	}
	decr := bytes.NewReader(decoded)

	ver, err := decr.ReadByte()
	if err != nil {
		return errors.New("read authkey version")
	}

	if ver != authKeyVersionLegacy && ver != authKeyVersion {
		return fmt.Errorf("unsupported authkey version %q", ver)
	}

	typ, err := decr.ReadByte()
	if err != nil {
		return errors.New("read authkey peer type")
	}

	if typ != authKeyPeerTypeCLI {
		if typ == authKeyPeerTypeWeb {
			return errors.New("browser auth keys are not supported by this CLI-only build")
		}
		return fmt.Errorf("unsupported authkey peer type %q", typ)
	}

	parsed := ClientAuth{}

	ipLenB, err := decr.ReadByte()
	if err != nil {
		return errors.New("read STUN ip len; invalid authkey")
	}

	ipLen := int(ipLenB)
	if ipLen > 0 {
		return errors.New("STUN overlay auth keys are not supported")
	}

	derpRegionBytes := make([]byte, 2)
	n, err := decr.Read(derpRegionBytes)
	if n != len(derpRegionBytes) || err != nil {
		return errors.New("read derp region; invalid authkey")
	}
	parsed.ReceiverDERPRegionID = binary.BigEndian.Uint16(derpRegionBytes)
	if parsed.ReceiverDERPRegionID == 0 {
		return errors.New("auth key does not specify a DERP region")
	}

	pubKeyBytes := make([]byte, 32)
	n, err = io.ReadFull(decr, pubKeyBytes)
	if n != len(pubKeyBytes) || err != nil {
		return errors.New("read receiver pubkey; invalid authkey")
	}
	parsed.ReceiverPublicKey = key.NodePublicFromRaw32(mem.B(pubKeyBytes))
	if parsed.ReceiverPublicKey.IsZero() {
		return errors.New("receiver public key is zero; invalid authkey")
	}

	privKeyBytes := make([]byte, 32)
	n, err = io.ReadFull(decr, privKeyBytes)
	if n != len(privKeyBytes) || err != nil {
		return errors.New("read overlay privkey; invalid authkey")
	}
	parsed.OverlayPrivateKey = key.NodePrivateFromRaw32(mem.B(privKeyBytes))
	if parsed.OverlayPrivateKey.IsZero() {
		return errors.New("overlay private key is zero; invalid authkey")
	}

	if decr.Len() != 0 {
		return errors.New("auth key has trailing data")
	}

	*ca = parsed
	return nil
}
