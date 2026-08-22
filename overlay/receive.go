//go:build !js
// +build !js

package overlay

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/stun/v3"
	"tailscale.com/derp"
	"tailscale.com/derp/derphttp"
	"tailscale.com/net/netcheck"
	"tailscale.com/net/netmon"
	"tailscale.com/net/portmapper"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/util/eventbus"

	"github.com/coder/pretty"
	"github.com/coder/wush/cliui"
)

func NewReceiveOverlay(logger *slog.Logger, hlog Logf, dm *tailcfg.DERPMap) *Receive {
	return &Receive{
		Logger:    logger,
		HumanLogf: hlog,
		DerpMap:   dm,
		SelfPriv:  key.NewNode(),
		PeerPriv:  key.NewNode(),
		peers:     make(map[string]receivePeer),
		in:        make(chan PeerUpdate, 8),
		out:       make(chan *overlayMessage, 8),
	}
}

const (
	peerKeepAliveInterval = 30 * time.Second
	peerInactiveTimeout   = 2 * time.Minute
)

type peerTransport uint8

const (
	peerTransportSTUN peerTransport = iota + 1
	peerTransportDERP
)

type peerSource struct {
	transport peerTransport
	stunAddr  netip.AddrPort
	derpKey   key.NodePublic
}

type receivePeer struct {
	source   peerSource
	lastSeen time.Time
}

type stunPeer struct {
	sessionID string
	addr      netip.AddrPort
}

type derpPeer struct {
	sessionID string
	key       key.NodePublic
}

type Receive struct {
	Logger    *slog.Logger
	HumanLogf Logf
	DerpMap   *tailcfg.DERPMap
	// SelfPriv is the private key that peers will encrypt overlay messages to.
	// The public key of this is sent in the auth key.
	SelfPriv key.NodePrivate
	// PeerPriv is the main auth mechanism used to secure the overlay. Peers are
	// sent this private key to encrypt node communication. Leaking this private
	// key would allow anyone to connect.
	PeerPriv key.NodePrivate

	// stunIP is the STUN address that can be used for P2P overlay
	// communication.
	stunIP netip.AddrPort
	// derpRegionID is the DERP region that can be used for proxied overlay
	// communication.
	derpRegionID uint16

	lastNode atomic.Pointer[tailcfg.Node]
	peerMu   sync.Mutex
	peers    map[string]receivePeer
	reapOnce sync.Once
	// in funnels node updates from other peers to us
	in chan PeerUpdate
	// out fans out our node updates to peers
	out chan *overlayMessage
}

func (r *Receive) IPs() []netip.Addr {
	i6 := [16]byte{0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0}
	i6[15] = 0x01
	return []netip.Addr{
		// netip.AddrFrom4([4]byte{100, 64, 0, 0}),
		netip.AddrFrom16(i6),
	}
}

func (r *Receive) PickDERPHome(ctx context.Context) error {
	nm := netmon.NewStatic()
	bus := eventbus.New()
	defer bus.Close()
	pm := portmapper.NewClient(portmapper.Config{
		EventBus: bus,
		Logf:     func(format string, args ...any) {},
		NetMon:   nm,
	})
	defer pm.Close()
	nc := netcheck.Client{
		NetMon:     nm,
		PortMapper: pm,
		Logf:       func(format string, args ...any) {},
	}

	report, err := nc.GetReport(ctx, r.DerpMap, nil)
	if err != nil {
		return err
	}

	if report.PreferredDERP == 0 {
		r.HumanLogf("Failed to determine overlay DERP region, defaulting to NYC.")
		r.derpRegionID = 1
	} else {
		r.HumanLogf("Picked DERP region %s as overlay home", r.DerpMap.Regions[report.PreferredDERP].RegionName)
		r.derpRegionID = uint16(report.PreferredDERP)
	}

	return nil
}

func (r *Receive) ClientAuth() *ClientAuth {
	return &ClientAuth{
		OverlayPrivateKey:    r.PeerPriv,
		ReceiverPublicKey:    r.SelfPriv.Public(),
		ReceiverStunAddr:     r.stunIP,
		ReceiverDERPRegionID: r.derpRegionID,
	}
}

func (r *Receive) Recv() <-chan PeerUpdate {
	return r.in
}

func (r *Receive) SendTailscaleNodeUpdate(node *tailcfg.Node) {
	r.out <- &overlayMessage{
		Typ:  messageTypeNodeUpdate,
		Node: *node.Clone(),
	}
}

func (r *Receive) ListenOverlaySTUN(ctx context.Context) (<-chan struct{}, error) {
	srvAddr, err := net.ResolveUDPAddr("udp4", "stun.l.google.com:19302")
	if err != nil {
		return nil, fmt.Errorf("resolve google STUN: %w", err)
	}

	conn, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return nil, fmt.Errorf("listen STUN: %w", err)
	}
	r.startPeerReaper(ctx)

	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()

	m := stun.MustBuild(stun.TransactionID, stun.BindingRequest)

	restun := time.NewTicker(time.Nanosecond)

	go func() {
		defer restun.Stop()
		for {
			select {
			case <-ctx.Done():
				return

			case <-restun.C:
				if _, writeErr := conn.WriteToUDP(m.Raw, srvAddr); writeErr != nil {
					r.HumanLogf("Failed to write STUN request on overlay: %s", writeErr)
				}
				restun.Reset(30 * time.Second)
			}
		}
	}()

	go func() {
		for {

			select {
			case <-ctx.Done():
				return
			case msg := <-r.out:
				if msg.Typ == messageTypeNodeUpdate {
					r.lastNode.Store(&msg.Node)
				}
				for _, peer := range r.stunPeers() {
					peerMsg := *msg
					peerMsg.SessionID = peer.sessionID
					raw, err := json.Marshal(peerMsg)
					if err != nil {
						panic("marshal overlay msg: " + err.Error())
					}
					sealed := r.SelfPriv.SealTo(r.PeerPriv.Public(), raw)
					if _, writeErr := conn.WriteToUDPAddrPort(sealed, peer.addr); writeErr != nil {
						r.HumanLogf("Failed to send updated node over udp: %s", writeErr)
					}
				}
			}
		}
	}()

	ipChan := make(chan struct{})

	go func() {
		var closeIPChanOnce sync.Once

		for {
			buf := make([]byte, 4<<10)
			n, addr, err := conn.ReadFromUDPAddrPort(buf)
			if err != nil {
				r.Logger.Error("read from STUN; exiting", "err", err)
				return
			}

			buf = buf[:n]
			if stun.IsMessage(buf) {
				m := new(stun.Message)
				m.Raw = buf

				if err := m.Decode(); err != nil {
					r.Logger.Error("decode STUN message; exiting", "err", err)
					return
				}

				var xorAddr stun.XORMappedAddress
				if err := xorAddr.GetFrom(m); err != nil {
					r.Logger.Error("decode STUN xor mapped addr; exiting", "err", err)
					return
				}

				stunAddr, ok := netip.AddrFromSlice(xorAddr.IP)
				if !ok {
					r.Logger.Error("convert STUN xor mapped addr", "ip", xorAddr.IP.String())
					continue
				}
				stunAddrPort := netip.AddrPortFrom(stunAddr, uint16(xorAddr.Port))

				// our first STUN response
				if !r.stunIP.IsValid() {
					r.HumanLogf("STUN address is %s", stunAddrPort.String())
				}

				if r.stunIP.IsValid() && r.stunIP.Compare(stunAddrPort) != 0 {
					r.HumanLogf(pretty.Sprintf(cliui.DefaultStyles.Warn, "STUN address changed, this may cause issues; %s->%s", r.stunIP.String(), stunAddrPort.String()))
				}
				r.stunIP = stunAddrPort
				closeIPChanOnce.Do(func() {
					close(ipChan)
				})
				continue
			}

			res, err := r.handleNextMessage(peerSource{
				transport: peerTransportSTUN,
				stunAddr:  addr,
			}, buf, "STUN")
			if err != nil {
				r.HumanLogf("Failed to handle overlay message: %s", err.Error())
				continue
			}

			if res != nil {
				if _, writeErr := conn.WriteToUDPAddrPort(res, addr); writeErr != nil {
					r.HumanLogf("Failed to send overlay response over STUN: %s", writeErr.Error())
					return
				}
			}
		}
	}()
	return ipChan, nil
}

func (r *Receive) ListenOverlayDERP(ctx context.Context) error {
	c := derphttp.NewRegionClient(r.SelfPriv, func(format string, args ...any) {}, netmon.NewStatic(), func() *tailcfg.DERPRegion {
		return r.DerpMap.Regions[int(r.derpRegionID)]
	})

	err := c.Connect(ctx)
	if err != nil {
		return err
	}
	r.startPeerReaper(ctx)

	go func() {
		for {

			select {
			case <-ctx.Done():
				return
			case msg := <-r.out:
				if msg.Typ == messageTypeNodeUpdate {
					r.lastNode.Store(&msg.Node)
				}
				for _, peer := range r.derpPeers() {
					peerMsg := *msg
					peerMsg.SessionID = peer.sessionID
					raw, err := json.Marshal(peerMsg)
					if err != nil {
						panic("marshal overlay msg: " + err.Error())
					}
					sealed := r.SelfPriv.SealTo(r.PeerPriv.Public(), raw)
					if sendErr := c.Send(peer.key, sealed); sendErr != nil {
						r.HumanLogf("Send updated node over DERP: %s", sendErr)
					}
				}
			}
		}
	}()

	for {
		msg, err := c.Recv()
		if err != nil {
			return err
		}

		switch msg := msg.(type) {
		case derp.ReceivedPacket:
			res, err := r.handleNextMessage(peerSource{
				transport: peerTransportDERP,
				derpKey:   msg.Source,
			}, msg.Data, "DERP")
			if err != nil {
				r.HumanLogf("Failed to handle overlay message from %s: %s", msg.Source.ShortString(), err.Error())
				continue
			}

			if res != nil {
				err = c.Send(msg.Source, res)
				if err != nil {
					r.HumanLogf("Failed to send overlay response over derp: %s", err.Error())
					return err
				}
			}
		case derp.PeerGoneMessage:
			r.removeDERPPeers(msg.Peer)
		}
	}
}

func (r *Receive) handleNextMessage(source peerSource, msg []byte, system string) ([]byte, error) {
	cleartext, ok := r.SelfPriv.OpenFrom(r.PeerPriv.Public(), msg)
	if !ok {
		return nil, errors.New("message failed decryption")
	}

	var ovMsg overlayMessage
	err := json.Unmarshal(cleartext, &ovMsg)
	if err != nil {
		return nil, fmt.Errorf("unmarshal overlay message: %w", err)
	}
	removed, err := r.trackPeer(ovMsg.SessionID, source, ovMsg.Typ, time.Now())
	if err != nil {
		return nil, err
	}
	if removed {
		return nil, nil
	}

	res := overlayMessage{SessionID: ovMsg.SessionID}
	switch ovMsg.Typ {
	case messageTypePing:
		res.Typ = messageTypePong
	case messageTypePong:
		// do nothing
	case messageTypeHello:
		res.Typ = messageTypeHelloResponse
		username := "unknown"
		if u := ovMsg.HostInfo.Username; u != "" {
			username = u
		}
		hostname := "unknown"
		if h := ovMsg.HostInfo.Hostname; h != "" {
			hostname = h
		}
		if lastNode := r.lastNode.Load(); lastNode != nil {
			res.Node = *lastNode
		}

		r.HumanLogf("Received connection request over %s from %s", system, fmt.Sprintf("%s@%s", username, hostname))
	case messageTypeNodeUpdate:
		r.Logger.Debug("received updated node", slog.String("node_key", ovMsg.Node.Key.String()))
		r.in <- PeerUpdate{ID: ovMsg.SessionID, Node: ovMsg.Node.Clone()}
		res.Typ = messageTypeNodeUpdate
		if lastNode := r.lastNode.Load(); lastNode != nil {
			res.Node = *lastNode
		}

	}

	if res.Typ == 0 {
		return nil, nil
	}

	raw, err := json.Marshal(res)
	if err != nil {
		panic("marshal node: " + err.Error())
	}

	sealed := r.SelfPriv.SealTo(r.PeerPriv.Public(), raw)
	return sealed, nil
}

func (r *Receive) trackPeer(sessionID string, source peerSource, typ messageType, now time.Time) (bool, error) {
	if sessionID == "" {
		return false, errors.New("overlay session ID is empty")
	}
	switch source.transport {
	case peerTransportSTUN:
		if !source.stunAddr.IsValid() {
			return false, errors.New("overlay STUN peer address is invalid")
		}
	case peerTransportDERP:
		if source.derpKey.IsZero() {
			return false, errors.New("overlay DERP peer key is empty")
		}
	default:
		return false, errors.New("overlay peer transport is invalid")
	}
	r.peerMu.Lock()
	if r.peers == nil {
		r.peers = make(map[string]receivePeer)
	}
	_, exists := r.peers[sessionID]
	if typ == messageTypeGoodbye {
		if exists {
			delete(r.peers, sessionID)
			r.in <- PeerUpdate{ID: sessionID}
		}
		r.peerMu.Unlock()
		return true, nil
	}
	if !exists {
		if typ != messageTypeHello {
			r.peerMu.Unlock()
			return false, errors.New("first overlay message must be hello")
		}
	}
	r.peers[sessionID] = receivePeer{source: source, lastSeen: now}
	r.peerMu.Unlock()
	return false, nil
}

func (r *Receive) stunPeers() []stunPeer {
	r.peerMu.Lock()
	defer r.peerMu.Unlock()
	peers := make([]stunPeer, 0, len(r.peers))
	for sessionID, peer := range r.peers {
		if peer.source.transport == peerTransportSTUN {
			peers = append(peers, stunPeer{sessionID: sessionID, addr: peer.source.stunAddr})
		}
	}
	return peers
}

func (r *Receive) derpPeers() []derpPeer {
	r.peerMu.Lock()
	defer r.peerMu.Unlock()
	peers := make([]derpPeer, 0, len(r.peers))
	for sessionID, peer := range r.peers {
		if peer.source.transport == peerTransportDERP {
			peers = append(peers, derpPeer{sessionID: sessionID, key: peer.source.derpKey})
		}
	}
	return peers
}

func (r *Receive) removeDERPPeers(peerKey key.NodePublic) {
	r.peerMu.Lock()
	for sessionID, peer := range r.peers {
		if peer.source.transport == peerTransportDERP && peer.source.derpKey == peerKey {
			delete(r.peers, sessionID)
			r.in <- PeerUpdate{ID: sessionID}
		}
	}
	r.peerMu.Unlock()
}

func (r *Receive) expirePeers(now time.Time) {
	cutoff := now.Add(-peerInactiveTimeout)
	r.peerMu.Lock()
	for sessionID, peer := range r.peers {
		if !peer.lastSeen.After(cutoff) {
			delete(r.peers, sessionID)
			r.in <- PeerUpdate{ID: sessionID}
		}
	}
	r.peerMu.Unlock()
}

func (r *Receive) startPeerReaper(ctx context.Context) {
	r.reapOnce.Do(func() {
		go func() {
			ticker := time.NewTicker(peerKeepAliveInterval)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case now := <-ticker.C:
					r.expirePeers(now)
				}
			}
		}()
	})
}
