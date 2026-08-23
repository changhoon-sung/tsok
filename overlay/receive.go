//go:build !js
// +build !js

package overlay

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"tailscale.com/derp"
	"tailscale.com/derp/derphttp"
	"tailscale.com/net/netcheck"
	"tailscale.com/net/netmon"
	"tailscale.com/net/portmapper"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/util/eventbus"

	"github.com/changhoon-sung/tsok/cliui"
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

type peerSource struct {
	derpKey key.NodePublic
}

type receivePeer struct {
	source   peerSource
	lastSeen time.Time
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

	// derpRegionID is the DERP region used for overlay communication.
	derpRegionID uint16

	lastNode atomic.Pointer[tailcfg.Node]
	peerMu   sync.Mutex
	peers    map[string]receivePeer
	reapOnce sync.Once

	handlerMu            sync.RWMutex
	openUDPHandler       func(sessionID string, port uint16) error
	sessionClosedHandler func(sessionID string)
	// in funnels node updates from other peers to us
	in chan PeerUpdate
	// out fans out our node updates to peers
	out chan *overlayMessage
}

func (r *Receive) SetOpenUDPHandler(handler func(sessionID string, port uint16) error) {
	r.handlerMu.Lock()
	r.openUDPHandler = handler
	r.handlerMu.Unlock()
}

func (r *Receive) SetSessionClosedHandler(handler func(sessionID string)) {
	r.handlerMu.Lock()
	r.sessionClosedHandler = handler
	r.handlerMu.Unlock()
}

func (r *Receive) notifySessionClosed(sessionID string) {
	r.handlerMu.RLock()
	handler := r.sessionClosedHandler
	r.handlerMu.RUnlock()
	if handler != nil {
		handler(sessionID)
	}
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
		r.HumanLogf("Failed to determine overlay DERP region, defaulting to %s.", cliui.Code("NYC"))
		r.derpRegionID = 1
	} else {
		r.HumanLogf("Picked DERP region %s as overlay home", cliui.Code(r.DerpMap.Regions[report.PreferredDERP].RegionName))
		r.derpRegionID = uint16(report.PreferredDERP)
	}

	return nil
}

func (r *Receive) ClientAuth() *ClientAuth {
	return &ClientAuth{
		OverlayPrivateKey:    r.PeerPriv,
		ReceiverPublicKey:    r.SelfPriv.Public(),
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
				derpKey: msg.Source,
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
		r.notifySessionClosed(ovMsg.SessionID)
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

		r.HumanLogf("Received connection request over %s from %s", system, cliui.Keyword(fmt.Sprintf("%s@%s", username, hostname)))
	case messageTypeNodeUpdate:
		r.Logger.Debug("received updated node", slog.String("node_key", ovMsg.Node.Key.String()))
		r.in <- PeerUpdate{ID: ovMsg.SessionID, Node: ovMsg.Node.Clone()}
		res.Typ = messageTypeNodeUpdate
		if lastNode := r.lastNode.Load(); lastNode != nil {
			res.Node = *lastNode
		}
	case messageTypeOpenUDP:
		res.Typ = messageTypeOpenUDPResponse
		res.RequestID = ovMsg.RequestID
		res.UDPPort = ovMsg.UDPPort
		if ovMsg.RequestID == "" {
			res.Error = "UDP request has no request ID"
			break
		}
		if ovMsg.UDPPort == 0 {
			res.Error = "UDP port cannot be zero"
			break
		}
		r.handlerMu.RLock()
		handler := r.openUDPHandler
		r.handlerMu.RUnlock()
		if handler == nil {
			res.Error = "UDP forwarding is disabled"
			break
		}
		if err := handler(ovMsg.SessionID, ovMsg.UDPPort); err != nil {
			res.Error = err.Error()
		}
	default:
		return nil, fmt.Errorf("unsupported overlay message type %d", ovMsg.Typ)

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
	if source.derpKey.IsZero() {
		return false, errors.New("overlay DERP peer key is empty")
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

func (r *Receive) derpPeers() []derpPeer {
	r.peerMu.Lock()
	defer r.peerMu.Unlock()
	peers := make([]derpPeer, 0, len(r.peers))
	for sessionID, peer := range r.peers {
		peers = append(peers, derpPeer{sessionID: sessionID, key: peer.source.derpKey})
	}
	return peers
}

func (r *Receive) removeDERPPeers(peerKey key.NodePublic) {
	var removed []string
	r.peerMu.Lock()
	for sessionID, peer := range r.peers {
		if peer.source.derpKey == peerKey {
			delete(r.peers, sessionID)
			r.in <- PeerUpdate{ID: sessionID}
			removed = append(removed, sessionID)
		}
	}
	r.peerMu.Unlock()
	for _, sessionID := range removed {
		r.notifySessionClosed(sessionID)
	}
}

func (r *Receive) expirePeers(now time.Time) {
	cutoff := now.Add(-peerInactiveTimeout)
	var removed []string
	r.peerMu.Lock()
	for sessionID, peer := range r.peers {
		if !peer.lastSeen.After(cutoff) {
			delete(r.peers, sessionID)
			r.in <- PeerUpdate{ID: sessionID}
			removed = append(removed, sessionID)
		}
	}
	r.peerMu.Unlock()
	for _, sessionID := range removed {
		r.notifySessionClosed(sessionID)
	}
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
