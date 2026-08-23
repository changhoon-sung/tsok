// SPDX-License-Identifier: BSD-3-Clause, CC0-1.0
// Package tsserver implements the Tailscale coordination protocol for a single
// client. Heavy inspiration and code was taken from https://github.com/juanfont/headscale.
// As such, this file is dual licensed under BSD-3-Clause and CC0-1.0.
package tsserver

import (
	"cmp"
	"context"
	cryptorand "crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/klauspost/compress/zstd"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"tailscale.com/control/controlbase"
	"tailscale.com/control/controlhttp/controlhttpserver"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/opt"
	"tailscale.com/types/ptr"

	"github.com/changhoon-sung/tsok/overlay"
)

func DERPMapTailscale(ctx context.Context) (*tailcfg.DERPMap, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://controlplane.tailscale.com/derpmap/default", nil)
	if err != nil {
		return nil, fmt.Errorf("make ts derpmap req: %w", err)
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("get ts derpmap: %w", err)
	}
	defer res.Body.Close()

	dm := &tailcfg.DERPMap{}
	err = json.NewDecoder(res.Body).Decode(dm)
	if err != nil {
		return nil, fmt.Errorf("decode ts derpmap: %w", err)
	}

	return dm, nil
}

func NewServer(ctx context.Context, logger *slog.Logger, ov overlay.Overlay, dm *tailcfg.DERPMap) (*server, error) {
	var secret [32]byte
	if _, err := cryptorand.Read(secret[:]); err != nil {
		return nil, fmt.Errorf("generate control server path: %w", err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("listen for local control connection: %w", err)
	}
	serverCtx, cancel := context.WithCancel(ctx)

	s := &server{
		ctx:             serverCtx,
		cancel:          cancel,
		logger:          logger,
		noisePrivateKey: key.NewMachine(),
		nodeUpdate:      make(chan struct{}, 1),
		listener:        listener,
		controlPath:     "/" + hex.EncodeToString(secret[:]),
		overlay:         ov,
		derpMap:         dm,
		peers:           newPeerStore(),
		peerUpdate:      make(chan struct{}, 1),
	}

	return s, nil
}

type server struct {
	ctx             context.Context
	cancel          context.CancelFunc
	logger          *slog.Logger
	derpMap         *tailcfg.DERPMap
	noisePrivateKey key.MachinePrivate
	listener        net.Listener
	controlPath     string
	httpMu          sync.Mutex
	httpServer      *http.Server
	noiseMu         sync.Mutex
	noiseConn       *controlbase.Conn
	noiseActive     atomic.Bool
	closeOnce       sync.Once
	closeErr        error

	overlay overlay.Overlay

	node       atomic.Pointer[tailcfg.Node]
	nodeUpdate chan struct{}

	peers      *peerStore
	peerUpdate chan struct{}
}

type peerStore struct {
	mu    sync.RWMutex
	nodes map[string]*tailcfg.Node
}

func newPeerStore() *peerStore {
	return &peerStore{nodes: make(map[string]*tailcfg.Node)}
}

func (p *peerStore) apply(update overlay.PeerUpdate) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if update.Node == nil {
		delete(p.nodes, update.ID)
		return
	}
	p.nodes[update.ID] = update.Node.Clone()
}

func (p *peerStore) snapshot() []*tailcfg.Node {
	p.mu.RLock()
	peers := make([]*tailcfg.Node, 0, len(p.nodes))
	for _, node := range p.nodes {
		peers = append(peers, node.Clone())
	}
	p.mu.RUnlock()
	slices.SortFunc(peers, func(a, b *tailcfg.Node) int {
		if idOrder := cmp.Compare(a.ID, b.ID); idOrder != 0 {
			return idOrder
		}
		return strings.Compare(a.Key.String(), b.Key.String())
	})
	return peers
}

func (s *server) ControlURL() string {
	return "http://" + s.listener.Addr().String() + s.controlPath
}

func (s *server) Close() error {
	s.closeOnce.Do(func() {
		s.cancel()
		var closeErrors []error

		s.httpMu.Lock()
		httpServer := s.httpServer
		s.httpMu.Unlock()
		if httpServer != nil {
			if err := httpServer.Close(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				closeErrors = append(closeErrors, err)
			}
		}
		if err := s.listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			closeErrors = append(closeErrors, err)
		}
		s.noiseMu.Lock()
		noiseConn := s.noiseConn
		s.noiseConn = nil
		s.noiseMu.Unlock()
		if noiseConn != nil {
			if err := noiseConn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
				closeErrors = append(closeErrors, err)
			}
		}
		s.closeErr = errors.Join(closeErrors...)
	})
	return s.closeErr
}

func (s *server) ListenAndServe(_ context.Context) error {
	r := chi.NewRouter()
	r.NotFound(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.logger.Info("main handler not found", "path", r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	}))

	r.Get(s.controlPath+"/key", s.KeyHandler)
	// Tailscale preserves the ControlURL path for HTTP requests, but the outer
	// Noise upgrade is always sent to the root /ts2021 endpoint.
	r.Post("/ts2021", s.NoiseUpgradeHandler)

	go func() {
		recv := s.overlay.Recv()
		for {
			select {
			case <-s.ctx.Done():
				return
			case update, ok := <-recv:
				if !ok {
					return
				}
				if update.ID == "" {
					continue
				}
				s.peers.apply(update)
				select {
				case s.peerUpdate <- struct{}{}:
				default:
				}
			case <-s.nodeUpdate:
				if node := s.node.Load(); node != nil {
					s.overlay.SendTailscaleNodeUpdate(node.Clone())
				}
			}
		}
	}()

	httpServer := &http.Server{
		Handler:           r,
		ReadHeaderTimeout: 30 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	s.httpMu.Lock()
	s.httpServer = httpServer
	s.httpMu.Unlock()
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-s.ctx.Done():
			_ = s.Close()
		case <-done:
		}
	}()

	err := httpServer.Serve(s.listener)
	if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

var ErrNoCapabilityVersion = errors.New("no capability version set")

func parseCabailityVersion(req *http.Request) (tailcfg.CapabilityVersion, error) {
	clientCapabilityStr := req.URL.Query().Get("v")

	if clientCapabilityStr == "" {
		return 0, ErrNoCapabilityVersion
	}

	clientCapabilityVersion, err := strconv.Atoi(clientCapabilityStr)
	if err != nil {
		return 0, fmt.Errorf("failed to parse capability version: %w", err)
	}

	return tailcfg.CapabilityVersion(clientCapabilityVersion), nil
}

const NoiseCapabilityVersion = 39

func (s *server) KeyHandler(
	writer http.ResponseWriter,
	req *http.Request,
) {
	// New Tailscale clients send a 'v' parameter to indicate the CurrentCapabilityVersion
	capVer, err := parseCabailityVersion(req)
	if err != nil {
		writer.WriteHeader(http.StatusInternalServerError)
		return
	}
	s.logger.Info("got key request")

	// TS2021 (Tailscale v2 protocol) requires to have a different key
	if capVer >= NoiseCapabilityVersion {
		resp := tailcfg.OverTLSPublicKeyResponse{
			PublicKey: s.noisePrivateKey.Public(),
		}
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusOK)
		err = json.NewEncoder(writer).Encode(resp)
		if err != nil {
			s.logger.Error("failed to write key response", "err", err)
		}
		return
	}
}

func (s *server) NoiseUpgradeHandler(w http.ResponseWriter, r *http.Request) {
	if !s.noiseActive.CompareAndSwap(false, true) {
		http.Error(w, "a local control connection is already active", http.StatusServiceUnavailable)
		return
	}
	defer s.noiseActive.Store(false)

	s.logger.Info("got noise upgrade request")
	ns := noiseServer{
		logger:     s.logger,
		derpMap:    s.derpMap,
		challenge:  key.NewChallenge(),
		peerStore:  s.peers,
		peerUpdate: s.peerUpdate,
		node:       &s.node,
		nodeUpdate: s.nodeUpdate,
		getIPs:     s.overlay.IPs,
	}

	noiseConn, err := controlhttpserver.AcceptHTTP(
		r.Context(),
		w,
		r,
		s.noisePrivateKey,
		// The regular Noise handlers below provide the complete response, so an
		// early payload is unnecessary.
		nil,
	)
	if err != nil {
		// http.Error(w, err.Error(), http.StatusInternalServerError)
		s.logger.Error("failed to accept control http", "err", err)
		return
	}
	s.logger.Info("accepted control http")
	s.noiseMu.Lock()
	s.noiseConn = noiseConn
	s.noiseMu.Unlock()
	defer func() {
		s.noiseMu.Lock()
		if s.noiseConn == noiseConn {
			s.noiseConn = nil
		}
		s.noiseMu.Unlock()
		_ = noiseConn.Close()
	}()
	if s.ctx.Err() != nil {
		return
	}
	if err := noiseConn.SetDeadline(time.Time{}); err != nil {
		s.logger.Error("clear control connection deadline", "err", err)
		return
	}

	ns.conn = noiseConn
	ns.machineKey = ns.conn.Peer()
	ns.protocolVersion = ns.conn.ProtocolVersion()

	// This router is served only over the Noise connection, and exposes only the new API.
	//
	// The HTTP2 server that exposes this router is created for
	// a single hijacked connection from /ts2021, using netutil.NewOneConnListener

	rtr := chi.NewMux()
	rtr.NotFound(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.logger.Info("ts2021 not found", "path", r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	}))
	rtr.Post(s.controlPath+"/machine/register", ns.NoiseRegistrationHandler)
	rtr.HandleFunc(s.controlPath+"/machine/map", ns.NoisePollNetMapHandler)
	rtr.Post(s.controlPath+"/machine/update-health", func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		r.Body.Close()
		w.WriteHeader(http.StatusNoContent)
	})

	ns.httpBaseConfig = &http.Server{
		Handler:           h2c.NewHandler(rtr, ns.http2Server),
		ReadHeaderTimeout: 30 * time.Second,
		ReadTimeout:       30 * time.Second,
	}
	ns.http2Server = &http2.Server{}

	ns.http2Server.ServeConn(
		noiseConn,
		&http2.ServeConnOpts{
			BaseConfig: ns.httpBaseConfig,
		},
	)
}

type noiseServer struct {
	logger         *slog.Logger
	httpBaseConfig *http.Server
	http2Server    *http2.Server
	conn           *controlbase.Conn
	machineKey     key.MachinePublic
	derpMap        *tailcfg.DERPMap
	getIPs         func() []netip.Addr

	peerStore  *peerStore
	peerUpdate chan struct{}

	node       *atomic.Pointer[tailcfg.Node]
	nodeUpdate chan struct{}

	// EarlyNoise-related stuff
	challenge       key.ChallengePrivate
	protocolVersion int
}

func (ns *noiseServer) notifyUpdate() {
	select {
	case ns.nodeUpdate <- struct{}{}:
	default:
	}
}

func (ns *noiseServer) NoiseRegistrationHandler(w http.ResponseWriter, r *http.Request) {
	ns.logger.Info("got noise registration request")

	registerRequest := tailcfg.RegisterRequest{}
	err := json.NewDecoder(r.Body).Decode(&registerRequest)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	sp := strings.SplitN(registerRequest.Auth.AuthKey, "-", 2)

	ips := ns.getIPs()

	resp := tailcfg.RegisterResponse{}
	resp.MachineAuthorized = true
	resp.User = tailcfg.User{
		ID:          tailcfg.UserID(123),
		DisplayName: "wgsh",
		Created:     time.Now(),
	}
	resp.Login = tailcfg.Login{
		ID:          tailcfg.LoginID(123),
		LoginName:   "wgsh",
		DisplayName: "wgsh",
	}

	if !registerRequest.Expiry.IsZero() && registerRequest.Expiry.Before(time.Now()) {
		node := ns.getSelfNode().Clone()
		if node != nil {
			node.Online = ptr.To(false)
			ns.storeNode(node)
		}
		ns.notifyUpdate()

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
		return
	}

	nodeID := tailcfg.NodeID(rand.Int64())
	addrs := []netip.Prefix{}
	for _, ip := range ips {
		addrs = append(addrs, netip.PrefixFrom(ip, ip.BitLen()))
	}

	ns.storeNode(&tailcfg.Node{
		ID:         nodeID,
		StableID:   tailcfg.StableNodeID(sp[0]),
		Hostinfo:   registerRequest.Hostinfo.View(),
		Name:       registerRequest.Hostinfo.Hostname,
		User:       resp.User.ID,
		Machine:    ns.machineKey,
		Key:        registerRequest.NodeKey,
		LastSeen:   ptr.To(time.Now()),
		Cap:        registerRequest.Version,
		Online:     ptr.To(true),
		Addresses:  addrs,
		AllowedIPs: addrs,
		CapMap: tailcfg.NodeCapMap{
			tailcfg.CapabilityDebug: []tailcfg.RawMessage{"true"},
		},
		MachineAuthorized: true,
	})

	ns.logger.Info("notify update")
	ns.notifyUpdate()
	ns.logger.Info("notify update done")

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	err = json.NewEncoder(w).Encode(resp)
	if err != nil {
		ns.logger.Error("failed to write register response", "err", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	ns.logger.Info("finished registration")
}

func (ns *noiseServer) storeNode(node *tailcfg.Node) *tailcfg.Node {
	ns.node.Store(node)
	return node
}

func (ns *noiseServer) getSelfNode() *tailcfg.Node {
	return ns.node.Load()
}

func (ns *noiseServer) NoisePollNetMapHandler(
	w http.ResponseWriter,
	req *http.Request,
) {
	ns.logger.Info("got noise poll request")

	mapRequest := tailcfg.MapRequest{}
	err := json.NewDecoder(req.Body).Decode(&mapRequest)
	if err != nil {
		ns.logger.Error("failed to decode map request", "err", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	node := ns.getSelfNode()

	if node == nil {
		ns.logger.Info("noise poll request before registration")
		http.Error(w, "node is nil", http.StatusUnauthorized)
		return
	}

	switch parseMapRequestType(&mapRequest) {
	case mapRequestUnknown:
		ns.logger.Error("unknown map request type")
		http.Error(w, "unknown request type", http.StatusBadRequest)
		return

	case mapRequestStreaming:
		ns.logger.Info("streaming")
		ns.handleStreaming(req.Context(), w, &mapRequest)

	case mapRequestEndpointUpdate:
		ns.logger.Info("endpoint update")
		ns.handleEndpointUpdate(w, &mapRequest)
	}

}

func (ns *noiseServer) peers() []*tailcfg.Node {
	return ns.peerStore.snapshot()
}

func (ns *noiseServer) handleStreaming(ctx context.Context, w http.ResponseWriter, req *tailcfg.MapRequest) {
	rc := http.NewResponseController(w)
	// Longpolling will break if there is a write timeout, so it needs to be
	// disabled.
	rc.SetWriteDeadline(time.Time{})

	node := ns.getSelfNode()

	keepAlive := time.NewTicker(50 * time.Second)
	defer keepAlive.Stop()

	initialPeers := ns.peers()
	knownPeerIDs := make(map[tailcfg.NodeID]struct{}, len(initialPeers))
	for _, peer := range initialPeers {
		knownPeerIDs[peer.ID] = struct{}{}
	}
	res := &tailcfg.MapResponse{
		KeepAlive:       false,
		ControlTime:     ptr.To(time.Now()),
		Node:            node,
		DERPMap:         ns.derpMap,
		CollectServices: opt.NewBool(false),
		Debug: &tailcfg.Debug{
			DisableLogTail: true,
		},
		Peers:        initialPeers,
		PacketFilter: tailcfg.FilterAllowAll,
	}

	err := writeMapResponse(w, req, res)
	if err != nil {
		ns.logger.Error("write map response", "err", err)
		return
	}
	err = rc.Flush()
	if err != nil {
		ns.logger.Error("flush map response", "err", err)
		return
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-ns.peerUpdate:
			peers := ns.peers()
			res := &tailcfg.MapResponse{
				KeepAlive:   false,
				ControlTime: ptr.To(time.Now()),
				Peers:       peers,
			}
			if len(peers) == 0 {
				for peerID := range knownPeerIDs {
					res.PeersRemoved = append(res.PeersRemoved, peerID)
				}
				slices.Sort(res.PeersRemoved)
			}
			knownPeerIDs = make(map[tailcfg.NodeID]struct{}, len(peers))
			for _, peer := range peers {
				knownPeerIDs[peer.ID] = struct{}{}
			}

			err := writeMapResponse(w, req, res)
			if err != nil {
				ns.logger.Error("write map response", "err", err)
				return
			}
			err = rc.Flush()
			if err != nil {
				ns.logger.Error("flush map response", "err", err)
				return
			}

		case <-keepAlive.C:
			err := writeMapResponse(w, req, &tailcfg.MapResponse{
				KeepAlive:   true,
				ControlTime: ptr.To(time.Now()),
			})
			if err != nil {
				ns.logger.Error("write map keep alive", "err", err)
				return
			}
			err = rc.Flush()
			if err != nil {
				ns.logger.Error("flush map response", "err", err)
				return
			}
		}
	}
}

func writeMapResponse(w http.ResponseWriter, req *tailcfg.MapRequest, res *tailcfg.MapResponse) error {
	jsonBody, err := json.Marshal(res)
	if err != nil {
		return fmt.Errorf("marshal map response: %w", err)
	}

	var respBody []byte
	if req.Compress == "zstd" {
		respBody = zstdEncode(jsonBody)
	} else {
		respBody = jsonBody
	}

	data := make([]byte, 4)
	binary.LittleEndian.PutUint32(data, uint32(len(respBody)))
	data = append(data, respBody...)

	_, err = w.Write(data)
	if err != nil {
		return fmt.Errorf("write map response: %w", err)
	}
	return nil
}

func zstdEncode(in []byte) []byte {
	encoder, ok := zstdEncoderPool.Get().(*zstd.Encoder)
	if !ok {
		panic("invalid type in sync pool")
	}
	out := encoder.EncodeAll(in, nil)
	_ = encoder.Close()
	zstdEncoderPool.Put(encoder)

	return out
}

var zstdEncoderPool = &sync.Pool{
	New: func() any {
		encoder, err := zstd.NewWriter(
			nil,
			zstd.WithEncoderLevel(zstd.SpeedFastest))
		if err != nil {
			panic(err)
		}

		return encoder
	},
}

func (ns *noiseServer) handleEndpointUpdate(_ http.ResponseWriter, req *tailcfg.MapRequest) {
	node := ns.getSelfNode().Clone()

	change := peerChange(req, node)
	change.Online = ptr.To(true)
	applyPeerChange(node, change)

	sendUpdate, routesChanged := hostInfoChanged(node.Hostinfo.AsStruct(), req.Hostinfo)
	node.Hostinfo = req.Hostinfo.View()
	_ = routesChanged
	_ = ns.storeNode(node)

	if peerChangeEmpty(change) && !sendUpdate {
		return
	}

	ns.notifyUpdate()
}

func applyPeerChange(node *tailcfg.Node, change tailcfg.PeerChange) {
	if change.Key != nil {
		node.Key = *change.Key
	}

	if change.DiscoKey != nil {
		node.DiscoKey = *change.DiscoKey
	}

	if change.Online != nil {
		node.Online = change.Online
	}

	if change.Endpoints != nil {
		node.Endpoints = change.Endpoints
	}

	// This might technically not be useful as we replace
	// the whole hostinfo blob when it has changed.
	if change.DERPRegion != 0 {
		if !node.Hostinfo.Valid() {
			node.Hostinfo = (&tailcfg.Hostinfo{
				NetInfo: &tailcfg.NetInfo{
					PreferredDERP: change.DERPRegion,
				},
			}).View()
		} else if !node.Hostinfo.NetInfo().Valid() {
			hf := node.Hostinfo.AsStruct()
			hf.NetInfo = &tailcfg.NetInfo{
				PreferredDERP: change.DERPRegion,
			}
			node.Hostinfo = hf.View()
		} else {
			hf := node.Hostinfo.AsStruct()
			hf.NetInfo.PreferredDERP = change.DERPRegion
			node.Hostinfo = hf.View()
		}
		node.HomeDERP = change.DERPRegion
		// Older Tailscale clients only understand the legacy DERP-in-IP:port
		// field. Emit both representations while mixed protocol versions are
		// supported.
		node.LegacyDERPString = net.JoinHostPort(tailcfg.DerpMagicIP, strconv.Itoa(change.DERPRegion))
	}

	node.LastSeen = change.LastSeen
}

func peerChangeEmpty(chng tailcfg.PeerChange) bool {
	return chng.Key == nil &&
		chng.DiscoKey == nil &&
		chng.Online == nil &&
		chng.Endpoints == nil &&
		chng.DERPRegion == 0 &&
		chng.LastSeen == nil &&
		chng.KeyExpiry == nil
}

func peerChange(req *tailcfg.MapRequest, node *tailcfg.Node) tailcfg.PeerChange {
	ret := tailcfg.PeerChange{
		NodeID: node.ID,
	}

	if node.Key.String() != req.NodeKey.String() {
		ret.Key = &req.NodeKey
	}

	if node.DiscoKey.String() != req.DiscoKey.String() {
		ret.DiscoKey = &req.DiscoKey
	}

	if node.Hostinfo.Valid() &&
		node.Hostinfo.NetInfo().Valid() &&
		req.Hostinfo != nil &&
		req.Hostinfo.NetInfo != nil &&
		node.Hostinfo.NetInfo().PreferredDERP() != req.Hostinfo.NetInfo.PreferredDERP {
		ret.DERPRegion = req.Hostinfo.NetInfo.PreferredDERP
	}

	if req.Hostinfo != nil && req.Hostinfo.NetInfo != nil {
		// If there is no stored Hostinfo or NetInfo, use
		// the new PreferredDERP.
		if !node.Hostinfo.Valid() {
			ret.DERPRegion = req.Hostinfo.NetInfo.PreferredDERP
		} else if !node.Hostinfo.NetInfo().Valid() {
			ret.DERPRegion = req.Hostinfo.NetInfo.PreferredDERP
		} else {
			// If there is a PreferredDERP check if it has changed.
			if node.Hostinfo.NetInfo().PreferredDERP() != req.Hostinfo.NetInfo.PreferredDERP {
				ret.DERPRegion = req.Hostinfo.NetInfo.PreferredDERP
			}
		}
	}

	ret.Endpoints = req.Endpoints

	ret.LastSeen = ptr.To(time.Now())

	return ret
}

func hostInfoChanged(old, new *tailcfg.Hostinfo) (bool, bool) {
	if old.Equal(new) {
		return false, false
	}

	// Routes
	oldRoutes := old.RoutableIPs
	newRoutes := new.RoutableIPs

	sort.Slice(oldRoutes, func(i, j int) bool {
		return comparePrefix(oldRoutes[i], oldRoutes[j]) > 0
	})
	sort.Slice(newRoutes, func(i, j int) bool {
		return comparePrefix(newRoutes[i], newRoutes[j]) > 0
	})

	if !slices.Equal(oldRoutes, newRoutes) {
		return true, true
	}

	// Services is mostly useful for discovery and not critical,
	// except for peerapi, which is how nodes talk to eachother.
	// If peerapi was not part of the initial mapresponse, we
	// need to make sure its sent out later as it is needed for
	// Taildrop.
	// TODO(kradalby): Length comparison is a bit naive, replace.
	if len(old.Services) != len(new.Services) {
		return true, false
	}

	return false, false
}

// TODO(kradalby): Remove after go 1.23, will be in stdlib.
// Compare returns an integer comparing two prefixes.
// The result will be 0 if p == p2, -1 if p < p2, and +1 if p > p2.
// Prefixes sort first by validity (invalid before valid), then
// address family (IPv4 before IPv6), then prefix length, then
// address.
func comparePrefix(p, p2 netip.Prefix) int {
	if c := cmp.Compare(p.Addr().BitLen(), p2.Addr().BitLen()); c != 0 {
		return c
	}
	if c := cmp.Compare(p.Bits(), p2.Bits()); c != 0 {
		return c
	}
	return p.Addr().Compare(p2.Addr())
}

type mapRequestType int

const (
	mapRequestUnknown mapRequestType = iota
	mapRequestStreaming
	mapRequestEndpointUpdate
)

func parseMapRequestType(mr *tailcfg.MapRequest) mapRequestType {
	if mr.Stream {
		return mapRequestStreaming
	} else if !mr.Stream && mr.OmitPeers {
		return mapRequestEndpointUpdate
	} else {
		return mapRequestUnknown
	}
}

const (
	earlyNoiseCapabilityVersion = 49
	earlyPayloadMagic           = "\xff\xff\xffTS"
)

var _ = (*noiseServer)(nil).earlyNoise

func (ns *noiseServer) earlyNoise(protocolVersion int, writer io.Writer) error {
	ns.logger.Info("early noise")
	if protocolVersion < earlyNoiseCapabilityVersion {
		return nil
	}

	earlyJSON, err := json.Marshal(&tailcfg.EarlyNoise{
		NodeKeyChallenge: ns.challenge.Public(),
	})
	if err != nil {
		return err
	}

	// 5 bytes that won't be mistaken for an HTTP/2 frame:
	// https://httpwg.org/specs/rfc7540.html#rfc.section.4.1 (Especially not
	// an HTTP/2 settings frame, which isn't of type 'T')
	var notH2Frame [5]byte
	copy(notH2Frame[:], earlyPayloadMagic)
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(earlyJSON)))
	// These writes are all buffered by caller, so fine to do them
	// separately:
	if _, err := writer.Write(notH2Frame[:]); err != nil {
		return err
	}
	if _, err := writer.Write(lenBuf[:]); err != nil {
		return err
	}
	if _, err := writer.Write(earlyJSON); err != nil {
		return err
	}

	return nil
}
