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
	"os"
	"os/user"
	"sync"
	"time"

	"github.com/coder/wush/cliui"
	"github.com/google/uuid"
	"tailscale.com/derp"
	"tailscale.com/derp/derphttp"
	"tailscale.com/net/netmon"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func NewSendOverlay(logger *slog.Logger, dm *tailcfg.DERPMap) *Send {
	s := &Send{
		Logger:    logger,
		derpMap:   dm,
		in:        make(chan PeerUpdate, 8),
		out:       make(chan *overlayMessage, 8),
		done:      make(chan struct{}),
		SelfIP:    randv6(),
		SessionID: uuid.NewString(),
	}
	return s
}

type Send struct {
	Logger  *slog.Logger
	derpMap *tailcfg.DERPMap

	SelfIP    netip.Addr
	SessionID string

	Auth ClientAuth

	in  chan PeerUpdate
	out chan *overlayMessage

	closeMu   sync.Mutex
	closeFunc func()
	closed    bool
	done      chan struct{}
}

func (s *Send) IPs() []netip.Addr {
	return []netip.Addr{s.SelfIP}
}

func (s *Send) Recv() <-chan PeerUpdate {
	return s.in
}

func (s *Send) SendTailscaleNodeUpdate(node *tailcfg.Node) {
	s.out <- &overlayMessage{
		Typ:       messageTypeNodeUpdate,
		SessionID: s.SessionID,
		Node:      *node.Clone(),
	}
}

func (s *Send) ListenOverlayDERP(ctx context.Context) error {
	derpPriv := key.NewNode()
	c := derphttp.NewRegionClient(derpPriv, func(format string, args ...any) {}, netmon.NewStatic(), func() *tailcfg.DERPRegion {
		return s.derpMap.Regions[int(s.Auth.ReceiverDERPRegionID)]
	})

	err := c.Connect(ctx)
	if err != nil {
		return err
	}

	sealed := s.newHelloPacket()
	err = c.Send(s.Auth.ReceiverPublicKey, sealed)
	if err != nil {
		return fmt.Errorf("send overlay hello over derp: %w", err)
	}

	s.setCloseFunc(func() {
		_ = c.Send(s.Auth.ReceiverPublicKey, s.sealMessage(overlayMessage{
			Typ:       messageTypeGoodbye,
			SessionID: s.SessionID,
		}))
		_ = c.Close()
	})
	defer s.Close()
	go func() {
		select {
		case <-ctx.Done():
			s.Close()
		case <-s.done:
		}
	}()

	keepAlive := time.NewTicker(peerKeepAliveInterval)
	defer keepAlive.Stop()

	go func() {
		for {
			select {
			case <-s.done:
				return
			case <-ctx.Done():
				return
			case msg := <-s.out:
				raw, err := json.Marshal(msg)
				if err != nil {
					panic("marshal overlay msg: " + err.Error())
				}

				sealed := s.Auth.OverlayPrivateKey.SealTo(s.Auth.ReceiverPublicKey, raw)
				err = c.Send(s.Auth.ReceiverPublicKey, sealed)
				if err != nil {
					fmt.Printf("send response over derp: %s\n", err)
					return
				}
			case <-keepAlive.C:
				err = c.Send(s.Auth.ReceiverPublicKey, s.sealMessage(overlayMessage{
					Typ:       messageTypePing,
					SessionID: s.SessionID,
				}))
				if err != nil {
					return
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
			if s.Auth.ReceiverPublicKey != msg.Source {
				fmt.Printf("message from unknown peer %s\n", msg.Source.String())
				continue
			}

			res, err := s.handleNextMessage(msg.Data)
			if err != nil {
				fmt.Println("Failed to handle overlay message", err)
				continue
			}

			if res != nil {
				err = c.Send(msg.Source, res)
				if err != nil {
					fmt.Println(cliui.Timestamp(time.Now()), "Failed to send overlay response over derp:", err.Error())
					return err
				}
			}
		}
	}
}

func (s *Send) newHelloPacket() []byte {
	var (
		username,
		hostname string
	)

	cu, _ := user.Current()
	if cu != nil {
		username = cu.Username
	}
	hostname, _ = os.Hostname()

	raw, err := json.Marshal(overlayMessage{
		Typ:       messageTypeHello,
		SessionID: s.SessionID,
		HostInfo: HostInfo{
			Username: username,
			Hostname: hostname,
		},
	})
	if err != nil {
		panic("marshal node: " + err.Error())
	}

	sealed := s.Auth.OverlayPrivateKey.SealTo(s.Auth.ReceiverPublicKey, raw)
	return sealed
}

func (s *Send) handleNextMessage(msg []byte) (resRaw []byte, _ error) {
	cleartext, ok := s.Auth.OverlayPrivateKey.OpenFrom(s.Auth.ReceiverPublicKey, msg)
	if !ok {
		return nil, errors.New("message failed decryption")
	}

	var ovMsg overlayMessage
	err := json.Unmarshal(cleartext, &ovMsg)
	if err != nil {
		return nil, fmt.Errorf("unmarshal overlay message: %w", err)
	}
	// Version 1 servers do not echo SessionID. Accept an empty value during the
	// documented client-first rolling upgrade, while requiring an exact match
	// whenever the server supports session-aware multi-peer routing.
	if ovMsg.SessionID != "" && ovMsg.SessionID != s.SessionID {
		return nil, errors.New("overlay response belongs to another session")
	}

	res := overlayMessage{SessionID: s.SessionID}
	switch ovMsg.Typ {
	case messageTypePing:
		res.Typ = messageTypePong
	case messageTypePong:
		// do nothing
	case messageTypeHelloResponse:
		s.in <- PeerUpdate{ID: s.Auth.ReceiverPublicKey.String(), Node: ovMsg.Node.Clone()}
	case messageTypeNodeUpdate:
		s.in <- PeerUpdate{ID: s.Auth.ReceiverPublicKey.String(), Node: ovMsg.Node.Clone()}
	}

	if res.Typ == 0 {
		return nil, nil
	}

	raw, err := json.Marshal(res)
	if err != nil {
		panic("marshal node: " + err.Error())
	}

	sealed := s.Auth.OverlayPrivateKey.SealTo(s.Auth.ReceiverPublicKey, raw)
	return sealed, nil
}

func (s *Send) sealMessage(msg overlayMessage) []byte {
	raw, err := json.Marshal(msg)
	if err != nil {
		panic("marshal overlay message: " + err.Error())
	}
	return s.Auth.OverlayPrivateKey.SealTo(s.Auth.ReceiverPublicKey, raw)
}

func (s *Send) setCloseFunc(closeFunc func()) {
	s.closeMu.Lock()
	if s.closed {
		s.closeMu.Unlock()
		closeFunc()
		return
	}
	s.closeFunc = closeFunc
	s.closeMu.Unlock()
}

// Close sends a best-effort disconnect message and releases the overlay
// transport. It is safe to call more than once.
func (s *Send) Close() {
	s.closeMu.Lock()
	if s.closed {
		s.closeMu.Unlock()
		return
	}
	s.closed = true
	closeFunc := s.closeFunc
	if s.done != nil {
		close(s.done)
	}
	s.closeMu.Unlock()
	if closeFunc != nil {
		closeFunc()
	}
}
