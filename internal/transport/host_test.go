package transport

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"
)

func TestUDPListenerLeaseIsSharedAcrossSessions(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	listener := newBlockingListener()
	listenCalls := 0
	host := &Host{
		ctx:        ctx,
		logf:       func(string, ...any) {},
		udpHandler: func(context.Context, net.Conn, uint16) {},
		udpPorts:   make(map[uint16]*udpPort),
		listenUDP: func(port uint16) (net.Listener, error) {
			listenCalls++
			if port != 5353 {
				t.Fatalf("listen port = %d, want 5353", port)
			}
			return listener, nil
		},
	}
	for _, sessionID := range []string{"session-a", "session-a", "session-b"} {
		if err := host.openUDP(sessionID, 5353); err != nil {
			t.Fatal(err)
		}
	}
	if listenCalls != 1 {
		t.Fatalf("listen calls = %d, want 1", listenCalls)
	}

	host.closeUDPSession("session-a")
	if listener.closeCount() != 0 {
		t.Fatal("shared listener closed while session-b still holds a lease")
	}
	host.closeUDPSession("session-b")
	if listener.closeCount() != 1 {
		t.Fatalf("listener close calls = %d, want 1", listener.closeCount())
	}
	if len(host.udpPorts) != 0 {
		t.Fatalf("retained UDP ports = %d, want 0", len(host.udpPorts))
	}
}

func TestUDPListenerRequestFailsWhenDisabled(t *testing.T) {
	t.Parallel()

	host := &Host{}
	if err := host.openUDP("session-a", 53); err == nil || err.Error() != "UDP forwarding is disabled" {
		t.Fatalf("openUDP error = %v", err)
	}
}

func TestSessionCloseClosesOnlyMatchingTCPConnections(t *testing.T) {
	t.Parallel()

	host := newTCPTestHost()
	closedIP := netip.MustParseAddr("fd7a:115c:a1e0::2")
	activeIP := netip.MustParseAddr("fd7a:115c:a1e0::3")
	closedConn, closedPeer := net.Pipe()
	activeConn, activePeer := net.Pipe()
	t.Cleanup(func() {
		_ = closedPeer.Close()
		_ = activeConn.Close()
		_ = activePeer.Close()
	})
	host.updateSession("session-a", []netip.Addr{closedIP})
	host.updateSession("session-b", []netip.Addr{activeIP})
	if !host.trackTCPConn(closedIP, closedConn) || !host.trackTCPConn(activeIP, activeConn) {
		t.Fatal("active peer connection was rejected")
	}

	host.closeSession("session-a", []netip.Addr{closedIP})

	_ = closedPeer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := closedPeer.Read(make([]byte, 1)); err == nil {
		t.Fatal("peer connection remained open after its overlay session closed")
	}
	host.tcpMu.Lock()
	_, closedTracked := host.tcpConns[closedIP]
	_, activeTracked := host.tcpConns[activeIP]
	host.tcpMu.Unlock()
	if closedTracked {
		t.Fatal("closed peer remains in TCP connection registry")
	}
	if !activeTracked {
		t.Fatal("unrelated active peer was removed from TCP connection registry")
	}
	lateConn, latePeer := net.Pipe()
	defer latePeer.Close()
	if host.trackTCPConn(closedIP, lateConn) {
		t.Fatal("connection from a closed peer was accepted")
	}
	_ = lateConn.Close()
}

func TestSessionUpdateReplacesPeerIPs(t *testing.T) {
	t.Parallel()

	host := newTCPTestHost()
	oldIP := netip.MustParseAddr("fd7a:115c:a1e0::4")
	newIP := netip.MustParseAddr("fd7a:115c:a1e0::5")
	oldConn, oldPeer := net.Pipe()
	defer oldPeer.Close()
	host.updateSession("session-a", []netip.Addr{oldIP})
	if !host.trackTCPConn(oldIP, oldConn) {
		t.Fatal("initial peer connection was rejected")
	}

	host.updateSession("session-a", []netip.Addr{newIP})

	_ = oldPeer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := oldPeer.Read(make([]byte, 1)); err == nil {
		t.Fatal("connection for replaced peer IP remained open")
	}
	lateOld, lateOldPeer := net.Pipe()
	defer lateOldPeer.Close()
	if host.trackTCPConn(oldIP, lateOld) {
		t.Fatal("connection from replaced peer IP was accepted")
	}
	_ = lateOld.Close()
	newConn, newPeer := net.Pipe()
	defer newConn.Close()
	defer newPeer.Close()
	if !host.trackTCPConn(newIP, newConn) {
		t.Fatal("connection from replacement peer IP was rejected")
	}
}

func TestSessionCloseKeepsIPSharedByActiveSession(t *testing.T) {
	t.Parallel()

	host := newTCPTestHost()
	sharedIP := netip.MustParseAddr("fd7a:115c:a1e0::6")
	host.updateSession("session-a", []netip.Addr{sharedIP})
	host.updateSession("session-b", []netip.Addr{sharedIP})
	conn, peer := net.Pipe()
	defer peer.Close()
	if !host.trackTCPConn(sharedIP, conn) {
		t.Fatal("shared peer connection was rejected")
	}

	host.closeSession("session-a", []netip.Addr{sharedIP})

	_ = peer.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	if _, err := peer.Read(make([]byte, 1)); err == nil {
		t.Fatal("shared peer read unexpectedly completed")
	} else if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("shared peer connection closed with %v while session-b remained active", err)
	}
	_ = peer.SetReadDeadline(time.Time{})
	host.closeSession("session-b", []netip.Addr{sharedIP})
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := peer.Read(make([]byte, 1)); err == nil {
		t.Fatal("shared peer connection remained open after its final session closed")
	}
}

func newTCPTestHost() *Host {
	return &Host{
		tcpConns:        make(map[netip.Addr]map[net.Conn]struct{}),
		tcpSessions:     make(map[string]map[netip.Addr]struct{}),
		tcpPeerSessions: make(map[netip.Addr]map[string]struct{}),
	}
}

type blockingListener struct {
	closed chan struct{}
	once   sync.Once
	mu     sync.Mutex
	closes int
}

func newBlockingListener() *blockingListener {
	return &blockingListener{closed: make(chan struct{})}
}

func (l *blockingListener) Accept() (net.Conn, error) {
	<-l.closed
	return nil, net.ErrClosed
}

func (l *blockingListener) Close() error {
	l.mu.Lock()
	l.closes++
	l.mu.Unlock()
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *blockingListener) Addr() net.Addr { return blockingAddr{} }

func (l *blockingListener) closeCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.closes
}

type blockingAddr struct{}

func (blockingAddr) Network() string { return "udp" }
func (blockingAddr) String() string  { return "test:5353" }

var _ net.Listener = (*blockingListener)(nil)
