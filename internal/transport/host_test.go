package transport

import (
	"context"
	"net"
	"sync"
	"testing"
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
