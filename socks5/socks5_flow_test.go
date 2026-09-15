package socks5

import (
	"bufio"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type blockingConn struct {
	mu      sync.Mutex
	closed  bool
	closedC chan struct{}
	once    sync.Once
}

func newBlockingConn() *blockingConn {
	return &blockingConn{closedC: make(chan struct{})}
}

func (c *blockingConn) Read(b []byte) (int, error) {
	<-c.closedC
	return 0, io.EOF
}

func (c *blockingConn) Write(b []byte) (int, error) {
	<-c.closedC
	return 0, io.ErrClosedPipe
}

func (c *blockingConn) Close() error {
	c.once.Do(func() {
		c.mu.Lock()
		c.closed = true
		c.mu.Unlock()
		close(c.closedC)
	})
	return nil
}

func (c *blockingConn) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

func (c *blockingConn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (c *blockingConn) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (c *blockingConn) SetDeadline(time.Time) error        { return nil }
func (c *blockingConn) SetReadDeadline(time.Time) error    { return nil }
func (c *blockingConn) SetWriteDeadline(time.Time) error   { return nil }

type fakeDialer struct {
	fn func(address string) (net.Conn, error)
}

func (d *fakeDialer) DialTCP(address string) (net.Conn, error) { return d.fn(address) }

func startTestServer(t *testing.T, dialer Dialer, configure func(*SOCKS5Server)) (*SOCKS5Server, string) {
	t.Helper()
	server := NewSOCKS5Server("127.0.0.1:0", dialer)
	if configure != nil {
		configure(server)
	}
	if err := server.StartInBackground(); err != nil {
		t.Fatalf("start socks5 server: %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })
	server.mu.Lock()
	addr := server.listener.Addr().String()
	server.mu.Unlock()
	return server, addr
}

// socksHandshake performs the no-auth greeting + CONNECT and returns the
// server reply code.
func socksHandshake(t *testing.T, conn net.Conn, target string) byte {
	t.Helper()
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("write greeting: %v", err)
	}
	greeting := make([]byte, 2)
	if _, err := io.ReadFull(conn, greeting); err != nil {
		t.Fatalf("read greeting reply: %v", err)
	}
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		t.Fatalf("split target: %v", err)
	}
	parsedPort, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}
	port := uint16(parsedPort)
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, host...)
	req = append(req, byte(port>>8), byte(port))
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("write connect: %v", err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("read connect reply: %v", err)
	}
	return reply[1]
}

func TestFlowCapsRejectExcessSessions(t *testing.T) {
	var dialed atomic.Int32
	dialer := &fakeDialer{fn: func(string) (net.Conn, error) {
		dialed.Add(1)
		return newBlockingConn(), nil
	}}
	server, addr := startTestServer(t, dialer, func(s *SOCKS5Server) {
		s.SetFlowLimits(1, 8, 20, 0, 0, 0)
	})

	first, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if code := socksHandshake(t, first, "example.com:443"); code != 0x00 {
		t.Fatalf("first session should be accepted, reply code 0x%02x", code)
	}

	second, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if code := socksHandshake(t, second, "example.com:443"); code != 0x02 {
		t.Fatalf("second session past maxTCP should be rejected (0x02), got 0x%02x", code)
	}

	if got := server.ActiveTotalFlows(); got != 1 {
		t.Fatalf("expected exactly 1 active flow, got %d", got)
	}
	if got := dialed.Load(); got != 1 {
		t.Fatalf("dialer must not run for rejected sessions, dialed=%d", got)
	}
}

func TestStalledSessionFreedAfterIdleTimeout(t *testing.T) {
	target := newBlockingConn()
	dialer := &fakeDialer{fn: func(string) (net.Conn, error) { return target, nil }}
	server, addr := startTestServer(t, dialer, func(s *SOCKS5Server) {
		s.SetFlowLimits(0, 0, 0, 0, 300*time.Millisecond, 0)
	})

	client, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if code := socksHandshake(t, client, "example.com:443"); code != 0x00 {
		t.Fatalf("session should be accepted, got 0x%02x", code)
	}

	// Nobody transfers anything: the idle deadline must force-close the
	// target conn (the old io.Copy pair would block forever here) and free
	// the slot.
	deadline := time.Now().Add(3 * time.Second)
	for !target.isClosed() && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if !target.isClosed() {
		t.Fatal("stalled session never released the target connection")
	}
	for server.ActiveTotalFlows() != 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if got := server.ActiveTotalFlows(); got != 0 {
		t.Fatalf("session slot not freed after stall, active=%d", got)
	}
}

func TestHandshakeTimeoutClosesSilentConn(t *testing.T) {
	dialer := &fakeDialer{fn: func(string) (net.Conn, error) { return newBlockingConn(), nil }}
	_, addr := startTestServer(t, dialer, func(s *SOCKS5Server) {
		s.SetFlowLimits(0, 0, 0, 200*time.Millisecond, 0, 0)
	})

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// Send nothing at all: the server must drop the conn promptly.
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	reader := bufio.NewReader(conn)
	if _, err := reader.ReadByte(); err == nil {
		t.Fatal("expected EOF/error from handshake timeout, got data")
	}
}

func TestUDPAssociateReapedWhenIdle(t *testing.T) {
	dialer := &fakeDialer{fn: func(string) (net.Conn, error) { return newBlockingConn(), nil }}
	server, addr := startTestServer(t, dialer, func(s *SOCKS5Server) {
		s.SetFlowLimits(0, 0, 0, 0, 0, 300*time.Millisecond)
	})

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	greeting := make([]byte, 2)
	if _, err := io.ReadFull(conn, greeting); err != nil {
		t.Fatal(err)
	}
	// UDP ASSOCIATE request.
	if _, err := conn.Write([]byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatal(err)
	}
	if reply[1] != 0x00 {
		t.Fatalf("associate should be accepted, code 0x%02x", reply[1])
	}
	if got := server.ActiveUDPFlows(); got != 1 {
		t.Fatalf("associate should occupy a UDP slot, active=%d", got)
	}

	// No datagrams ever arrive: the idle endpoint timeout must reap the
	// associate (close the control conn, free the slot) so a churn of
	// dead gvisor UDP tunnels cannot exhaust the UDP cap and starve DNS.
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if n, err := conn.Read(make([]byte, 1)); err == nil && n > 0 {
		t.Fatalf("idle associate was never reaped, read %d bytes", n)
	}
	deadline := time.Now().Add(2 * time.Second)
	for server.ActiveUDPFlows() != 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if got := server.ActiveUDPFlows(); got != 0 {
		t.Fatalf("idle associate slot not freed, active=%d", got)
	}
}
