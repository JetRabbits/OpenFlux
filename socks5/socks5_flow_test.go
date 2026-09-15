package socks5

import (
	"bufio"
	"fmt"
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

func (c *blockingConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *blockingConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *blockingConn) SetDeadline(time.Time) error      { return nil }
func (c *blockingConn) SetReadDeadline(time.Time) error  { return nil }
func (c *blockingConn) SetWriteDeadline(time.Time) error { return nil }

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
		s.SetFlowLimits(1, 8, 20, 0, 0, 0, 200*time.Millisecond, 0)
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

func TestDialTimeoutFreesSlot(t *testing.T) {
	blocked := make(chan struct{})
	dialer := &fakeDialer{fn: func(string) (net.Conn, error) {
		<-blocked // never returns until the test ends
		return nil, io.EOF
	}}
	server, addr := startTestServer(t, dialer, func(s *SOCKS5Server) {
		s.SetFlowLimits(0, 0, 0, 0, 300*time.Millisecond, 0, 0, 0)
	})
	defer close(blocked)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	code := socksHandshake(t, conn, "example.com:443")
	if code != 0x04 {
		t.Fatalf("timed-out dial should reply host-unreachable 0x04, got 0x%02x", code)
	}
	deadline := time.Now().Add(2 * time.Second)
	for server.ActiveTotalFlows() != 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if got := server.ActiveTotalFlows(); got != 0 {
		t.Fatalf("stuck dial kept the flow slot, active=%d", got)
	}
}

func TestStalledSessionFreedAfterIdleTimeout(t *testing.T) {
	target := newBlockingConn()
	dialer := &fakeDialer{fn: func(string) (net.Conn, error) { return target, nil }}
	server, addr := startTestServer(t, dialer, func(s *SOCKS5Server) {
		s.SetFlowLimits(0, 0, 0, 0, 300*time.Millisecond, 0, 0, 0)
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
		s.SetFlowLimits(0, 0, 0, 200*time.Millisecond, 0, 0, 0, 0)
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
		s.SetFlowLimits(0, 0, 0, 0, 0, 300*time.Millisecond, 0, 0)
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

func TestUDPAssociateReapedOnNonDNSPort(t *testing.T) {
	dialer := &fakeDialer{fn: func(string) (net.Conn, error) { return newBlockingConn(), nil }}
	server, addr := startTestServer(t, dialer, func(s *SOCKS5Server) {
		// Long endpoint timeout: only the terminal classification may
		// reap this associate, not idleness.
		s.SetFlowLimits(0, 0, 0, 0, 0, 30*time.Second, 0, 0)
	})

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(conn, make([]byte, 2)); err != nil {
		t.Fatal(err)
	}
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
	relayPort := int(reply[8])<<8 | int(reply[9])

	udp, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", relayPort))
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	datagram := []byte{0, 0, 0, 1, 127, 0, 0, 1, 1, 0xbb} // => dest port 443
	if _, err := udp.Write(append(datagram, 0xde, 0xad)); err != nil {
		t.Fatal(err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if n, err := conn.Read(make([]byte, 1)); err == nil && n > 0 {
		t.Fatalf("non-DNS associate was not reaped, read %d bytes", n)
	}
	deadline := time.Now().Add(2 * time.Second)
	for server.ActiveUDPFlows() != 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if got := server.ActiveUDPFlows(); got != 0 {
		t.Fatalf("non-DNS associate slot not freed, active=%d", got)
	}
}

func TestDefaultLimitsArePopulated(t *testing.T) {
	// Regression guard: defaults once silently lost their literal and
	// dialTimeout=0 made time.After(0) reject every dial instantly.
	s := NewSOCKS5Server("127.0.0.1:0", &fakeDialer{})
	if s.limits.dialTimeout <= 0 || s.limits.slotWait <= 0 ||
		s.limits.handshake <= 0 || s.limits.idle <= 0 || s.limits.udpEndpoint <= 0 {
		t.Fatalf("zero-valued default limits: %+v", s.limits)
	}
	if s.limits.maxTCP <= 0 || s.limits.maxUDP <= 0 || s.limits.maxTotal <= 0 {
		t.Fatalf("non-positive default caps: %+v", s.limits)
	}
}

type eofOnReadConn struct{ *blockingConn }

func (c *eofOnReadConn) Read([]byte) (int, error) { return 0, io.EOF }

func TestHalfCloseFreesSlotImmediately(t *testing.T) {
	// Device regression: SpeedTest servers send FIN right after the
	// response while the client keeps the socket silently open. The first
	// copy to finish must force-close both ends and free the slot at once;
	// waiting for the mutual-silence timer instead pinned all 24 TCP slots
	// and the tunnel presented as "no connection" at a healthy 27 MB.
	target := &eofOnReadConn{blockingConn: newBlockingConn()}
	dialer := &fakeDialer{fn: func(string) (net.Conn, error) { return target, nil }}
	server, addr := startTestServer(t, dialer, func(s *SOCKS5Server) {
		// Idle window deliberately huge: only EOF propagation can free
		// the slot within the test's 2 s budget.
		s.SetFlowLimits(0, 0, 0, 0, 10*time.Second, 0, 0, 0)
	})

	client, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if code := socksHandshake(t, client, "example.com:443"); code != 0x00 {
		t.Fatalf("session should be accepted, got 0x%02x", code)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if server.ActiveTCPFlows() == 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("target-side EOF must free the slot immediately; flow still pinned")
}
