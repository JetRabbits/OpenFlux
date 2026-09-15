package socks5

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"universal-bypass-tool/utils"
)

type Dialer interface {
	DialTCP(address string) (net.Conn, error)
}

// Resource ceilings for in-process SOCKS sessions, mirroring the hardening
// that made the Cordyceps mobile runtime survive iOS NetworkExtension
// jetsam limits (~50 MB phys_footprint): an uncapped, undeadlined session
// table lets every half-dead tun2socks tunnel retain two blocked io.Copy
// goroutines plus buffers forever (observed stackInuse 7.5 MB and ~7 MB/
// footprint growth per 5 s burst, with FreeOSMemory unable to reclaim any
// of it because the goroutines were still live).
const (
	// Tuned against real iOS NetworkExtension behaviour: the tunnel-owner
	// device allocates one UDP ASSOCIATE per destination (every DNS
	// resolver, NTP, captive portal probes...), so the startup burst alone
	// negotiates 10-15 associates. The Cordyceps-baseline 8 starved DNS
	// with "connection not allowed by ruleset" retry storms on first
	// device tests. Idle/terminal reaping keeps the real steady state tiny
	// (observed 0-3 DNS associates); the caps are emergency brakes, with
	// worst-case cost ~48 * (32 KB copy + 128 KB gvisor buffer) ~ 8 MB.
	DefaultMaxTCPFlows        = 24
	DefaultMaxUDPFlows        = 32
	DefaultMaxTotalFlows      = 48
	DefaultHandshakeTimeout   = 10 * time.Second
	DefaultSessionIdleTimeout = 75 * time.Second
	DefaultUDPEndpointTimeout = 45 * time.Second
)

type flowLimits struct {
	maxTCP      int
	maxUDP      int
	maxTotal    int
	handshake   time.Duration
	idle        time.Duration
	udpEndpoint time.Duration
}

type SOCKS5Server struct {
	listenAddr string
	dialer     Dialer
	limits     flowLimits

	mu       sync.Mutex
	listener net.Listener
	closed   bool

	activeTCP atomic.Int32
	activeUDP atomic.Int32
}

func NewSOCKS5Server(addr string, dialer Dialer) *SOCKS5Server {
	return &SOCKS5Server{
		listenAddr: addr,
		dialer:     dialer,
		limits: flowLimits{
			maxTCP:      DefaultMaxTCPFlows,
			maxUDP:      DefaultMaxUDPFlows,
			maxTotal:    DefaultMaxTotalFlows,
			handshake:   DefaultHandshakeTimeout,
			idle:        DefaultSessionIdleTimeout,
			udpEndpoint: DefaultUDPEndpointTimeout,
		},
	}
}

// SetFlowLimits overrides the resource ceilings for tests and platform
// bindings. Any zero/negative argument keeps the current value for that
// field. Call before Start/StartInBackground.
func (s *SOCKS5Server) SetFlowLimits(maxTCP, maxUDP, maxTotal int, handshake, idle, udpEndpoint time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if maxTCP > 0 {
		s.limits.maxTCP = maxTCP
	}
	if maxUDP > 0 {
		s.limits.maxUDP = maxUDP
	}
	if maxTotal > 0 {
		s.limits.maxTotal = maxTotal
	}
	if handshake > 0 {
		s.limits.handshake = handshake
	}
	if idle > 0 {
		s.limits.idle = idle
	}
	if udpEndpoint > 0 {
		s.limits.udpEndpoint = udpEndpoint
	}
}

// ActiveTCPFlows / ActiveUDPFlows / ActiveTotalFlows expose the live session
// counts for runtime diagnostics (same role as the Cordyceps SOCKS counters).
func (s *SOCKS5Server) ActiveTCPFlows() int { return int(s.activeTCP.Load()) }
func (s *SOCKS5Server) ActiveUDPFlows() int { return int(s.activeUDP.Load()) }
func (s *SOCKS5Server) ActiveTotalFlows() int {
	return int(s.activeTCP.Load()) + int(s.activeUDP.Load())
}

func (s *SOCKS5Server) Start() error {
	if err := s.startListening(); err != nil {
		return err
	}
	return s.acceptLoop()
}

// StartInBackground starts the listener synchronously and serves connections on
// a goroutine. This is used by the mobile shared-library binding: Start must
// return after the SOCKS5 port is bound, while the server keeps running until
// Close is called.
func (s *SOCKS5Server) StartInBackground() error {
	if err := s.startListening(); err != nil {
		return err
	}
	go func() {
		if err := s.acceptLoop(); err != nil {
			utils.Debugf("[SOCKS5] background server stopped: %v", err)
		}
	}()
	return nil
}

func (s *SOCKS5Server) startListening() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.listener != nil && !s.closed {
		return fmt.Errorf("SOCKS5 server already listening on %s", s.listenAddr)
	}

	listener, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		return err
	}
	s.listener = listener
	s.closed = false

	utils.Debugf("[SOCKS5] Listening on %s", s.listenAddr)
	return nil
}

func (s *SOCKS5Server) acceptLoop() error {
	s.mu.Lock()
	listener := s.listener
	s.mu.Unlock()
	if listener == nil {
		return fmt.Errorf("SOCKS5 server is not listening")
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed || errors.Is(err, net.ErrClosed) {
				return nil
			}
			utils.Debugf("[SOCKS5] Accept error: %v", err)
			continue
		}
		go s.handleConnection(conn)
	}
}

func (s *SOCKS5Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil
	}
	s.closed = true
	if s.listener == nil {
		return nil
	}
	err := s.listener.Close()
	s.listener = nil
	return err
}

func (s *SOCKS5Server) handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	handshake, idle, udpEndpoint := func() (time.Duration, time.Duration, time.Duration) {
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.limits.handshake, s.limits.idle, s.limits.udpEndpoint
	}()

	// Handshake phase must not be able to pin a goroutine forever: a
	// half-open gvisor tunnel that never sends its greeting would otherwise
	// leak a session slot and its stacks indefinitely.
	_ = clientConn.SetReadDeadline(time.Now().Add(handshake))

	buf := make([]byte, 256)
	n, err := clientConn.Read(buf)
	if err != nil || n < 2 || buf[0] != 0x05 {
		return
	}

	clientConn.Write([]byte{0x05, 0x00})

	n, err = clientConn.Read(buf)
	if err != nil || n < 10 {
		return
	}

	// Handshake complete; deadlines from here on are per-transfer.
	_ = clientConn.SetReadDeadline(time.Time{})

	if buf[1] == 0x03 {
		if !s.reserveFlow(true) {
			utils.Debugf("[SOCKS5] UDP flow cap reached, rejecting ASSOCIATE")
			clientConn.Write([]byte{0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
			return
		}
		defer s.releaseFlow(true)
		s.handleUDPAssociate(clientConn, udpEndpoint)
		return
	}

	if buf[1] != 0x01 {
		return
	}

	var targetAddr string
	switch buf[3] {
	case 0x01:
		targetAddr = fmt.Sprintf("%d.%d.%d.%d:%d",
			buf[4], buf[5], buf[6], buf[7],
			uint16(buf[8])<<8|uint16(buf[9]))
	case 0x03:
		domainLen := int(buf[4])
		targetAddr = fmt.Sprintf("%s:%d",
			string(buf[5:5+domainLen]),
			uint16(buf[5+domainLen])<<8|uint16(buf[6+domainLen]))
	default:
		return
	}

	utils.Debugf("[SOCKS5] CONNECT %s", targetAddr)

	if !s.reserveFlow(false) {
		utils.Debugf("[SOCKS5] TCP flow cap reached, rejecting CONNECT %s", targetAddr)
		clientConn.Write([]byte{0x05, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return
	}
	defer s.releaseFlow(false)

	targetConn, err := s.dialer.DialTCP(targetAddr)
	if err != nil {
		utils.Debugf("[SOCKS5] Dial failed: %v", err)
		clientConn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return
	}
	defer targetConn.Close()

	clientConn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

	// Either direction finishing (including on an idle/deadline error)
	// force-closes both endpoints. Plain io.Copy + WaitGroup leaks the
	// sibling goroutine forever when one side half-closes without the
	// peer propagating FIN (the exact session style that accumulated
	// 7.5 MB of stuck stacks on iOS).
	finish := func() {
		_ = clientConn.Close()
		_ = targetConn.Close()
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		defer finish()
		relayWithIdleTimeout(targetConn, clientConn, idle)
	}()
	go func() {
		defer wg.Done()
		defer finish()
		relayWithIdleTimeout(clientConn, targetConn, idle)
	}()
	wg.Wait()
}

// reserveFlow takes a session slot honouring the per-kind and global caps.
func (s *SOCKS5Server) reserveFlow(udp bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	tcp := s.activeTCP.Load()
	udpCount := s.activeUDP.Load()
	maxTCP, maxUDP, maxTotal := s.limits.maxTCP, s.limits.maxUDP, s.limits.maxTotal
	if int(tcp+udpCount) >= maxTotal {
		return false
	}
	if udp {
		if int(udpCount) >= maxUDP {
			return false
		}
		s.activeUDP.Add(1)
		return true
	}
	if int(tcp) >= maxTCP {
		return false
	}
	s.activeTCP.Add(1)
	return true
}

func (s *SOCKS5Server) releaseFlow(udp bool) {
	if udp {
		s.activeUDP.Add(-1)
	} else {
		s.activeTCP.Add(-1)
	}
}

// relayWithIdleTimeout copies src -> dst, refreshing read/write deadlines on
// every chunk so a stalled peer frees its goroutine (and the sibling copy,
// via the shared force-close) after the idle window instead of forever.
// Connections whose implementation ignores deadlines still unblock through
// the peer direction closing.
func relayWithIdleTimeout(dst, src net.Conn, timeout time.Duration) {
	buf := make([]byte, 32*1024)
	for {
		now := time.Now()
		_ = src.SetReadDeadline(now.Add(timeout))
		_ = dst.SetWriteDeadline(now.Add(timeout))
		n, rerr := src.Read(buf)
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
		}
		if rerr != nil {
			return
		}
	}
}

func (s *SOCKS5Server) handleUDPAssociate(clientConn net.Conn, endpointTimeout time.Duration) {
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		utils.Debugf("[SOCKS5] UDP ASSOCIATE listen failed: %v", err)
		clientConn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer udpConn.Close()

	addr := udpConn.LocalAddr().(*net.UDPAddr)
	port := uint16(addr.Port)
	clientConn.Write([]byte{
		0x05, 0x00, 0x00, 0x01,
		127, 0, 0, 1,
		byte(port >> 8), byte(port),
	})
	utils.Debugf("[SOCKS5] UDP ASSOCIATE dns relay on %s", addr.String())

	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, clientConn)
		close(done)
		_ = udpConn.Close()
	}()

	packet := make([]byte, 4096)
	for {
		select {
		case <-done:
			return
		default:
		}

		// A UDP associate is cheap to recreate, so silence is treated as
		// death: gvisor creates one associate per UDP tunnel and keeps the
		// control connection open indefinitely, so keeping idle associates
		// alive pin slots (each with a socket + goroutine) and starve new
		// flows - a single stuck batch exhausted the UDP cap and killed
		// DNS on device. Idle endpoints are reaped; the next datagram
		// transparently negotiates a fresh associate.
		_ = udpConn.SetReadDeadline(time.Now().Add(endpointTimeout))
		n, clientAddr, err := udpConn.ReadFromUDP(packet)
		if err != nil {
			select {
			case <-done:
			default:
				var netErr net.Error
				if errors.As(err, &netErr) && netErr.Timeout() {
					utils.Debugf("[SOCKS5] UDP associate idle for %s, reaping", endpointTimeout)
				}
			}
			return
		}
		response, err := s.handleSOCKS5UDPDatagram(packet[:n])
		if err != nil {
			// gvisor creates one UDP tunnel per destination: a tunnel whose
			// first datagram targets a non-DNS port (QUIC :443 churn, etc.)
			// can never carry useful traffic through this DNS-only relay,
			// yet every such datagram refreshed the associate's idle window
			// and pinned the slot forever - on device that filled the UDP
			// cap and starved DNS. Reap it on first sight instead; gvisor
			// tears the flow down on the next write error and would create
			// a fresh associate for any genuinely useful tunnel.
			var derr *dgramError
			if errors.As(err, &derr) && derr.terminal {
				utils.Debugf("[SOCKS5] UDP associate targets port %d (not DNS), reaping", derr.port)
				return
			}
			utils.Debugf("[SOCKS5] UDP datagram ignored: %v", err)
			continue
		}
		_, _ = udpConn.WriteToUDP(response, clientAddr)
	}
}

// dgramError classifies a rejected datagram: terminal when the tunnel can
// never become useful (non-DNS destination port), transient otherwise.
type dgramError struct {
	port     uint16
	terminal bool
	msg      string
}

func (e *dgramError) Error() string { return e.msg }

func (s *SOCKS5Server) handleSOCKS5UDPDatagram(packet []byte) ([]byte, error) {
	if len(packet) < 10 || packet[0] != 0 || packet[1] != 0 || packet[2] != 0 {
		return nil, fmt.Errorf("invalid UDP header")
	}
	if packet[3] != 0x01 {
		return nil, &dgramError{terminal: true, msg: "only IPv4 UDP targets are supported"}
	}
	port := binary.BigEndian.Uint16(packet[8:10])
	if port != 53 {
		return nil, &dgramError{port: port, terminal: true,
			msg: fmt.Sprintf("only DNS UDP/53 is supported, got %d", port)}
	}
	dnsPayload := packet[10:]
	dnsResponse, err := resolveDNSQuery(dnsPayload)
	if err != nil {
		return nil, err
	}

	response := make([]byte, 10+len(dnsResponse))
	copy(response[:10], packet[:10])
	copy(response[10:], dnsResponse)
	return response, nil
}

func resolveDNSQuery(query []byte) ([]byte, error) {
	if len(query) < 12 {
		return nil, fmt.Errorf("short DNS query")
	}
	qdCount := binary.BigEndian.Uint16(query[4:6])
	if qdCount == 0 {
		return dnsErrorResponse(query, 1), nil
	}

	name, qEnd, err := parseDNSQuestionName(query, 12)
	if err != nil {
		return dnsErrorResponse(query, 1), nil
	}
	if qEnd+4 > len(query) {
		return dnsErrorResponse(query, 1), nil
	}
	qType := binary.BigEndian.Uint16(query[qEnd : qEnd+2])
	question := query[12 : qEnd+4]

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", name)
	if err != nil {
		utils.Debugf("[SOCKS5] DNS lookup failed for %s: %v", name, err)
		return dnsErrorResponse(query, 3), nil
	}

	answers := make([]byte, 0)
	answerCount := 0
	for _, ip := range ips {
		if qType == 1 {
			v4 := ip.To4()
			if v4 == nil {
				continue
			}
			answers = appendDNSAnswer(answers, qType, v4)
			answerCount++
		} else if qType == 28 {
			v6 := ip.To16()
			if v6 == nil || ip.To4() != nil {
				continue
			}
			answers = appendDNSAnswer(answers, qType, v6)
			answerCount++
		}
	}

	response := make([]byte, 12, 12+len(question)+len(answers))
	copy(response[0:2], query[0:2])
	binary.BigEndian.PutUint16(response[2:4], 0x8180)
	binary.BigEndian.PutUint16(response[4:6], 1)
	binary.BigEndian.PutUint16(response[6:8], uint16(answerCount))
	binary.BigEndian.PutUint16(response[8:10], 0)
	binary.BigEndian.PutUint16(response[10:12], 0)
	response = append(response, question...)
	response = append(response, answers...)
	return response, nil
}

func parseDNSQuestionName(packet []byte, offset int) (string, int, error) {
	labels := make([]byte, 0)
	for {
		if offset >= len(packet) {
			return "", offset, fmt.Errorf("name out of bounds")
		}
		l := int(packet[offset])
		offset++
		if l == 0 {
			break
		}
		if l&0xC0 != 0 || offset+l > len(packet) {
			return "", offset, fmt.Errorf("unsupported compressed/invalid name")
		}
		if len(labels) > 0 {
			labels = append(labels, '.')
		}
		labels = append(labels, packet[offset:offset+l]...)
		offset += l
	}
	return string(labels), offset, nil
}

func appendDNSAnswer(dst []byte, qType uint16, ip []byte) []byte {
	// Name pointer to the first question name at offset 12.
	dst = append(dst, 0xC0, 0x0C)
	tmp := make([]byte, 10)
	binary.BigEndian.PutUint16(tmp[0:2], qType)
	binary.BigEndian.PutUint16(tmp[2:4], 1)  // IN
	binary.BigEndian.PutUint32(tmp[4:8], 60) // TTL
	binary.BigEndian.PutUint16(tmp[8:10], uint16(len(ip)))
	dst = append(dst, tmp...)
	dst = append(dst, ip...)
	return dst
}

func dnsErrorResponse(query []byte, rcode uint16) []byte {
	response := make([]byte, 12)
	copy(response[0:2], query[0:2])
	binary.BigEndian.PutUint16(response[2:4], 0x8180|rcode)
	if len(query) >= 6 {
		copy(response[4:6], query[4:6])
	}
	return response
}
