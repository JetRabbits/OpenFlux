package socks5

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"openflux/utils"
)

type Dialer interface {
	DialTCP(address string) (net.Conn, error)
}

// UDPDialer is optional, preserving compatibility with TCP-only integrations.
type UDPDialer interface {
	DialUDP(address string) (net.Conn, error)
}

const (
	DefaultMaxTCPFlows        = 48
	DefaultMaxUDPFlows        = 64
	DefaultMaxTotalFlows      = 112
	DefaultHandshakeTimeout   = 10 * time.Second
	DefaultSessionIdleTimeout = 75 * time.Second
	DefaultUDPEndpointTimeout = 15 * time.Second
	DefaultSlotWaitTimeout    = 30 * time.Second
	DefaultDialTimeout        = 20 * time.Second
)

type flowLimits struct {
	maxTCP      int
	maxUDP      int
	maxTotal    int
	handshake   time.Duration
	idle        time.Duration
	udpEndpoint time.Duration
	slotWait    time.Duration
	dialTimeout time.Duration
}

type SOCKS5Server struct {
	listenAddr string
	dialer     Dialer

	mu       sync.Mutex
	listener net.Listener
	closed   bool
	clients  map[net.Conn]struct{}
	limits   flowLimits

	activeTCP  atomic.Int32
	activeUDP  atomic.Int32
	refusedTCP atomic.Uint64
	refusedUDP atomic.Uint64
}

func NewSOCKS5Server(addr string, dialer Dialer) *SOCKS5Server {
	return &SOCKS5Server{
		listenAddr: addr,
		dialer:     dialer,
		clients:    make(map[net.Conn]struct{}),
		limits: flowLimits{
			maxTCP:      DefaultMaxTCPFlows,
			maxUDP:      DefaultMaxUDPFlows,
			maxTotal:    DefaultMaxTotalFlows,
			handshake:   DefaultHandshakeTimeout,
			idle:        DefaultSessionIdleTimeout,
			udpEndpoint: DefaultUDPEndpointTimeout,
			slotWait:    DefaultSlotWaitTimeout,
			dialTimeout: DefaultDialTimeout,
		},
	}
}

func (s *SOCKS5Server) SetFlowLimits(maxTCP, maxUDP, maxTotal int, handshake, idle, udpEndpoint, slotWait, dialTimeout time.Duration) {
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
	if slotWait > 0 {
		s.limits.slotWait = slotWait
	}
	if dialTimeout > 0 {
		s.limits.dialTimeout = dialTimeout
	}
}

func (s *SOCKS5Server) ActiveTCPFlows() int     { return int(s.activeTCP.Load()) }
func (s *SOCKS5Server) ActiveUDPFlows() int     { return int(s.activeUDP.Load()) }
func (s *SOCKS5Server) ActiveTotalFlows() int   { return int(s.activeTCP.Load() + s.activeUDP.Load()) }
func (s *SOCKS5Server) RefusedTCPFlows() uint64 { return s.refusedTCP.Load() }
func (s *SOCKS5Server) RefusedUDPFlows() uint64 { return s.refusedUDP.Load() }

// Bind reserves the listen address so callers can detect "address already in
// use" synchronously, before serving. Safe to call once; Start binds lazily if
// it wasn't called.
func (s *SOCKS5Server) Bind() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return net.ErrClosed
	}
	if s.listener != nil {
		return nil
	}
	listener, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		return err
	}
	s.listener = listener
	return nil
}

func (s *SOCKS5Server) Start() error {
	if err := s.Bind(); err != nil {
		return err
	}

	s.mu.Lock()
	listener := s.listener
	s.mu.Unlock()
	defer listener.Close()

	utils.Debugf("[SOCKS5] Listening on %s", s.listenAddr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed {
				utils.Debugf("[SOCKS5] Listener closed, stopping")
				return net.ErrClosed
			}
			utils.Debugf("[SOCKS5] Accept error: %v", err)
			continue
		}
		go s.handleConnection(conn)
	}
}

// StartInBackground binds synchronously, then serves until Close is called.
func (s *SOCKS5Server) StartInBackground() error {
	if err := s.Bind(); err != nil {
		return err
	}
	utils.SafeGo("socks5.accept", func() {
		if err := s.Start(); err != nil && !errors.Is(err, net.ErrClosed) {
			utils.Debugf("[SOCKS5] background server stopped: %v", err)
		}
	})
	return nil
}

// Close stops the server, unblocking Start's accept loop.
func (s *SOCKS5Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	for conn := range s.clients {
		_ = conn.Close()
	}
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

func (s *SOCKS5Server) handleConnection(clientConn net.Conn) {
	s.mu.Lock()
	handshake := s.limits.handshake
	if s.closed || len(s.clients) >= 256 {
		s.mu.Unlock()
		_ = clientConn.Close()
		return
	}
	if s.clients == nil {
		s.clients = make(map[net.Conn]struct{})
	}
	s.clients[clientConn] = struct{}{}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.clients, clientConn)
		s.mu.Unlock()
	}()
	_ = clientConn.SetDeadline(time.Now().Add(handshake))
	// A malformed request must never crash the host process; contain any
	// panic to this connection.
	defer func() {
		if r := recover(); r != nil {
			utils.Debugf("[SOCKS5] Recovered from panic in handler: %v", r)
		}
	}()
	defer clientConn.Close()

	var greeting [2]byte
	if _, err := io.ReadFull(clientConn, greeting[:]); err != nil || greeting[0] != 0x05 {
		return
	}
	methods := make([]byte, int(greeting[1]))
	if _, err := io.ReadFull(clientConn, methods); err != nil {
		return
	}
	noAuth := false
	for _, method := range methods {
		if method == 0x00 {
			noAuth = true
			break
		}
	}
	if !noAuth {
		_, _ = clientConn.Write([]byte{0x05, 0xff})
		return
	}
	if _, err := clientConn.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	var request [4]byte
	if _, err := io.ReadFull(clientConn, request[:]); err != nil || request[0] != 0x05 || request[2] != 0 {
		return
	}
	targetAddr, err := readAddress(clientConn, request[3])
	if err != nil {
		writeReply(clientConn, 0x08, nil)
		return
	}

	_ = clientConn.SetDeadline(time.Time{})
	switch request[1] {
	case 0x01:
		if !s.reserveFlow(false) {
			s.refusedTCP.Add(1)
			utils.Debugf("[SOCKS5] TCP flow cap reached, rejecting CONNECT %s", targetAddr)
			writeReply(clientConn, 0x02, nil)
			return
		}
		defer s.releaseFlow(false)
		s.handleConnect(clientConn, targetAddr)
	case 0x03:
		if !s.reserveFlow(true) {
			s.refusedUDP.Add(1)
			utils.Debugf("[SOCKS5] UDP flow cap reached, rejecting ASSOCIATE")
			writeReply(clientConn, 0x02, nil)
			return
		}
		defer s.releaseFlow(true)
		s.handleUDPAssociate(clientConn, targetAddr)
	default:
		writeReply(clientConn, 0x07, nil)
	}
}

func (s *SOCKS5Server) handleConnect(clientConn net.Conn, targetAddr string) {

	utils.Debugf("[SOCKS5] CONNECT %s", targetAddr)

	targetConn, err := s.dialWithTimeout(targetAddr)
	if err != nil {
		utils.Debugf("[SOCKS5] Dial failed: %v", err)
		writeReply(clientConn, 0x04, nil)
		return
	}
	defer targetConn.Close()

	if err := writeReply(clientConn, 0x00, targetConn.LocalAddr()); err != nil {
		return
	}

	idle := s.sessionIdleTimeout()
	var wg sync.WaitGroup
	wg.Add(2)
	var lastActivity atomic.Int64
	lastActivity.Store(time.Now().UnixNano())
	stalled := func() bool {
		return time.Since(time.Unix(0, lastActivity.Load())) > idle
	}
	finish := func() {
		_ = clientConn.Close()
		_ = targetConn.Close()
	}
	watchDone := make(chan struct{})
	defer close(watchDone)
	utils.SafeGo("socks5.tcp-idle", func() {
		tick := idle / 4
		if tick <= 0 {
			tick = time.Second
		}
		ticker := time.NewTicker(tick)
		defer ticker.Stop()
		for {
			select {
			case <-watchDone:
				return
			case <-ticker.C:
				if stalled() {
					finish()
					return
				}
			}
		}
	})

	go func() {
		defer wg.Done()
		defer finish()
		relayWithSessionIdle(targetConn, clientConn, idle, func(n int) {
			lastActivity.Store(time.Now().UnixNano())
		}, stalled)
	}()

	go func() {
		defer wg.Done()
		defer finish()
		relayWithSessionIdle(clientConn, targetConn, idle, func(n int) {
			lastActivity.Store(time.Now().UnixNano())
		}, stalled)
	}()

	wg.Wait()
}

func (s *SOCKS5Server) dialWithTimeout(targetAddr string) (net.Conn, error) {
	timeout := s.dialTimeout()
	type result struct {
		conn net.Conn
		err  error
	}
	ch := make(chan result, 1)
	utils.SafeGo("socks5.dial", func() {
		conn, err := s.dialer.DialTCP(targetAddr)
		ch <- result{conn: conn, err: err}
	})
	select {
	case r := <-ch:
		return r.conn, r.err
	case <-time.After(timeout):
		utils.SafeGo("socks5.dial-cleanup", func() {
			r := <-ch
			if r.conn != nil {
				_ = r.conn.Close()
			}
		})
		return nil, fmt.Errorf("dial %s timed out after %s", targetAddr, timeout)
	}
}

func (s *SOCKS5Server) sessionIdleTimeout() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.limits.idle
}

func (s *SOCKS5Server) udpEndpointTimeout() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.limits.udpEndpoint
}

func (s *SOCKS5Server) dialTimeout() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.limits.dialTimeout
}

func (s *SOCKS5Server) slotWait() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.limits.slotWait
}

func (s *SOCKS5Server) reserveFlow(udp bool) bool {
	deadline := time.Now().Add(s.slotWait())
	for {
		if s.tryReserveFlow(udp) {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func (s *SOCKS5Server) tryReserveFlow(udp bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	tcp, udpCount := s.activeTCP.Load(), s.activeUDP.Load()
	if int(tcp+udpCount) >= s.limits.maxTotal {
		return false
	}
	if udp {
		if int(udpCount) >= s.limits.maxUDP {
			return false
		}
		s.activeUDP.Add(1)
		return true
	}
	if int(tcp) >= s.limits.maxTCP {
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

const relayBufferSize = 8 * 1024

var relayBufferPool = sync.Pool{New: func() any { b := make([]byte, relayBufferSize); return &b }}

func relayWithSessionIdle(dst, src net.Conn, timeout time.Duration, bump func(int), stalled func() bool) {
	bufp := relayBufferPool.Get().(*[]byte)
	defer relayBufferPool.Put(bufp)
	buf := *bufp
	for {
		_ = src.SetReadDeadline(time.Now().Add(timeout))
		n, rerr := src.Read(buf)
		if n > 0 {
			bump(n)
			_ = dst.SetWriteDeadline(time.Now().Add(timeout))
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
			if stalled() {
				continue
			}
		}
		if rerr != nil {
			return
		}
	}
}

func (s *SOCKS5Server) handleUDPAssociate(control net.Conn, requestedAddr string) {
	endpointTimeout := s.udpEndpointTimeout()
	dialer, ok := s.dialer.(UDPDialer)
	if !ok {
		_ = writeReply(control, 0x07, nil)
		return
	}
	requestedHost, requestedService, err := net.SplitHostPort(requestedAddr)
	if err != nil {
		_ = writeReply(control, 0x08, nil)
		return
	}
	requestedIP := net.ParseIP(requestedHost)
	var requestedPort int
	_, _ = fmt.Sscanf(requestedService, "%d", &requestedPort)
	// Do not resolve the association's source address using local DNS.
	if requestedIP == nil {
		_ = writeReply(control, 0x08, nil)
		return
	}
	bindIP := net.ParseIP("127.0.0.1")
	if host, _, err := net.SplitHostPort(control.LocalAddr().String()); err == nil {
		if parsed := net.ParseIP(host); parsed != nil {
			bindIP = parsed
		}
	}
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: bindIP})
	if err != nil {
		writeReply(control, 0x01, nil)
		return
	}
	defer udpConn.Close()

	type udpFlow struct{ conn net.Conn }
	flows := make(map[string]udpFlow)
	var flowsMu sync.Mutex
	var closing bool
	var clientAddr *net.UDPAddr
	var clientMu sync.RWMutex
	expectedIP := net.ParseIP("127.0.0.1")
	if host, _, err := net.SplitHostPort(control.RemoteAddr().String()); err == nil {
		expectedIP = net.ParseIP(host)
	}
	if expectedIP == nil || (!requestedIP.IsUnspecified() && !requestedIP.Equal(expectedIP)) {
		_ = writeReply(control, 0x02, nil)
		return
	}
	if err := writeReply(control, 0x00, udpConn.LocalAddr()); err != nil {
		return
	}
	_ = control.SetReadDeadline(time.Now().Add(endpointTimeout))
	defer func() {
		_ = udpConn.Close()
		flowsMu.Lock()
		defer flowsMu.Unlock()
		closing = true
		for _, flow := range flows {
			_ = flow.conn.Close()
		}
	}()

	utils.SafeGo("socks5.udp", func() {
		buf := make([]byte, 65535)
		for {
			_ = udpConn.SetReadDeadline(time.Now().Add(endpointTimeout))
			n, from, err := udpConn.ReadFromUDP(buf)
			if err != nil {
				var netErr net.Error
				if errors.As(err, &netErr) && netErr.Timeout() {
					utils.Debugf("[SOCKS5] UDP associate idle for %s, reaping", endpointTimeout)
				}
				_ = control.Close()
				return
			}
			_ = control.SetReadDeadline(time.Now().Add(endpointTimeout))
			if !from.IP.Equal(expectedIP) || (requestedPort != 0 && from.Port != requestedPort) {
				continue
			}
			clientMu.RLock()
			pinnedClient := clientAddr
			clientMu.RUnlock()
			if pinnedClient != nil &&
				(!from.IP.Equal(pinnedClient.IP) || from.Port != pinnedClient.Port) {
				continue
			}
			dest, payload, err := parseUDPRequest(buf[:n])
			if err != nil {
				continue
			}
			clientMu.Lock()
			clientAddr = from
			clientMu.Unlock()

			flowsMu.Lock()
			if closing {
				flowsMu.Unlock()
				return
			}
			flow, ok := flows[dest]
			if !ok {
				if len(flows) >= 256 {
					flowsMu.Unlock()
					continue
				}
				// Dial outside the lock so shutdown can close existing flows.
				flowsMu.Unlock()
				conn, err := dialer.DialUDP(dest)
				flowsMu.Lock()
				if err != nil {
					flowsMu.Unlock()
					continue
				}
				if closing {
					flowsMu.Unlock()
					_ = conn.Close()
					return
				}
				flow = udpFlow{conn: conn}
				flows[dest] = flow
				_ = conn.SetReadDeadline(time.Now().Add(endpointTimeout))
				flowKey := dest
				utils.SafeGo("socks5.udp-response", func() {
					defer func() {
						_ = conn.Close()
						flowsMu.Lock()
						if current, ok := flows[flowKey]; ok && current.conn == conn {
							delete(flows, flowKey)
						}
						flowsMu.Unlock()
					}()
					response := make([]byte, 65535)
					for {
						n, err := conn.Read(response)
						if err != nil {
							return
						}
						_ = conn.SetReadDeadline(time.Now().Add(endpointTimeout))
						packet := makeUDPResponse(conn.RemoteAddr(), response[:n])
						clientMu.RLock()
						to := clientAddr
						clientMu.RUnlock()
						if to != nil {
							_ = udpConn.SetWriteDeadline(time.Now().Add(10 * time.Second))
							_, _ = udpConn.WriteToUDP(packet, to)
						}
					}
				})
			}
			flowsMu.Unlock()
			_ = flow.conn.SetReadDeadline(time.Now().Add(endpointTimeout))
			_ = flow.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if _, err := flow.conn.Write(payload); err != nil {
				_ = flow.conn.Close()
				flowsMu.Lock()
				if current, ok := flows[dest]; ok && current.conn == flow.conn {
					delete(flows, dest)
				}
				flowsMu.Unlock()
			}
		}
	})

	_, _ = io.Copy(io.Discard, control)
}

func readAddress(r io.Reader, atyp byte) (string, error) {
	var host string
	switch atyp {
	case 0x01:
		buf := make([]byte, 4)
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", err
		}
		host = net.IP(buf).String()
	case 0x03:
		var size [1]byte
		if _, err := io.ReadFull(r, size[:]); err != nil || size[0] == 0 {
			return "", fmt.Errorf("invalid domain length")
		}
		buf := make([]byte, int(size[0]))
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", err
		}
		host = string(buf)
	case 0x04:
		buf := make([]byte, 16)
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", err
		}
		host = net.IP(buf).String()
	default:
		return "", fmt.Errorf("unsupported address type %d", atyp)
	}
	var port [2]byte
	if _, err := io.ReadFull(r, port[:]); err != nil {
		return "", err
	}
	return net.JoinHostPort(host, fmt.Sprintf("%d", binary.BigEndian.Uint16(port[:]))), nil
}

func writeReply(w io.Writer, code byte, addr net.Addr) error {
	reply := append([]byte{0x05, code, 0x00}, encodeAddress(addr)...)
	_, err := w.Write(reply)
	return err
}

func addressString(addr net.Addr) string {
	if addr == nil {
		return "0.0.0.0:0"
	}
	return addr.String()
}

func parseUDPRequest(packet []byte) (string, []byte, error) {
	if len(packet) < 4 || packet[0] != 0 || packet[1] != 0 || packet[2] != 0 {
		return "", nil, fmt.Errorf("invalid or fragmented SOCKS5 UDP packet")
	}
	r := &sliceReader{data: packet[4:]}
	addr, err := readAddress(r, packet[3])
	if err != nil {
		return "", nil, err
	}
	return addr, r.data, nil
}

type sliceReader struct{ data []byte }

func (r *sliceReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	return n, nil
}

func makeUDPResponse(addr net.Addr, payload []byte) []byte {
	out := append([]byte{0, 0, 0}, encodeAddress(addr)...)
	return append(out, payload...)
}

func encodeAddress(addr net.Addr) []byte {
	ip := net.IPv4zero.To4()
	atyp := byte(0x01)
	port := 0
	if host, service, err := net.SplitHostPort(addressString(addr)); err == nil {
		if parsed := net.ParseIP(host); parsed != nil {
			if v4 := parsed.To4(); v4 != nil {
				ip = v4
			} else {
				ip, atyp = parsed.To16(), 0x04
			}
		}
		fmt.Sscanf(service, "%d", &port)
	}
	out := append([]byte{atyp}, ip...)
	return append(out, byte(port>>8), byte(port))
}
