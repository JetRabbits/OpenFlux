package socks5

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"universal-bypass-tool/utils"
)

type Dialer interface {
	DialTCP(address string) (net.Conn, error)
}

type SOCKS5Server struct {
	listenAddr string
	dialer     Dialer

	mu       sync.Mutex
	listener net.Listener
	closed   bool
}

func NewSOCKS5Server(addr string, dialer Dialer) *SOCKS5Server {
	return &SOCKS5Server{listenAddr: addr, dialer: dialer}
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

	if buf[1] == 0x03 {
		s.handleUDPAssociate(clientConn)
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

	targetConn, err := s.dialer.DialTCP(targetAddr)
	if err != nil {
		utils.Debugf("[SOCKS5] Dial failed: %v", err)
		clientConn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return
	}
	defer targetConn.Close()

	clientConn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		defer targetConn.Close()
		io.Copy(targetConn, clientConn)
	}()

	go func() {
		defer wg.Done()
		defer clientConn.Close()
		io.Copy(clientConn, targetConn)
	}()

	wg.Wait()
}

func (s *SOCKS5Server) handleUDPAssociate(clientConn net.Conn) {
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

		n, clientAddr, err := udpConn.ReadFromUDP(packet)
		if err != nil {
			return
		}
		response, err := s.handleSOCKS5UDPDatagram(packet[:n])
		if err != nil {
			utils.Debugf("[SOCKS5] UDP datagram ignored: %v", err)
			continue
		}
		_, _ = udpConn.WriteToUDP(response, clientAddr)
	}
}

func (s *SOCKS5Server) handleSOCKS5UDPDatagram(packet []byte) ([]byte, error) {
	if len(packet) < 10 || packet[0] != 0 || packet[1] != 0 || packet[2] != 0 {
		return nil, fmt.Errorf("invalid UDP header")
	}
	if packet[3] != 0x01 {
		return nil, fmt.Errorf("only IPv4 UDP targets are supported")
	}
	port := binary.BigEndian.Uint16(packet[8:10])
	if port != 53 {
		return nil, fmt.Errorf("only DNS UDP/53 is supported, got %d", port)
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
