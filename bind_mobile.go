package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"universal-bypass-tool/socks5"
	"universal-bypass-tool/transport"
	"universal-bypass-tool/transport/oneme"
	"universal-bypass-tool/transport/yandex"
	"universal-bypass-tool/tunnel"
	"universal-bypass-tool/utils"

	t2core "github.com/xjasonlyu/tun2socks/v2/core"
	t2device "github.com/xjasonlyu/tun2socks/v2/core/device"
	"github.com/xjasonlyu/tun2socks/v2/core/device/fdbased"
	"github.com/xjasonlyu/tun2socks/v2/core/device/iobased"
	t2option "github.com/xjasonlyu/tun2socks/v2/core/option"
	t2proxy "github.com/xjasonlyu/tun2socks/v2/proxy"
	_ "github.com/xjasonlyu/tun2socks/v2/proxy/socks5"
	t2tunnel "github.com/xjasonlyu/tun2socks/v2/tunnel"
	"github.com/xjasonlyu/tun2socks/v2/tunnel/statistic"
	gvstack "gvisor.dev/gvisor/pkg/tcpip/stack"
)

// iOS NetworkExtension packet-tunnel processes run under a very small jetsam
// budget. Keep the packet-flow queues small and drop under backpressure
// rather than growing unbounded — TCP/QUIC will recover, and this mirrors the
// proven-safe queue sizing already used by libgalactic_tun.so's own
// packet-flow bridge for Cordyceps.
const (
	fluxPacketFlowInboundQueueCapacity  = 256
	fluxPacketFlowOutboundQueueCapacity = 256
)

type mobileClientState struct {
	transport transport.Transport
	tunnel    *tunnel.TCPTunnel
	socks     *socks5.SOCKS5Server
	startedAt time.Time
}

var mobileState struct {
	sync.Mutex
	client *mobileClientState
}

// fluxTun2SocksState holds the Android TUN<->local-SOCKS5 bridge for Flux.
//
// This is intentionally implemented here, inside libopenflux.so, rather than
// by calling into the separate libgalactic_tun.so shared library (which has
// its own, structurally identical StartTun2SocksWithFd/StopTun2Socks). Both
// are Go-compiled shared libraries (buildmode=c-shared); loading TWO
// independent Go runtimes into one Android process corrupts each other's cgo
// callback bookkeeping and reproducibly crashes the process (observed:
// "fatal error: unknown caller pc" on essentially any libgalactic_tun.so
// call, including no-op ones, once libopenflux.so is also loaded). Keeping
// the whole Flux data path — carrier client, local SOCKS5 server, and now
// the TUN bridge — inside this single Go runtime avoids that class of bug
// entirely: StopFluxTun2Socks() below can safely call device.Close() exactly
// once, synchronously, because there is no second Go runtime to conflict
// with.
type fluxTun2SocksClient struct {
	device t2device.Device
	stack  *gvstack.Stack
	// packetRW is non-nil only for the iOS NetworkExtension packet-flow
	// variant (StartFluxTun2SocksPacketFlow); the Android fd-based variant
	// (StartFluxTun2SocksWithFd) leaves it nil.
	packetRW *fluxPacketFlowReadWriter
}

var fluxTun2Socks struct {
	sync.Mutex
	client *fluxTun2SocksClient
}

// fluxPacketFlowReadWriter adapts NEPacketTunnelFlow-style packet
// injection/read calls (iOS) into an io.ReadWriter usable by
// tun2socks/v2's iobased.Endpoint, mirroring libgalactic_tun.so's
// packetFlowReadWriter used for the Cordyceps path on iOS.
type fluxPacketFlowReadWriter struct {
	inbound    chan []byte
	outbound   chan []byte
	closed     chan struct{}
	once       sync.Once
	closedFlag uint32
}

func newFluxPacketFlowReadWriter() *fluxPacketFlowReadWriter {
	return &fluxPacketFlowReadWriter{
		inbound:  make(chan []byte, fluxPacketFlowInboundQueueCapacity),
		outbound: make(chan []byte, fluxPacketFlowOutboundQueueCapacity),
		closed:   make(chan struct{}),
	}
}

func (rw *fluxPacketFlowReadWriter) Read(p []byte) (int, error) {
	if atomic.LoadUint32(&rw.closedFlag) != 0 {
		return 0, fmt.Errorf("flux packet flow closed")
	}
	select {
	case pkt := <-rw.inbound:
		if atomic.LoadUint32(&rw.closedFlag) != 0 {
			return 0, fmt.Errorf("flux packet flow closed")
		}
		return copy(p, pkt), nil
	case <-rw.closed:
		return 0, fmt.Errorf("flux packet flow closed")
	}
}

func (rw *fluxPacketFlowReadWriter) Write(p []byte) (int, error) {
	if atomic.LoadUint32(&rw.closedFlag) != 0 {
		return 0, fmt.Errorf("flux packet flow closed")
	}
	pkt := append([]byte(nil), p...)
	select {
	case <-rw.closed:
		return 0, fmt.Errorf("flux packet flow closed")
	default:
	}
	select {
	case rw.outbound <- pkt:
		return len(p), nil
	case <-rw.closed:
		return 0, fmt.Errorf("flux packet flow closed")
	default:
		// Drop under backpressure but report success so gVisor drains its
		// hidden endpoint queue instead of accumulating packets internally.
		return len(p), nil
	}
}

func (rw *fluxPacketFlowReadWriter) Close() {
	rw.once.Do(func() {
		atomic.StoreUint32(&rw.closedFlag, 1)
		close(rw.closed)
	})
}

func (rw *fluxPacketFlowReadWriter) Inject(pkt []byte) error {
	if atomic.LoadUint32(&rw.closedFlag) != 0 {
		return fmt.Errorf("flux packet flow closed")
	}
	copyPkt := append([]byte(nil), pkt...)
	select {
	case <-rw.closed:
		return fmt.Errorf("flux packet flow closed")
	default:
	}
	select {
	case rw.inbound <- copyPkt:
		return nil
	case <-rw.closed:
		return fmt.Errorf("flux packet flow closed")
	default:
		// Drop under backpressure; TCP will recover and this avoids blocking
		// the NetworkExtension read loop indefinitely.
		return nil
	}
}

func (rw *fluxPacketFlowReadWriter) ReadOutbound() ([]byte, error) {
	if atomic.LoadUint32(&rw.closedFlag) != 0 {
		return nil, fmt.Errorf("flux packet flow closed")
	}
	select {
	case pkt := <-rw.outbound:
		if atomic.LoadUint32(&rw.closedFlag) != 0 {
			return nil, fmt.Errorf("flux packet flow closed")
		}
		return pkt, nil
	case <-rw.closed:
		return nil, fmt.Errorf("flux packet flow closed")
	}
}

func (rw *fluxPacketFlowReadWriter) TryReadOutbound() ([]byte, error) {
	if atomic.LoadUint32(&rw.closedFlag) != 0 {
		return nil, fmt.Errorf("flux packet flow closed")
	}
	select {
	case pkt := <-rw.outbound:
		if atomic.LoadUint32(&rw.closedFlag) != 0 {
			return nil, fmt.Errorf("flux packet flow closed")
		}
		return pkt, nil
	case <-rw.closed:
		return nil, fmt.Errorf("flux packet flow closed")
	default:
		return nil, nil
	}
}

// fluxPacketFlowDevice adapts iobased.Endpoint to tun2socks/v2's
// t2device.Device interface (Name/Type on top of the embedded Endpoint).
type fluxPacketFlowDevice struct {
	*iobased.Endpoint
}

func (d *fluxPacketFlowDevice) Name() string { return "fluxpacketflow" }
func (d *fluxPacketFlowDevice) Type() string { return "fluxpacketflow" }

func fluxTun2SocksStackOptions() []t2option.Option {
	return []t2option.Option{
		t2option.WithTCPModerateReceiveBuffer(true),
	}
}

// StartFluxTun2SocksWithFd bridges an Android VpnService TUN fd to the local
// OpenFlux SOCKS5 endpoint started by StartOpenFluxClient. Idempotent: an
// existing bridge is torn down (closed) before the new one is created.
//
//export StartFluxTun2SocksWithFd
func StartFluxTun2SocksWithFd(tunFd C.int, socksAddrC *C.char, mtuC C.int) *C.char {
	socksAddr := strings.TrimSpace(cstr(socksAddrC))
	if socksAddr == "" {
		socksAddr = "127.0.0.1:1080"
	}
	mtu := int(mtuC)
	if mtu <= 0 {
		mtu = 1500
	}

	fluxTun2Socks.Lock()
	defer fluxTun2Socks.Unlock()

	stopFluxTun2SocksLocked()
	statistic.DefaultManager.ResetStatistic()

	// Align the OpenFlux carrier-side netstack's MTU with the real MTU used
	// on the Android TUN / SOCKS side, instead of leaving it at
	// tunnel.TunnelLinkEndpoint's old hardcoded 1500 regardless of what was
	// actually configured. This determines the TCP MSS (and therefore packet
	// sizes framed into trans.Send()) for connections relayed through this
	// bridge — see TCPTunnel.SetMTU()'s doc comment.
	mobileState.Lock()
	client := mobileState.client
	mobileState.Unlock()
	if client != nil && client.tunnel != nil {
		client.tunnel.SetMTU(uint32(mtu))
	}

	dev, err := fdbased.Open(strconv.Itoa(int(tunFd)), uint32(mtu), 0)
	if err != nil {
		return cStringOrNil(fmt.Sprintf("open fd device: %v", err))
	}

	proxyURL, err := url.Parse("socks5://" + socksAddr)
	if err != nil {
		dev.Close()
		return cStringOrNil(fmt.Sprintf("parse socks proxy: %v", err))
	}
	proxy, err := t2proxy.Parse(proxyURL)
	if err != nil {
		dev.Close()
		return cStringOrNil(fmt.Sprintf("create socks proxy: %v", err))
	}

	handler := t2tunnel.New(proxy, statistic.DefaultManager)
	handler.ProcessAsync()

	stk, err := t2core.CreateStack(&t2core.Config{
		LinkEndpoint:     dev,
		TransportHandler: handler,
		Options:          fluxTun2SocksStackOptions(),
	})
	if err != nil {
		handler.Close()
		dev.Close()
		return cStringOrNil(fmt.Sprintf("create tun2socks stack: %v", err))
	}

	fluxTun2Socks.client = &fluxTun2SocksClient{device: dev, stack: stk}
	return nil
}

// StartFluxTun2SocksPacketFlow starts the Flux TUN<->SOCKS5 bridge backed by
// packet injection/read exports instead of a raw fd. Use this on iOS, where
// NetworkExtension exposes NEPacketTunnelFlow rather than a TUN file
// descriptor. Idempotent: an existing bridge (fd-based or packet-flow) is
// torn down before the new one is created.
//
//export StartFluxTun2SocksPacketFlow
func StartFluxTun2SocksPacketFlow(socksAddrC *C.char, mtuC C.int) *C.char {
	socksAddr := strings.TrimSpace(cstr(socksAddrC))
	if socksAddr == "" {
		socksAddr = "127.0.0.1:1080"
	}
	mtu := int(mtuC)
	if mtu <= 0 {
		mtu = 1500
	}

	fluxTun2Socks.Lock()
	defer fluxTun2Socks.Unlock()

	stopFluxTun2SocksLocked()
	statistic.DefaultManager.ResetStatistic()

	mobileState.Lock()
	client := mobileState.client
	mobileState.Unlock()
	if client != nil && client.tunnel != nil {
		client.tunnel.SetMTU(uint32(mtu))
	}

	rw := newFluxPacketFlowReadWriter()
	endpoint, err := iobased.New(rw, uint32(mtu), 0)
	if err != nil {
		rw.Close()
		return cStringOrNil(fmt.Sprintf("open packet flow device: %v", err))
	}
	dev := &fluxPacketFlowDevice{Endpoint: endpoint}

	proxyURL, err := url.Parse("socks5://" + socksAddr)
	if err != nil {
		dev.Close()
		rw.Close()
		return cStringOrNil(fmt.Sprintf("parse socks proxy: %v", err))
	}
	proxy, err := t2proxy.Parse(proxyURL)
	if err != nil {
		dev.Close()
		rw.Close()
		return cStringOrNil(fmt.Sprintf("create socks proxy: %v", err))
	}

	handler := t2tunnel.New(proxy, statistic.DefaultManager)
	handler.ProcessAsync()

	stk, err := t2core.CreateStack(&t2core.Config{
		LinkEndpoint:     dev,
		TransportHandler: handler,
		Options:          fluxTun2SocksStackOptions(),
	})
	if err != nil {
		handler.Close()
		dev.Close()
		rw.Close()
		return cStringOrNil(fmt.Sprintf("create tun2socks stack: %v", err))
	}

	fluxTun2Socks.client = &fluxTun2SocksClient{device: dev, stack: stk, packetRW: rw}
	return nil
}

// InjectFluxTun2SocksPacket injects one inbound IP packet read from
// NEPacketTunnelFlow into the Flux tun2socks stack started by
// StartFluxTun2SocksPacketFlow.
//
//export InjectFluxTun2SocksPacket
func InjectFluxTun2SocksPacket(data unsafe.Pointer, lenC C.int) *C.char {
	if data == nil || int(lenC) <= 0 {
		return nil
	}
	fluxTun2Socks.Lock()
	var rw *fluxPacketFlowReadWriter
	if fluxTun2Socks.client != nil {
		rw = fluxTun2Socks.client.packetRW
	}
	fluxTun2Socks.Unlock()
	if rw == nil {
		return cStringOrNil("flux packet-flow tun2socks is not running")
	}
	pkt := C.GoBytes(data, lenC)
	if err := rw.Inject(pkt); err != nil {
		return cStringOrNil(err.Error())
	}
	return nil
}

// ReadFluxTun2SocksPacket blocks until an outbound IP packet is produced by
// the Flux tun2socks stack or the packet-flow bridge is closed. Returns
// packet length, or -1 when not running/closed.
//
//export ReadFluxTun2SocksPacket
func ReadFluxTun2SocksPacket(buffer unsafe.Pointer, maxLenC C.int) C.int {
	if buffer == nil || int(maxLenC) <= 0 {
		return -1
	}
	fluxTun2Socks.Lock()
	var rw *fluxPacketFlowReadWriter
	if fluxTun2Socks.client != nil {
		rw = fluxTun2Socks.client.packetRW
	}
	fluxTun2Socks.Unlock()
	if rw == nil {
		return -1
	}
	pkt, err := rw.ReadOutbound()
	if err != nil {
		return -1
	}
	maxLen := int(maxLenC)
	if len(pkt) > maxLen {
		pkt = pkt[:maxLen]
	}
	copy(unsafe.Slice((*byte)(buffer), len(pkt)), pkt)
	return C.int(len(pkt))
}

// TryReadFluxTun2SocksPacket reads one outbound IP packet without blocking.
// Returns packet length, 0 when no packet is immediately available, or -1
// when not running/closed.
//
//export TryReadFluxTun2SocksPacket
func TryReadFluxTun2SocksPacket(buffer unsafe.Pointer, maxLenC C.int) C.int {
	if buffer == nil || int(maxLenC) <= 0 {
		return -1
	}
	fluxTun2Socks.Lock()
	var rw *fluxPacketFlowReadWriter
	if fluxTun2Socks.client != nil {
		rw = fluxTun2Socks.client.packetRW
	}
	fluxTun2Socks.Unlock()
	if rw == nil {
		return -1
	}
	pkt, err := rw.TryReadOutbound()
	if err != nil {
		return -1
	}
	if pkt == nil {
		return 0
	}
	maxLen := int(maxLenC)
	if len(pkt) > maxLen {
		pkt = pkt[:maxLen]
	}
	copy(unsafe.Slice((*byte)(buffer), len(pkt)), pkt)
	return C.int(len(pkt))
}

// StopFluxTun2Socks stops the Flux TUN<->SOCKS5 bridge started by either
// StartFluxTun2SocksWithFd or StartFluxTun2SocksPacketFlow. Idempotent —
// safe to call when no bridge is running.
//
//export StopFluxTun2Socks
func StopFluxTun2Socks() *C.char {
	fluxTun2Socks.Lock()
	defer fluxTun2Socks.Unlock()
	stopFluxTun2SocksLocked()
	return nil
}

func stopFluxTun2SocksLocked() {
	client := fluxTun2Socks.client
	if client == nil {
		return
	}
	fluxTun2Socks.client = nil
	if client.stack != nil {
		client.stack.Close()
		client.stack.Wait()
	}
	if client.device != nil {
		client.device.Close()
	}
	if client.packetRW != nil {
		client.packetRW.Close()
	}
}

func cStringOrNil(s string) *C.char {
	if s == "" {
		return nil
	}
	return C.CString(s)
}

func cstr(v *C.char) string {
	if v == nil {
		return ""
	}
	return C.GoString(v)
}

//export StartOpenFluxClient
func StartOpenFluxClient(
	transportC *C.char,
	urlC *C.char,
	socksAddrC *C.char,
	maxTokenC *C.char,
	maxUidC *C.char,
	debug C.int,
) *C.char {
	mobileState.Lock()
	defer mobileState.Unlock()

	if mobileState.client != nil {
		return cStringOrNil("openflux client is already running")
	}

	transportType := strings.TrimSpace(strings.ToLower(cstr(transportC)))
	if transportType == "" {
		transportType = "yandex"
	}
	socksAddr := strings.TrimSpace(cstr(socksAddrC))
	if socksAddr == "" {
		socksAddr = "127.0.0.1:1080"
	}

	if debug != 0 {
		utils.EnableDebug()
	}

	config := transport.DefaultConfig()
	var trans transport.Transport
	switch transportType {
	case "yandex":
		docURL := strings.TrimSpace(cstr(urlC))
		if docURL == "" {
			return cStringOrNil("OpenFlux yandex transport requires url")
		}
		trans = yandex.NewYandexDocsTransport(docURL, config)
	case "oneme":
		uid, err := strconv.ParseInt(strings.TrimSpace(cstr(maxUidC)), 10, 64)
		if err != nil {
			return cStringOrNil(fmt.Sprintf("OpenFlux oneme transport requires numeric maxUid: %v", err))
		}
		trans = oneme.NewOneMeTransport(false, cstr(maxTokenC), uid, config)
	default:
		return cStringOrNil(fmt.Sprintf("unsupported OpenFlux transport %q", transportType))
	}

	if err := trans.Start(); err != nil {
		return cStringOrNil(fmt.Sprintf("start transport: %v", err))
	}

	tun := tunnel.NewTCPTunnel(trans, false)
	server := socks5.NewSOCKS5Server(socksAddr, tun)
	if err := server.StartInBackground(); err != nil {
		_ = trans.Stop()
		return cStringOrNil(fmt.Sprintf("start socks5: %v", err))
	}

	mobileState.client = &mobileClientState{
		transport: trans,
		tunnel:    tun,
		socks:     server,
		startedAt: time.Now(),
	}
	return nil
}

//export StopOpenFluxClient
func StopOpenFluxClient() *C.char {
	mobileState.Lock()
	client := mobileState.client
	mobileState.client = nil
	mobileState.Unlock()

	if client == nil {
		return nil
	}

	var warnings []string
	if client.socks != nil {
		if err := client.socks.Close(); err != nil {
			warnings = append(warnings, fmt.Sprintf("close socks5: %v", err))
		}
	}
	if client.transport != nil {
		if err := client.transport.Stop(); err != nil {
			warnings = append(warnings, fmt.Sprintf("stop transport: %v", err))
		}
	}

	if len(warnings) > 0 {
		return cStringOrNil(strings.Join(warnings, "; "))
	}
	return nil
}

//export OpenFluxStats
func OpenFluxStats() *C.char {
	mobileState.Lock()
	client := mobileState.client
	mobileState.Unlock()

	if client == nil || client.transport == nil {
		return cStringOrNil(`{"connected":false,"bytesSent":0,"bytesReceived":0,"reconnects":0,"uptimeSeconds":0}`)
	}

	stats := client.transport.Stats()
	payload := map[string]any{
		"connected":     stats.Connected,
		"bytesSent":     stats.BytesSent,
		"bytesReceived": stats.BytesReceived,
		"reconnects":    stats.Reconnects,
		"uptimeSeconds": int64(time.Since(client.startedAt).Seconds()),
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return cStringOrNil(`{"connected":false}`)
	}
	return cStringOrNil(string(encoded))
}

//export FreeOpenFluxString
func FreeOpenFluxString(s *C.char) {
	if s != nil {
		C.free(unsafe.Pointer(s))
	}
}
