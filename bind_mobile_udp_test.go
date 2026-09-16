package main

import (
	"testing"
	"time"

	"universal-bypass-tool/socks5"
)

// TestFluxUDPSessionTimeoutUndercutsRelay locks the layering invariant that
// makes the fluxUDPSessionTimeout memory saving correct.
//
// A tun2socks UDP session parks two 64 KiB relay buffers for its whole idle
// window (tunnel.copyPacketData holds buffer.Get(MaxSegmentSize) until the
// session dies), and the live iPhone heap profile showed those parked buffers
// as the single largest consumer of the Go heap. The session is only worth
// parking while our own SOCKS5 relay would still accept traffic on it; past
// DefaultUDPEndpointTimeout the relay has already reaped the associate, so any
// extra parking is pure footprint.
func TestFluxUDPSessionTimeoutUndercutsRelay(t *testing.T) {
	if fluxUDPSessionTimeout >= socks5.DefaultUDPEndpointTimeout {
		t.Fatalf("fluxUDPSessionTimeout=%s must stay below the SOCKS5 UDP endpoint timeout %s, "+
			"otherwise tun2socks parks relay buffers for sessions the relay already reaped",
			fluxUDPSessionTimeout, socks5.DefaultUDPEndpointTimeout)
	}
	if fluxUDPSessionTimeout <= 0 {
		// A zero timeout makes every UDP session die on its first idle tick.
		t.Fatalf("fluxUDPSessionTimeout=%s must be positive", fluxUDPSessionTimeout)
	}
	if fluxUDPSessionTimeout > time.Minute {
		t.Fatalf("fluxUDPSessionTimeout=%s exceeds the idle-window budget of a mobile extension",
			fluxUDPSessionTimeout)
	}
}
