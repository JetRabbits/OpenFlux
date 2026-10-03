package yandex

import "testing"

func TestWSChromeLikeDefaultAndToggle(t *testing.T) {
	original := wsChromeLike
	t.Cleanup(func() { wsChromeLike = original })

	if !wsChromeLike {
		t.Fatal("wsChromeLike must default to true (standalone server behavior)")
	}

	SetWSChromeLike(false)
	if wsChromeLike {
		t.Fatal("SetWSChromeLike(false) did not disable chrome-like docs WebSocket")
	}

	SetWSChromeLike(true)
	if !wsChromeLike {
		t.Fatal("SetWSChromeLike(true) did not re-enable chrome-like docs WebSocket")
	}
}

func TestNewDocWSDialerHonorsWSChromeLike(t *testing.T) {
	original := wsChromeLike
	t.Cleanup(func() { wsChromeLike = original })

	SetWSChromeLike(true)
	if got := newDocWSDialer(); got.NetDialTLSContext == nil {
		t.Fatal("chrome-like mode must install NetDialTLSContext")
	}

	SetWSChromeLike(false)
	d := newDocWSDialer()
	if d.NetDialTLSContext != nil {
		t.Fatal("plain mode must not install NetDialTLSContext")
	}
	if d.NetDialContext == nil {
		t.Fatal("plain mode must keep the net dialer (hard TCP timeout)")
	}
}

func TestDocWSUserAgentHonorsWSChromeLike(t *testing.T) {
	original := wsChromeLike
	t.Cleanup(func() { wsChromeLike = original })

	SetWSChromeLike(true)
	if got := docWSUserAgent(); got != chromeUserAgent {
		t.Fatalf("chrome-like UA = %q, want %q", got, chromeUserAgent)
	}

	SetWSChromeLike(false)
	if got := docWSUserAgent(); got != legacyWSUserAgent {
		t.Fatalf("legacy UA = %q, want %q", got, legacyWSUserAgent)
	}
}
