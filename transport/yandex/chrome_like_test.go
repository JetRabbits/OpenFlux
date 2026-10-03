package yandex

import (
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"testing"
	"time"
)

func withChromeLike(t *testing.T, enabled bool, fn func()) {
	t.Helper()
	original := chromeLike
	t.Cleanup(func() { SetChromeLike(original) })
	SetChromeLike(enabled)
	fn()
}

func TestChromeLikeDefaultAndToggle(t *testing.T) {
	original := chromeLike
	t.Cleanup(func() { SetChromeLike(original) })

	if !chromeLike {
		t.Fatal("chromeLike must default to true (standalone server behavior)")
	}

	SetChromeLike(false)
	if chromeLike {
		t.Fatal("SetChromeLike(false) did not disable chrome emulation")
	}

	SetChromeLike(true)
	if !chromeLike {
		t.Fatal("SetChromeLike(true) did not re-enable chrome emulation")
	}
}

func TestNewDocWSDialerHonorsChromeLike(t *testing.T) {
	withChromeLike(t, true, func() {
		if got := newDocWSDialer(); got.NetDialTLSContext == nil {
			t.Fatal("chrome-like mode must install NetDialTLSContext")
		}
	})

	withChromeLike(t, false, func() {
		d := newDocWSDialer()
		if d.NetDialTLSContext != nil {
			t.Fatal("plain mode must not install NetDialTLSContext")
		}
		if d.NetDialContext == nil {
			t.Fatal("plain mode must keep the net dialer (hard TCP timeout)")
		}
	})
}

func TestDocUserAgentsHonorChromeLike(t *testing.T) {
	withChromeLike(t, true, func() {
		if got := docWSUserAgent(); got != chromeUserAgent {
			t.Fatalf("chrome-like WS UA = %q, want %q", got, chromeUserAgent)
		}
		if got := docFetchUserAgent(); got != chromeUserAgent {
			t.Fatalf("chrome-like fetch UA = %q, want %q", got, chromeUserAgent)
		}
	})

	withChromeLike(t, false, func() {
		if got := docWSUserAgent(); got != legacyWSUserAgent {
			t.Fatalf("legacy WS UA = %q, want %q", got, legacyWSUserAgent)
		}
		if got := docFetchUserAgent(); got != legacyFetchUserAgent {
			t.Fatalf("legacy fetch UA = %q, want %q", got, legacyFetchUserAgent)
		}
	})
}

func TestDocHTTPClientHonorsChromeLike(t *testing.T) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}

	withChromeLike(t, true, func() {
		if c := docHTTPClient(jar, time.Second); c.Transport == nil {
			t.Fatal("chrome-like mode must install the utls transport")
		}
	})

	withChromeLike(t, false, func() {
		c := docHTTPClient(jar, time.Second)
		if c.Transport != nil {
			t.Fatal("plain mode must use net/http default transport")
		}
		if c.Jar != jar {
			t.Fatal("plain mode must keep the cookie jar")
		}
		if c.Timeout != time.Second {
			t.Fatalf("plain mode timeout = %v, want 1s", c.Timeout)
		}
	})
}

func TestSetFetchHeadersHonorsChromeLike(t *testing.T) {
	newReq := func() *http.Request {
		return httptest.NewRequest(http.MethodGet, "https://docs.example/x", nil)
	}

	withChromeLike(t, true, func() {
		req := newReq()
		setFetchHeaders(req, "some-ua")
		if req.Header.Get("Accept") == "" {
			t.Fatal("chrome-like mode must add browser Accept headers")
		}
	})

	withChromeLike(t, false, func() {
		req := newReq()
		setFetchHeaders(req, "some-ua")
		if got := req.Header.Get("User-Agent"); got != "some-ua" {
			t.Fatalf("plain mode UA = %q, want %q", got, "some-ua")
		}
		if req.Header.Get("Accept") != "" {
			t.Fatal("plain mode must not add extra browser headers")
		}
	})
}
