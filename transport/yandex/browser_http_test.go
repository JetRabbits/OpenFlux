package yandex

import (
	"net/http"
	"net/http/cookiejar"
	"testing"
	"time"
)

func TestSetChromeLikeHeaders(t *testing.T) {
	req, err := http.NewRequest("GET", "https://docs.yandex.ru/edit/d/test", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Cookie", "session=kept")
	req.Header.Set("X-Keep", "kept")

	ua := "Mozilla/5.0 test"
	setChromeLikeHeaders(req, ua)

	assertHeader := func(key, want string) {
		t.Helper()
		if got := req.Header.Get(key); got != want {
			t.Fatalf("%s = %q, want %q", key, got, want)
		}
	}
	assertHeader("User-Agent", ua)
	assertHeader("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
	assertHeader("Accept-Language", "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7")
	assertHeader("Accept-Encoding", "identity")
	assertHeader("Cookie", "session=kept")
	assertHeader("X-Keep", "kept")
}

func TestChromeLikeHTTPClientConfig(t *testing.T) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	timeout := 15 * time.Second

	client := chromeLikeHTTPClient(jar, timeout)
	if client.Jar != jar {
		t.Fatalf("client jar was not preserved")
	}
	if client.Timeout != timeout {
		t.Fatalf("client timeout = %v, want %v", client.Timeout, timeout)
	}

	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("client transport = %T, want *http.Transport", client.Transport)
	}
	if transport.ForceAttemptHTTP2 {
		t.Fatalf("ForceAttemptHTTP2 = true, want false")
	}
	if transport.DialTLSContext == nil {
		t.Fatalf("DialTLSContext is nil")
	}
}
