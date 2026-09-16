package yandex

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// TestSafeWriteDeadlineKillsStalledConnection pins the 2026-09-16 iOS fix:
// against a document server that stops draining the socket, safeWrite must
// fail at the deadline and KILL the connection (unblocking the reader), so
// the read loop can trigger a reconnect. Before the fix, WriteMessage blocked
// forever on the blackholed TCP connection, freezing the only writerLoop
// while the transport still reported CONNECTED: downloads lived, every
// sustained upload stalled and died with a connection reset.
func TestSafeWriteDeadlineKillsStalledConnection(t *testing.T) {
	old := ydocWriteDeadline
	ydocWriteDeadline = 300 * time.Millisecond
	t.Cleanup(func() { ydocWriteDeadline = old })

	stalled := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		up := websocket.Upgrader{
			// httptest origin differs from Host; accept for the test.
			CheckOrigin: func(*http.Request) bool { return true },
		}
		conn, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		// Never read another frame: the client's send window fills and its
		// next big write blackholes, exactly like a half-dead edge LB.
		<-stalled
		_ = conn.Close()
	}))
	defer func() { close(stalled); server.Close() }()

	wsURL := "ws://" + strings.TrimPrefix(server.URL, "http://")
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	session := &DocSession{Conn: conn}

	start := time.Now()
	// 32 MiB into a socket nobody reads: the buffers (~hundreds of KB at
	// most) fill and the write must be cut off by the deadline.
	werr := session.safeWrite(websocket.BinaryMessage, make([]byte, 32<<20))
	if werr == nil {
		t.Fatal("safeWrite: expected deadline error against a server that never reads")
	}
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("safeWrite took %v; deadline not enforced", elapsed)
	}

	// Kill semantics: the reader side must be finished too - either the
	// deadline call fails on the closed socket or the next read errors. No
	// path may block forever.
	if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		return // socket already closed by kill(): reader cannot block
	}
	if _, _, rerr := conn.ReadMessage(); rerr == nil {
		t.Fatal("ReadMessage: expected error after safeWrite killed the connection")
	}
}

// TestSafeWriteRejectsNilConnection guards the cheap path added with the
// deadline fix (writerLoop may observe a session before a dial completes).
func TestSafeWriteRejectsNilConnection(t *testing.T) {
	session := &DocSession{}
	if err := session.safeWrite(websocket.TextMessage, []byte("x")); err == nil {
		t.Fatal("safeWrite: expected error for nil connection")
	}
}

// TestDocSessionKillIsIdempotent locks the goroutine-safety assumption used
// by every error path (write error, read error, keep-alive failure).
func TestDocSessionKillIsIdempotent(t *testing.T) {
	u, err := url.Parse("ws://127.0.0.1:1/none")
	if err != nil {
		t.Fatal(err)
	}
	d := websocket.Dialer{HandshakeTimeout: 50 * time.Millisecond}
	conn, _, err := d.Dial(u.String(), nil)
	if err == nil {
		_ = conn.Close()
		t.Skip("unexpectedly connected to :1")
	}
	// Constructing from a dead dial is not supported; verify kill on a real
	// local upgrade instead.
	stalled := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		up := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		<-stalled
		_ = c.Close()
	}))
	defer func() { close(stalled); server.Close() }()
	wsURL := "ws://" + strings.TrimPrefix(server.URL, "http://")
	conn, _, err = websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	session := &DocSession{Conn: conn}
	session.kill()
	session.kill() // second call must not panic
}
