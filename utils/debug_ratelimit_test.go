package utils

import (
	"os"
	"strings"
	"testing"
	"time"
)

// captureDebug redirects the utils logger through SetOutput (the level-
// aware upstream design snapshots its writer, so swapping the os.Stderr
// variable no longer captures anything) while fn runs and returns
// everything written. The teardown must happen *before* buf.String()
// (defers would run after the return value is computed and lose the
// tail), so this helper closes the writer and waits explicitly.
func captureDebug(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	var buf strings.Builder
	done := make(chan struct{})
	go func() {
		defer close(done)
		b := make([]byte, 4096)
		for {
			n, rerr := r.Read(b)
			if n > 0 {
				buf.Write(b[:n])
			}
			if rerr != nil {
				return
			}
		}
	}()

	func() {
		SetOutput(w)
		defer SetOutput(nil)
		fn()
	}()

	_ = w.Close()
	<-done
	r.Close()
	return buf.String()
}

func TestDebugRateLimitSuppressesBurst(t *testing.T) {
	SetDebugRateLimit(0)
	defer SetDebugRateLimit(0)

	out := captureDebug(t, func() {
		EnableDebug()
		defer SetLevel(LevelOff)
		SetDebugRateLimit(5)
		start := time.Now()
		for i := 0; i < 100; i++ {
			Debugf("burst line %d", i)
		}
		if time.Since(start) > 900*time.Millisecond {
			t.Skip("host too slow to keep the burst inside one window")
		}
	})

	if got := strings.Count(out, "burst line"); got > 6 {
		t.Fatalf("expected at most window+slack (6) burst lines with limit 5, got %d\n%s", got, out)
	}
}

func TestDebugRateLimitReportsSuppressed(t *testing.T) {
	SetDebugRateLimit(0)
	defer SetDebugRateLimit(0)

	out := captureDebug(t, func() {
		EnableDebug()
		defer SetLevel(LevelOff)
		SetDebugRateLimit(5)
		for i := 0; i < 50; i++ {
			Debugf("burst line %d", i)
		}
		time.Sleep(1100 * time.Millisecond)
		Debugf("first line after window")
	})

	if !strings.Contains(out, "rate limiter") {
		t.Fatalf("expected suppression summary after window rollover, got:\n%s", out)
	}
	if !strings.Contains(out, "first line after window") {
		t.Fatalf("line emitted after the window must pass through, got:\n%s", out)
	}
}

func TestDebugRateLimitDisabledByDefault(t *testing.T) {
	SetDebugRateLimit(0)
	defer SetDebugRateLimit(0)

	out := captureDebug(t, func() {
		EnableDebug()
		defer SetLevel(LevelOff)
		for i := 0; i < 500; i++ {
			Debugf("unlimited line %d", i)
		}
	})

	if !strings.Contains(out, "unlimited line 499") {
		t.Fatalf("with limiting disabled every line must pass through")
	}
}
