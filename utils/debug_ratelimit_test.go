package utils

import (
	"os"
	"strings"
	"testing"
	"time"
)

// captureStderr swaps os.Stderr for a pipe while fn runs and returns
// everything written to it. Note: the teardown must happen *before*
// buf.String() (defers would run after the return value is computed and
// lose the tail), so this helper closes the writer and waits explicitly.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stderr
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
		os.Stderr = w
		defer func() { os.Stderr = orig }()
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

	out := captureStderr(t, func() {
		EnableDebug()
		defer func() { verbose = false }()
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

	out := captureStderr(t, func() {
		EnableDebug()
		defer func() { verbose = false }()
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

	out := captureStderr(t, func() {
		EnableDebug()
		defer func() { verbose = false }()
		for i := 0; i < 500; i++ {
			Debugf("unlimited line %d", i)
		}
	})

	if !strings.Contains(out, "unlimited line 499") {
		t.Fatalf("with limiting disabled every line must pass through")
	}
}
