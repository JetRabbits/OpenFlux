package utils

import (
	"fmt"
	"io"
	"log"
	"os"
	"sync"
	"time"
)

var (
	debugLog *log.Logger
	verbose  bool
)

// debugRate implements an optional sliding-window rate limit for Debugf
// output. The per-packet TCP/UDP dumps that Debug=true enables are cheap on
// a desktop but, inside an iOS NetworkExtension (~50 MB jetsam limit), the
// formatting allocations and stderr syscalls starve the data path and the
// footprint grows until the OS kills the tunnel. Disabled by default so
// desktop behaviour is byte-for-byte unchanged; mobile bind layers opt in
// via SetDebugRateLimit.
type debugRate struct {
	mu         sync.Mutex
	perWindow  int // lines per 1s window; 0 disables limiting
	window     time.Time
	emitted    int
	suppressed int
}

var dbgRate debugRate

// SetDebugRateLimit caps Debugf at linesPerSecond (0 turns limiting off).
// Safe to call before/after EnableDebug. Dropped lines are summarised once
// per window so bursts remain visible in aggregate.
func SetDebugRateLimit(linesPerSecond int) {
	dbgRate.mu.Lock()
	defer dbgRate.mu.Unlock()
	dbgRate.perWindow = linesPerSecond
	dbgRate.window = time.Time{}
	dbgRate.emitted = 0
	dbgRate.suppressed = 0
}

type rateLimitedWriter struct{}

func (rateLimitedWriter) Write(p []byte) (int, error) {
	dbgRate.mu.Lock()
	if dbgRate.perWindow > 0 {
		now := time.Now()
		if now.Sub(dbgRate.window) >= time.Second {
			if dbgRate.suppressed > 0 {
				fmt.Fprintf(os.Stderr,
					"[DEBUG] rate limiter: %d debug line(s) suppressed in previous window\n",
					dbgRate.suppressed)
			}
			dbgRate.window = now
			dbgRate.emitted = 0
			dbgRate.suppressed = 0
		}
		if dbgRate.emitted >= dbgRate.perWindow {
			dbgRate.suppressed++
			dbgRate.mu.Unlock()
			return len(p), nil // pretend consumed; caller must not retry
		}
		dbgRate.emitted++
	}
	dbgRate.mu.Unlock()
	return os.Stderr.Write(p)
}

func EnableDebug() {
	verbose = true
	var w io.Writer = rateLimitedWriter{}
	debugLog = log.New(w, "", log.LstdFlags|log.Lmicroseconds)
	log.SetFlags(log.LstdFlags | log.Lmicroseconds | log.Lshortfile)
}

func Debugf(format string, args ...interface{}) {
	if verbose {
		debugLog.Output(2, fmt.Sprintf(format, args...))
	}
}

func IsVerbose() bool {
	return verbose
}
