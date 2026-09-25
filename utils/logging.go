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
	debugLog      *log.Logger
	verbose       bool
	defaultStderr io.Writer = os.Stderr
	output        io.Writer = defaultStderr
	dbgRate       debugRate
)

type debugRate struct {
	mu         sync.Mutex
	perWindow  int
	window     time.Time
	emitted    int
	suppressed int
}

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
				_, _ = fmt.Fprintf(logOutput(), "[DEBUG] rate limiter: %d debug line(s) suppressed in previous window\n", dbgRate.suppressed)
			}
			dbgRate.window = now
			dbgRate.emitted = 0
			dbgRate.suppressed = 0
		}
		if dbgRate.emitted >= dbgRate.perWindow {
			dbgRate.suppressed++
			dbgRate.mu.Unlock()
			return len(p), nil
		}
		dbgRate.emitted++
	}
	dbgRate.mu.Unlock()
	return logOutput().Write(p)
}

func logOutput() io.Writer {
	if output == defaultStderr {
		return os.Stderr
	}
	return output
}

// SetOutput redirects all debug and standard log output to w.
// Used by the mobile bridge to pipe logs into the app UI.
func SetOutput(w io.Writer) {
	output = w
	log.SetOutput(w)
	if debugLog != nil {
		debugLog.SetOutput(w)
	}
}

func EnableDebug() {
	verbose = true
	debugLog = log.New(rateLimitedWriter{}, "", log.LstdFlags|log.Lmicroseconds)
	log.SetOutput(output)
	log.SetFlags(log.LstdFlags | log.Lmicroseconds | log.Lshortfile)
}

func Debugf(format string, args ...interface{}) {
	if verbose {
		debugLog.Output(2, fmt.Sprintf(format, args...))
	}
}

// SetDebug toggles verbose logging at runtime (off = Debugf becomes a no-op).
func SetDebug(on bool) {
	if on {
		EnableDebug()
		return
	}
	verbose = false
}

func IsVerbose() bool {
	return verbose
}

// SafeGo runs fn in a new goroutine, recovering from any panic so a crash in
// one worker cannot take down the whole process (critical when this code runs
// embedded as a library inside a mobile app).
func SafeGo(name string, fn func()) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				Debugf("[PANIC] recovered in %s: %v", name, r)
			}
		}()
		fn()
	}()
}
