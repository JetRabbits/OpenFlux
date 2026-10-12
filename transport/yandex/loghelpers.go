package yandex

import (
	"log"
	"sync"
	"time"
)

// infof logs an always-on message. The fork's utils package only grew
// Debugf so far; upstream's Infof calls are routed here, so boards.go stays
// a byte-for-byte sync target for upstream updates.
func infof(format string, args ...interface{}) {
	log.Printf(format, args...)
}

// infoThrottle backs throttled.
var infoThrottle sync.Map

// throttled reports true at most once per `every` per key, so repeated
// reconnect storms log one line, not one per attempt.
func throttled(key string, every time.Duration) bool {
	now := time.Now()
	if last, ok := infoThrottle.Load(key); ok && now.Sub(last.(time.Time)) < every {
		return false
	}
	infoThrottle.Store(key, now)
	return true
}
