package transport

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestStripeKnobMutationDuringPump pins the fix for the CI -race failure:
// the package's stripe knobs (stripePieceBytes, codelTarget, holeDeadline)
// are mutated here while a StripedTransport's pump/stats goroutines run,
// exactly as earlier tests in this binary leave stragglers running when a
// later test retunes a knob. Before the atomics this raced (the write in a
// test goroutine against (*sender).codelShouldDrop / nextPiece / a
// concurrent newReorderBuffer read); now every read goes through an atomic
// accessor and -race stays clean.
func TestStripeKnobMutationDuringPump(t *testing.T) {
	savedPB, savedHD, savedCT := stripePieceBytes(), holeDeadline(), codelTarget()

	a, b := newDelayPair(20 * time.Millisecond)
	A := NewStripedTransport([]Transport{a})
	B := NewStripedTransport([]Transport{b})
	B.Receive(func([]byte) {})
	if err := A.Start(); err != nil {
		t.Fatal(err)
	}
	if err := B.Start(); err != nil {
		t.Fatal(err)
	}
	defer A.Stop()
	defer B.Stop()

	var stop atomic.Bool
	var wg sync.WaitGroup

	// A pumping transport: its pump goroutine drives nextPiece and
	// codelShouldDrop, the two hot readers of stripePieceBytes/codelTarget.
	frame := make([]byte, 8192)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for !stop.Load() {
			_ = A.Send(frame)
			time.Sleep(time.Millisecond)
		}
	}()

	// Mutate the knobs the way the reorder/scale tests do, and construct a
	// fresh reorder buffer (the holeDeadline reader) in the loop, while the
	// transport above keeps pumping. All mutations run the deferred restores.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 2000 && !stop.Load(); i++ {
			setStripePieceBytes(64 * 1024)
			setCodelTarget(time.Minute)
			setHoleDeadline(100 * time.Millisecond)
			r := newReorderBuffer(func([]byte, bool) {})
			close(r.out)
			setStripePieceBytes(savedPB)
			setCodelTarget(savedCT)
			setHoleDeadline(savedHD)
		}
	}()

	time.Sleep(500 * time.Millisecond)
	stop.Store(true)
	wg.Wait()

	// The restores ran last: knobs are back at their entry values.
	if got := stripePieceBytes(); got != savedPB {
		t.Fatalf("stripePieceBytes not restored: %d != %d", got, savedPB)
	}
	if got := holeDeadline(); got != savedHD {
		t.Fatalf("holeDeadline not restored: %v != %v", got, savedHD)
	}
	if got := codelTarget(); got != savedCT {
		t.Fatalf("codelTarget not restored: %v != %v", got, savedCT)
	}
}
