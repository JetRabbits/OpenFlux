package cupsonline

// Tests for the pipelined change_code writer: the writer keeps up to
// MaxInflightBatches calls outstanding and processes replies asynchronously,
// so (a) late/OUT-OF-ORDER replies must neither lose frames nor roll the
// applied baseline back, (b) a "not applied" result for one of several
// in-flight sends must rebase+retransmit exactly once while the others
// proceed, and (c) when the window is full the send loop must apply back-
// pressure upstream instead of unbounding memory. Latency is pinned by
// (d): small frames spaced over a slow (RTT-emulated) link must each land in
// ≈one dwell + push, with no serialization backlog. The wire bytes themselves
// are golden-tested unchanged in TestMakeDiffLiveFrameGoldens — pipelining
// only reorders the SCHEDULING, never the framing or the diff dialect.

import (
	"bytes"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/JetRabbits/OpenFlux/transport"
)

// watchCodeVersion samples the channel's APPLIED baseline version at ~500 Hz
// while the test body runs; the stop function returns the timeline. The
// writer adopts authoritative documents by version monotonicity, so a pipelined
// (re)ordering of replies must never move this number backwards.
func watchCodeVersion(t *testing.T, w *cupsWS) func() []int64 {
	t.Helper()
	stop := make(chan struct{})
	samples := make(chan int64, 16384)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}
			w.codeMu.Lock()
			v := w.codeVersion
			w.codeMu.Unlock()
			select {
			case samples <- v:
			default:
			}
			time.Sleep(2 * time.Millisecond)
		}
	}()
	var once sync.Once
	return func() []int64 {
		once.Do(func() { close(stop) })
		<-done
		close(samples)
		var out []int64
		for v := range samples {
			out = append(out, v)
		}
		return out
	}
}

func assertMonotonic(t *testing.T, samples []int64) {
	t.Helper()
	for i := 1; i < len(samples); i++ {
		if samples[i] < samples[i-1] {
			t.Errorf("applied baseline version rolled back: %d after %d — out-of-order reply leaked into the baseline", samples[i], samples[i-1])
			return
		}
	}
}

// waitExitBaseline converges the exit's baseline to the stored document.
func waitExitBaseline(t *testing.T, tr *CupsonlineTransport, f *fakeServer, id string) {
	t.Helper()
	w := tr.wss[0]
	deadline := time.Now().Add(10 * time.Second)
	for {
		w.codeMu.Lock()
		code := w.serverCode
		w.codeMu.Unlock()
		if code == f.codeOf(id) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("exit baseline never converged onto the stored document")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// (a) Three payload batches are dispatched back-to-back while ALL their RPC
// replies are held for 200-300ms and delivered OUT OF ORDER (arrival order
// #2, #1, #3). The fake still applies the patches in arrival order, so the
// optimistic chain lands all three with zero retransmits; the shuffled replies
// must neither lose a frame, double-send a batch, nor roll the baseline back.
func TestPipelinedSendsOutOfOrderReplies(t *testing.T) {
	f := newFakeCups(t)
	exitTr, clientTr, id := startExitClient(t, f)

	got := make(chan []byte, 64)
	clientTr.Receive(func(p []byte) { got <- append([]byte(nil), p...) })

	// Dispatch happens ≈12/72/132ms after each Send (idle flush); replies
	// then land at ≈312 / 272 / 384ms — strictly #2 before #1 before #3,
	// every one of them while the other two are still outstanding.
	f.setReplyDelays(id, 300*time.Millisecond, 200*time.Millisecond, 250*time.Millisecond)

	watch := watchCodeVersion(t, exitTr.wss[0])

	const frames = 3
	want := map[string]bool{}
	for i := 1; i <= frames; i++ {
		pkt := []byte(fmt.Sprintf("ofx-pipe-%d", i))
		want[string(pkt)] = true
		if err := exitTr.Send(pkt); err != nil {
			t.Fatalf("Send %d: %v", i, err)
		}
		time.Sleep(60 * time.Millisecond)
	}

	seen := map[string]bool{}
	deadline := time.After(20 * time.Second)
	for len(seen) < frames {
		select {
		case p := <-got:
			if want[string(p)] {
				seen[string(p)] = true
			}
		case <-deadline:
			a, r, n := f.stats(id)
			t.Fatalf("only %d/%d frames reached the client (server stats: applied=%d rejected=%d noop=%d, exit stats %+v)",
				len(seen), frames, a, r, n, exitTr.Stats())
		}
	}

	// The optimistic chain must have applied all three calls with ZERO
	// retransmits: late/out-of-order replies are not failures — the document
	// they carry is older than the pushed baseline, they merely confirm.
	applied, rejected, noop := f.stats(id)
	if applied != frames {
		t.Errorf("applied = %d, want %d (no retransmit expected for in-order applies)", applied, frames)
	}
	if rejected != 0 || noop != 0 {
		t.Errorf("rejected=%d noop=%d, want 0/0", rejected, noop)
	}
	if calls := f.callCount(id); calls != frames {
		t.Errorf("room saw %d change_code calls, want exactly %d (out-of-order replies must not trigger resends)", calls, frames)
	}
	if st := waitForStats(t, exitTr, frames, 0); st.PacketsSent != uint64(frames) {
		t.Errorf("exit counted %d packets sent, want %d", st.PacketsSent, frames)
	}

	assertMonotonic(t, watch())
	waitExitBaseline(t, exitTr, f, id)

	// Final state: the block carries the LAST batch (each send replaces the
	// block wholesale), template and peer block untouched.
	code := f.codeOf(id)
	if body := extractBlockSide(strings.Split(code, "\n"), "X"); body != b64Frame([]byte("ofx-pipe-3")) {
		t.Errorf("final block does not carry the last batch: %q", body)
	}
	t.Logf("out-of-order replies (2,1,3): %d frames delivered through %d change_code calls, baseline monotonic", frames, applied)
}

// (b) The FIRST of three in-flight sends comes back "not applied" (the fake
// no-ops a patch that WOULD have applied — the live server's silent-noop shape).
// The transport must rebase that batch on the authoritative reply and
// retransmit it EXACTLY ONCE while the later batches proceed; final state:
// all three payloads delivered, block = the last batch, one call per batch
// plus a single retransmit.
func TestPipelinedNotAppliedRetransmit(t *testing.T) {
	f := newFakeCups(t)
	exitTr, clientTr, id := startExitClient(t, f)

	got := make(chan []byte, 64)
	clientTr.Receive(func(p []byte) { got <- append([]byte(nil), p...) })

	f.setForceNoop(id, 1) // the first change_code call is silently not applied

	const frames = 3
	want := map[string]bool{}
	for i := 1; i <= frames; i++ {
		pkt := []byte(fmt.Sprintf("ofx-nap-%d", i))
		want[string(pkt)] = true
		if err := exitTr.Send(pkt); err != nil {
			t.Fatalf("Send %d: %v", i, err)
		}
		time.Sleep(60 * time.Millisecond)
	}

	seen := map[string]bool{}
	deadline := time.After(20 * time.Second)
	for len(seen) < frames {
		select {
		case p := <-got:
			if want[string(p)] {
				seen[string(p)] = true
			}
		case <-deadline:
			a, r, n := f.stats(id)
			t.Fatalf("only %d/%d frames reached the client after the forced no-op (applied=%d rejected=%d noop=%d)",
				len(seen), frames, a, r, n)
		}
	}

	// Exactly ONE rebase+retransmit happened (the forced no-op of send #1),
	// and the retransmit applied against the adopted authoritative document.
	applied, rejected, noop := f.stats(id)
	if noop != 1 {
		t.Errorf("noop = %d, want 1 (the forced rejection only — later batches chained onto the retransmit)", noop)
	}
	if rejected != 0 {
		t.Errorf("rejected = %d, want 0", rejected)
	}
	if applied != frames {
		t.Errorf("applied = %d, want %d", applied, frames)
	}
	calls := f.callCount(id)
	if calls != frames+1 {
		t.Errorf("room saw %d change_code calls, want %d (3 batches + exactly 1 retransmit)", calls, frames+1)
	}
	waitExitBaseline(t, exitTr, f, id)

	// The retransmit of batch #1 lands the payload, later batches rewrite the
	// block in order — the final block must carry the LAST batch byte-exact.
	code := f.codeOf(id)
	if body := extractBlockSide(strings.Split(code, "\n"), "X"); body != b64Frame([]byte("ofx-nap-3")) {
		t.Errorf("final block does not carry the last batch: %q", body)
	}
	t.Logf("forced no-op on send #1 of 3: recovered with %d retransmit(s), all payloads delivered", calls-frames)
}

// (c) With the reply gate shut, the window (3) fills and the writer must
// STOP dispatching a 4th call — the 4th frame waits upstream (Send/back-
// pressure), proving the bounded window and ordered queue. While gated, all
// three applied batches are already delivered via pushes (proof they were
// concurrently in flight). Opening the gate drains the window and the 4th
// frame goes out.
func TestPipelinedWindowBackpressure(t *testing.T) {
	f := newFakeCups(t)
	exitTr, clientTr, id := startExitClient(t, f)

	got := make(chan []byte, 64)
	clientTr.Receive(func(p []byte) { got <- append([]byte(nil), p...) })

	gate := make(chan struct{})
	f.setGate(id, gate)
	t.Cleanup(func() { close(gate) }) // release any still-waiting reply goroutine

	const frames = 4
	want := map[string]bool{}
	for i := 1; i <= frames; i++ {
		pkt := []byte(fmt.Sprintf("ofx-bp-%d", i))
		want[string(pkt)] = true
		if err := exitTr.Send(pkt); err != nil {
			t.Fatalf("Send %d: %v", i, err)
		}
		time.Sleep(80 * time.Millisecond)
	}

	// Frames 1..3: applied + pushed while their replies sit gated — three
	// sends were genuinely in flight together (a stop-and-wait writer could
	// have only ONE undelivered... the first, waiting for its own reply).
	seen := map[string]bool{}
	deadline := time.After(10 * time.Second)
	for len(seen) < frames-1 {
		select {
		case p := <-got:
			if want[string(p)] {
				seen[string(p)] = true
			}
		case <-deadline:
			t.Fatalf("only %d/%d gated-applied frames reached the client via push", len(seen), frames-1)
		}
	}

	// The fourth call must NOT have been dispatched: window full.
	time.Sleep(300 * time.Millisecond)
	if calls := f.callCount(id); calls != frames-1 {
		t.Errorf("room saw %d change_code calls while the window was full, want %d (4th must wait for a slot)", calls, frames-1)
	}

	// Release the gated replies; the window drains and the queued batch rides.
	// Feed tokens while a reply is actually waiting (tolerant to scheduling
	// jitter on slow CI, where a later call may not be dispatched yet).
	for i := 0; i < 2*frames; i++ {
		select {
		case gate <- struct{}{}:
		case <-time.After(250 * time.Millisecond):
		}
	}

	select {
	case p := <-got:
		if !want[string(p)] || string(p) != "ofx-bp-4" {
			t.Fatalf("unexpected frame after gate release: %q", p)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the queued 4th frame never went out after the window drained")
	}
	if calls := f.callCount(id); calls != frames {
		t.Errorf("room saw %d calls, want %d", calls, frames)
	}
	waitExitBaseline(t, exitTr, f, id)
	t.Logf("bounded window held the 4th send until a reply freed a slot; 3 sends had been concurrently in flight")
}

// (d) Latency pin over an RTT-emulated link: change_code REPLIES take 200ms
// (the authoritative baseline lags a full RTT) while pushes deliver normally.
// A stream of small frames spaced 500ms — each an isolated batch (idle flush
// 12ms, well under the 30ms dwell: the small-packet fast path) — must keep
// per-frame delivery latency at ≈dwell+push (asserted ceiling ≈1.2×RTT =
// 240ms), i.e. no serialization backlog: the writer never blocks the next
// frame on the previous call's reply.
func TestPipelinedLatencyNoBacklog(t *testing.T) {
	f := newFakeCups(t)
	exitTr, clientTr, id := startExitClient(t, f)

	got := make(chan []byte, 256)
	clientTr.Receive(func(p []byte) { got <- append([]byte(nil), p...) })

	const rtt = 200 * time.Millisecond
	f.setReplyDelays(id, rtt) // every reply lands a full RTT late

	const frames = 8
	const spacing = 500 * time.Millisecond
	const ceiling = rtt + rtt/5 // ≈1.2×RTT

	var maxLat time.Duration
	t0 := time.Now()
	for i := 1; i <= frames; i++ {
		pkt := []byte(fmt.Sprintf("ofx-lat-%d", i))
		sentAt := time.Now()
		if err := exitTr.Send(pkt); err != nil {
			t.Fatalf("Send %d: %v", i, err)
		}
		deadline := time.After(10 * time.Second)
		for {
			select {
			case p := <-got:
				if bytes.Equal(p, pkt) {
					lat := time.Since(sentAt)
					if lat > maxLat {
						maxLat = lat
					}
					if lat > ceiling {
						t.Errorf("frame %d delivered in %v, over the %.1fxRTT ceiling %v — the writer serialized behind an outstanding reply",
							i, lat.Round(time.Millisecond), 1.2, ceiling)
					}
					goto next
				}
			case <-deadline:
				t.Fatalf("frame %d never reached the client", i)
			}
		}
	next:
		if d := time.Until(t0.Add(time.Duration(i) * spacing)); d > 0 {
			time.Sleep(d)
		}
	}

	applied, rejected, noop := f.stats(id)
	calls := f.callCount(id)
	if calls != frames {
		t.Errorf("room saw %d change_code calls, want exactly %d (isolated frames must not retransmit)", calls, frames)
	}
	if applied != frames || rejected != 0 || noop != 0 {
		t.Errorf("server stats applied=%d rejected=%d noop=%d, want %d/0/0", applied, rejected, noop, frames)
	}
	t.Logf("RTT %v, %d frames @ %v: max per-frame delivery latency %v (ceiling %v), %d calls total",
		rtt, frames, spacing, maxLat.Round(time.Millisecond), ceiling, calls)
}

// The window is configurable down to 1 — a single serial outstanding write,
// the pre-pipelining schedule — and the transport must still converge.
func TestPipelinedWindowOneStillWorks(t *testing.T) {
	f := newFakeCups(t)
	f.pointBaseAt(t)

	exitTr := NewCupsonlineTransport("", transport.DefaultConfig(), false)
	exitTr.config = fastCupsConfig()
	exitTr.config.NumRooms = 1
	exitTr.config.MaxInflightBatches = 1
	exitTr.Receive(func([]byte) {})
	if err := exitTr.Start(); err != nil {
		t.Fatalf("exit Start: %v", err)
	}
	t.Cleanup(func() { _ = exitTr.Stop() })
	ids := exitTr.RoomUUIDs()
	raw := mustPack(ids)

	clientTr := NewCupsonlineTransport(raw, transport.DefaultConfig(), true)
	clientTr.config = fastCupsConfig()
	got := make(chan []byte, 64)
	clientTr.Receive(func(p []byte) { got <- append([]byte(nil), p...) })
	if err := clientTr.Start(); err != nil {
		t.Fatalf("client Start: %v", err)
	}
	t.Cleanup(func() { _ = clientTr.Stop() })

	waitWSConnected(t, exitTr, "exit")
	waitWSConnected(t, clientTr, "client")

	// With window 1 the next batch may only go out after the previous reply
	// was processed — assert by holding replies: with the gate shut the very
	// first call is as far as the writer gets.
	gate := make(chan struct{})
	f.setGate(ids[0], gate)
	t.Cleanup(func() { close(gate) })

	for i := 1; i <= 3; i++ {
		if err := exitTr.Send([]byte(fmt.Sprintf("ofx-w1-%d", i))); err != nil {
			t.Fatalf("Send %d: %v", i, err)
		}
		time.Sleep(60 * time.Millisecond)
	}
	time.Sleep(200 * time.Millisecond)
	if calls := f.callCount(ids[0]); calls != 1 {
		t.Errorf("with window=1 and a gated reply, room saw %d calls, want 1 (strictly stop-and-wait)", calls)
	}
	// Feed tokens while gated replies are actually waiting: the writer may
	// legitimately coalesce the frames that queued behind the closed window
	// into fewer batches, so the exact call count is bounded, not pinned.
	for i := 0; i < 8; i++ {
		select {
		case gate <- struct{}{}:
		case <-time.After(250 * time.Millisecond):
		}
	}
	seen := map[string]bool{}
	deadline := time.After(15 * time.Second)
	for len(seen) < 3 {
		select {
		case p := <-got:
			if strings.HasPrefix(string(p), "ofx-w1-") {
				seen[string(p)] = true
			}
		case <-deadline:
			t.Fatalf("window-1 writer lost frames: %v", seen)
		}
	}
}
