package cupsonline

// Throughput regression tests for the outbound batching rework: the writer
// must AGGREGATE a sustained stream into few change_code calls (each call
// re-broadcasts the whole document, so calls-per-second IS the bandwidth
// budget), must SHRINK the document back after bursts (a small frame after a
// big one replaces, never grows, our block), must PRUNE stray copies of our
// block that a fuzzy server apply left behind, and must rebase a stale
// baseline on the tracked push/reply code WITHOUT the extra
// shared_editor_room_info RPC when a fresher document already reached us.

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/JetRabbits/OpenFlux/transport"
)

// startExitClient spins up the canonical pair on the fake service: one exit
// (room-creating) transport and one client joining its single room.
func startExitClient(t *testing.T, f *fakeServer) (exitTr, clientTr *CupsonlineTransport, roomID string) {
	t.Helper()
	f.pointBaseAt(t)

	exitTr = NewCupsonlineTransport("", transport.DefaultConfig(), false)
	exitTr.config = fastCupsConfig()
	exitTr.config.NumRooms = 1
	exitTr.Receive(func([]byte) {})
	if err := exitTr.Start(); err != nil {
		t.Fatalf("exit Start: %v", err)
	}
	t.Cleanup(func() { _ = exitTr.Stop() })

	ids := exitTr.RoomUUIDs()
	if len(ids) != 1 {
		t.Fatalf("exit room count = %d, want 1", len(ids))
	}
	raw, _ := json.Marshal(ids)

	clientTr = NewCupsonlineTransport("?rooms="+base64.RawURLEncoding.EncodeToString(raw), transport.DefaultConfig(), true)
	clientTr.config = fastCupsConfig()
	clientTr.Receive(func([]byte) {})
	if err := clientTr.Start(); err != nil {
		t.Fatalf("client Start: %v", err)
	}
	t.Cleanup(func() { _ = clientTr.Stop() })

	waitWSConnected(t, exitTr, "exit")
	waitWSConnected(t, clientTr, "client")
	return exitTr, clientTr, ids[0]
}

// ---- (1) aggregation ----

func TestSendLoopAggregatesSustainedStream(t *testing.T) {
	f := newFakeCups(t)
	exitTr, clientTr, id := startExitClient(t, f)

	got := make(chan []byte, 4096)
	clientTr.Receive(func(p []byte) { got <- append([]byte(nil), p...) })

	const frames = 160
	const pktLen = 1304 // one striped piece's worth of tunnel payload
	pkts := make([][]byte, frames)
	for i := range pkts {
		pkts[i] = make([]byte, pktLen)
		for j := range pkts[i] {
			pkts[i][j] = byte('a' + (i+j)%26)
		}
		if err := exitTr.Send(pkts[i]); err != nil {
			t.Fatalf("Send %d: %v", i, err)
		}
	}

	seen := 0
	deadline := time.After(60 * time.Second)
	for seen < frames {
		select {
		case <-got:
			seen++
		case <-deadline:
			t.Fatalf("only %d/%d frames reached the client", seen, frames)
		}
	}

	applied, rejected, _ := f.stats(id)
	// 160 × 1304B raw against the 12288B batch cap is ≥17 flushes — but at
	// most a quarter of the per-frame sends the old 2ms/3072B settings
	// produced (which is the amplification bug under test).
	if applied > frames/4 {
		t.Errorf("sustained stream of %d frames cost %d change_code calls; want <= %d (25%% of per-frame sends)", frames, applied, frames/4)
	}
	if applied < 8 {
		t.Errorf("only %d batches for %d frames — payload must have been dropped or collapsed impossibly", applied, frames)
	}
	if rejected != 0 {
		t.Errorf("rejected = %d, want 0", rejected)
	}
	t.Logf("aggregation: %d frames (%d KB) -> %d change_code calls, doc=%dB", frames, frames*pktLen/1024, applied, len(f.codeOf(id)))
}

// ---- (2) document shrinks between bursts ----

func TestDocShrinksBetweenBursts(t *testing.T) {
	f := newFakeCups(t)
	exitTr, clientTr, id := startExitClient(t, f)

	got := make(chan []byte, 64)
	clientTr.Receive(func(p []byte) { got <- append([]byte(nil), p...) })

	big := make([]byte, 12000) // a video keyframe's worth of tunnel bytes
	for i := range big {
		big[i] = byte(i)
	}
	small := []byte("ofx-idle-keepalive")

	if err := exitTr.Send(big); err != nil {
		t.Fatalf("Send big: %v", err)
	}
	if p := <-got; !bytes.Equal(p, big) {
		t.Fatalf("big frame mangled: %d bytes", len(p))
	}
	codeBig := len(f.codeOf(id))

	if err := exitTr.Send(small); err != nil {
		t.Fatalf("Send small: %v", err)
	}
	deadline := time.After(20 * time.Second)
	for {
		select {
		case p := <-got:
			if bytes.Equal(p, small) {
				goto delivered
			}
		case <-deadline:
			t.Fatal("small frame never reached the client")
		}
	}
delivered:
	codeSmall := len(f.codeOf(id))

	tmpl := len(fakeTemplate())
	if codeSmall >= codeBig-10000 {
		t.Errorf("document did not shrink after a small frame: %dB -> %dB", codeBig, codeSmall)
	}
	if codeSmall > tmpl+400 {
		t.Errorf("document after small frame is %dB, want ~template (%dB) + one small block", codeSmall, tmpl)
	}
	// And the surviving block must carry the LATEST payload, byte-exact.
	if body := extractBlockSide(strings.Split(f.codeOf(id), "\n"), "X"); body != b64Frame(small) {
		t.Errorf("block body after shrink is %d bytes, want the small frame's b64 (%d bytes)", len(body), len(b64Frame(small)))
	}
	t.Logf("doc size: template=%dB, after 12KB frame=%dB, after 18B frame=%dB", tmpl, codeBig, codeSmall)
}

// ---- (3) stray blocks are pruned ----

func TestStrayBlocksPruned(t *testing.T) {
	f := newFakeCups(t)
	exitTr, clientTr, id := startExitClient(t, f)

	got := make(chan []byte, 64)
	clientTr.Receive(func(p []byte) { got <- append([]byte(nil), p...) })

	first := []byte("ofx-first-payload")
	_ = exitTr.Send(first)
	<-got

	// A fuzzy apply left a SECOND, foreign-separated copy of our block in the
	// document (spacer text between them: no single data-region hunk can
	// reach it). Plant it with a server-side mutate that ALSO rewrites our
	// block's body to the stale payload and strands the exit's baseline: the
	// next send's patch then provably cannot match (context gone → silent
	// no-op), forcing the full recover → prune → rewrite path.
	stray := blockText("X", 0, chunkLines(b64Frame([]byte("stale-copy"))))
	f.silentMutate(id, func(doc string) string {
		rewritten, _, _ := buildBlockEdit(doc, "X", 0, b64Frame([]byte("stale-copy")))
		return rewritten + "\n// spacer: foreign text between blocks\n" + stray + "\n"
	})

	payload := []byte("payload-after-stray")
	deadline := time.After(20 * time.Second)
	tick := time.NewTicker(150 * time.Millisecond)
	defer tick.Stop()
	_ = exitTr.Send(payload)
	for {
		select {
		case p := <-got:
			if bytes.Equal(p, payload) {
				goto delivered
			}
		case <-tick.C:
			_ = exitTr.Send(payload)
		case <-deadline:
			t.Fatal("payload never reached the client after the stray was planted")
		}
	}
delivered:
	// The document must converge to EXACTLY one block for our side.
	code := f.codeOf(id)
	for start := time.Now(); time.Since(start) < 10*time.Second; {
		if len(findBlocks(code, "X")) == 1 {
			break
		}
		time.Sleep(50 * time.Millisecond)
		code = f.codeOf(id)
	}
	if n := len(findBlocks(code, "X")); n != 1 {
		t.Fatalf("stray prune did not converge: %d blocks for side X, want 1", n)
	}
	if body := extractBlockSide(strings.Split(code, "\n"), "X"); body != b64Frame(payload) {
		t.Errorf("surviving block carries %d bytes, want the latest payload (%d bytes)", len(body), len(b64Frame(payload)))
	}
	if !strings.Contains(code, "foreign text") {
		t.Error("prune touched foreign document text — only our own stray block may be deleted")
	}
	_, _, noop := f.stats(id)
	if noop == 0 {
		t.Error("stale-baseline no-op never happened — the recovery path under test did not run")
	}
}

// ---- (4) cheap rebase: no room_info RPC when a push/reply tracked us ----

func TestRebasedBaseline(t *testing.T) {
	cases := []struct {
		name      string
		stored    string
		storedVer int64
		base      string
		baseVer   int64
		wantOK    bool
	}{
		{"nothing moved", "doc", 5, "doc", 5, false},
		{"content moved but version did not (versioned server must not trust it)", "doc2", 5, "doc1", 5, false},
		{"content and version moved", "doc2", 6, "doc1", 5, true},
		{"unversioned server, content moved", "doc2", -1, "doc1", -1, true},
		{"unversioned server, nothing moved", "doc", -1, "doc", -1, false},
		{"version moved past a stale-content baseline", "doc", 9, "doc", 4, false},
	}
	for _, c := range cases {
		w := &cupsWS{serverCode: c.stored, codeVersion: c.storedVer}
		_, ok := w.rebasedBaseline(c.base, c.baseVer)
		if ok != c.wantOK {
			t.Errorf("%s: rebasedBaseline = %v, want %v", c.name, ok, c.wantOK)
		}
	}
}

// Integration: the stale-baseline recovery (the live server answers every
// change_code with the authoritative document) must NOT spend a
// shared_editor_room_info round trip — the adopted reply code is enough.
func TestStaleRecoveryNeedsNoRoomInfo(t *testing.T) {
	f := newFakeCups(t)
	exitTr, clientTr, id := startExitClient(t, f)

	got := make(chan []byte, 64)
	clientTr.Receive(func(p []byte) { got <- append([]byte(nil), p...) })

	// First round trip establishes that the connect-time baseline fetch is
	// done, so the counter snapshot below is stable.
	seed := []byte("ofx-seed")
	_ = exitTr.Send(seed)
	<-got
	ri := f.roomInfoCount(id)

	f.silentMutate(id, func(doc string) string { return doc + "\n// server-side edit, push lost\n" })

	payload := []byte("ofx-after-stranding")
	deadline := time.After(20 * time.Second)
	tick := time.NewTicker(150 * time.Millisecond)
	defer tick.Stop()
	_ = exitTr.Send(payload)
	for {
		select {
		case p := <-got:
			if bytes.Equal(p, payload) {
				goto delivered
			}
		case <-tick.C:
			_ = exitTr.Send(payload)
		case <-deadline:
			t.Fatal("payload never landed after the baseline was stranded")
		}
	}
delivered:
	if got := f.roomInfoCount(id); got != ri {
		t.Errorf("stale recovery cost %d shared_editor_room_info calls, want 0 — the reply/push rebase regressed", got-ri)
	}
}

// ---- (5) config + latency pins ----

func TestDefaultBatchingConfig(t *testing.T) {
	c := DefaultCupsonlineConfig()
	if c.BatchTimeout != 70*time.Millisecond {
		t.Errorf("BatchTimeout = %v, want 70ms dwell", c.BatchTimeout)
	}
	if c.BatchIdleFlush != 12*time.Millisecond {
		t.Errorf("BatchIdleFlush = %v, want 12ms", c.BatchIdleFlush)
	}
	if c.MaxCodeBytesPerBatch != 12288 {
		t.Errorf("MaxCodeBytesPerBatch = %d, want 12288", c.MaxCodeBytesPerBatch)
	}
}

// One isolated send must still land promptly: the BatchTimeout dwell only
// applies while frames keep arriving (browse-latency protection).
func TestIsolatedSendFlushesPromptly(t *testing.T) {
	f := newFakeCups(t)
	exitTr, clientTr, _ := startExitClient(t, f)

	got := make(chan []byte, 4)
	clientTr.Receive(func(p []byte) { got <- append([]byte(nil), p...) })

	pkt := []byte("ofx-lone-packet")
	start := time.Now()
	if err := exitTr.Send(pkt); err != nil {
		t.Fatalf("Send: %v", err)
	}
	select {
	case p := <-got:
		if !bytes.Equal(p, pkt) {
			t.Fatalf("mangled: %q", p)
		}
		if d := time.Since(start); d > 5*time.Second {
			t.Errorf("lone send took %v to land — idle-flush must not wait out the BatchTimeout dwell", d)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("lone send never landed")
	}
}
