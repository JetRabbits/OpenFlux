package cupsonline

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/JetRabbits/OpenFlux/transport"
)

func fastCupsConfig() CupsonlineConfig {
	c := DefaultCupsonlineConfig()
	c.KeepAliveInterval = time.Hour // fake server answers pings anyway; keep tests quiet
	c.StatsInterval = time.Hour
	c.RoomCreatePause = time.Millisecond
	c.WSReadTimeout = 60 * time.Second
	c.ReconnectMinDelay = 20 * time.Millisecond
	c.ReconnectMaxDelay = 200 * time.Millisecond
	return c
}

func b64Frame(p ...[]byte) string {
	f, _ := framePackets(p)
	return base64.RawStdEncoding.EncodeToString(f)
}

func waitWSConnected(t *testing.T, tr *CupsonlineTransport, label string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		ok := len(tr.wss) > 0
		for _, w := range tr.wss {
			ok = ok && w.connected.Load()
		}
		if ok {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("%s: ws channels never became connected", label)
}

// applyEdit runs a buildBlockEdit patch through the reference server-side
// apply, asserting the transport's expectation matches what the server dialect
// actually produces (the fake's no-op path must never trigger for a patch
// computed from the true current document).
func applyEdit(t *testing.T, doc, side string, idx int, payloadB64 string) string {
	t.Helper()
	newDoc, diff, changed := buildBlockEdit(doc, side, idx, payloadB64)
	if !changed {
		t.Fatalf("edit reported unchanged for a document that needs the write")
	}
	got, applied, err := fakeApplyDiff(doc, diff)
	if err != nil {
		t.Fatalf("patch rejected as malformed: %v\n--- patch ---\n%s", err, diff)
	}
	if !applied {
		t.Fatalf("patch silently no-oped against its own base doc:\n--- patch ---\n%s", diff)
	}
	if got != newDoc {
		t.Fatalf("applied result != intended:\n got %q\nwant %q", got, newDoc)
	}
	return newDoc
}

// (a) Full-stack round trip: an exit transport (creates its room on the fake
// service) and a client transport (joins by room uuid, exit-style url blob)
// pass packets both ways through the code document — real constructors, real
// Start/Send/Receive paths.
func TestTwoPeersRoundTrip(t *testing.T) {
	f := newFakeCups(t)
	f.pointBaseAt(t)

	exitTr := NewCupsonlineTransport("", transport.DefaultConfig(), false)
	exitTr.config = fastCupsConfig()
	exitTr.config.NumRooms = 1
	exitGot := make(chan []byte, 128)
	exitTr.Receive(func(p []byte) { exitGot <- append([]byte(nil), p...) })
	if err := exitTr.Start(); err != nil {
		t.Fatalf("exit Start: %v", err)
	}
	defer exitTr.Stop()

	ids := exitTr.RoomUUIDs()
	if len(ids) != 1 {
		t.Fatalf("exit room count = %d, want 1", len(ids))
	}
	raw, _ := json.Marshal(ids)

	clientTr := NewCupsonlineTransport("?rooms="+base64.RawURLEncoding.EncodeToString(raw), transport.DefaultConfig(), true)
	clientTr.config = fastCupsConfig()
	clientGot := make(chan []byte, 128)
	clientTr.Receive(func(p []byte) { clientGot <- append([]byte(nil), p...) })
	if err := clientTr.Start(); err != nil {
		t.Fatalf("client Start: %v", err)
	}
	defer clientTr.Stop()

	waitWSConnected(t, exitTr, "exit")
	waitWSConnected(t, clientTr, "client")

	pktA := []byte("ofx-exit-packet-1")
	pktB := []byte("ofx-client-packet-1")

	gotA, gotB := false, false
	deadline := time.After(20 * time.Second)
	tick := time.NewTicker(150 * time.Millisecond)
	defer tick.Stop()
	_ = exitTr.Send(pktA)
	_ = clientTr.Send(pktB)
	for !gotA || !gotB {
		select {
		case p := <-clientGot:
			if bytes.Equal(p, pktA) {
				gotA = true
			}
		case p := <-exitGot:
			if bytes.Equal(p, pktB) {
				gotB = true
			}
		case <-tick.C:
			if !gotA {
				_ = exitTr.Send(pktA)
			}
			if !gotB {
				_ = clientTr.Send(pktB)
			}
		case <-deadline:
			applied, rejected, noop := f.stats(ids[0])
			t.Fatalf("round trip incomplete: exit->client=%v client->exit=%v (server applied=%d rejected=%d noop=%d, exit stats %+v, client stats %+v)",
				gotA, gotB, applied, rejected, noop, exitTr.Stats(), clientTr.Stats())
		}
	}

	if st := waitForStats(t, exitTr, 1, 1); st.PacketsSent < 1 || st.PacketsRecv < 1 {
		t.Fatalf("exit stats: %+v", st)
	}
	if st := waitForStats(t, clientTr, 1, 1); st.PacketsSent < 1 || st.PacketsRecv < 1 {
		t.Fatalf("client stats: %+v", st)
	}
}

// waitForStats polls until both counters reach at least the given values (the
// sender's counters tick in its send-loop goroutine a hair after the peer's
// packet lands, so an immediate read can lag by scheduling).
func waitForStats(t *testing.T, tr *CupsonlineTransport, minSent, minRecv uint64) transport.TransportStats {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		st := tr.Stats()
		if st.PacketsSent >= minSent && st.PacketsRecv >= minRecv {
			return st
		}
		if time.Now().After(deadline) {
			return st
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// (b) Stale-baseline recovery the LIVE way: a server-side edit that never
// broadcast a push strands the exit's baseline; the first change_code is
// SILENTLY NO-OPED (version bump, doc untouched — no 400!), and the transport
// must notice via the authoritative code in the RPC reply, refetch room_info
// and land the packet on the retry.
func TestStaleBaselineRecovery(t *testing.T) {
	f := newFakeCups(t)
	f.pointBaseAt(t)

	exitTr := NewCupsonlineTransport("", transport.DefaultConfig(), false)
	exitTr.config = fastCupsConfig()
	exitTr.config.NumRooms = 1
	if err := exitTr.Start(); err != nil {
		t.Fatalf("exit Start: %v", err)
	}
	defer exitTr.Stop()
	ids := exitTr.RoomUUIDs()

	clientTr := NewCupsonlineTransport(mustPack(ids), transport.DefaultConfig(), true)
	clientTr.config = fastCupsConfig()
	clientGot := make(chan []byte, 128)
	clientTr.Receive(func(p []byte) { clientGot <- append([]byte(nil), p...) })
	if err := clientTr.Start(); err != nil {
		t.Fatalf("client Start: %v", err)
	}
	defer clientTr.Stop()

	waitWSConnected(t, exitTr, "exit")
	waitWSConnected(t, clientTr, "client")

	// Out-of-band edit touching the rune region where the exit's first append
	// patch places its context — the stored document no longer matches what
	// exit believes.
	f.silentMutate(ids[0], func(code string) string {
		lines := strings.Split(code, "\n")
		for i := len(lines) - 1; i >= 0; i-- {
			if strings.TrimSpace(lines[i]) != "" {
				lines[i] = "// строчка подменена другим редактором"
				break
			}
		}
		return strings.Join(lines, "\n")
	})

	pkt := []byte("ofx-after-stale")
	arrived := false
	deadline := time.After(20 * time.Second)
	tick := time.NewTicker(150 * time.Millisecond)
	defer tick.Stop()
	_ = exitTr.Send(pkt)
	for !arrived {
		select {
		case p := <-clientGot:
			if bytes.Equal(p, pkt) {
				arrived = true
			}
		case <-tick.C:
			_ = exitTr.Send(pkt)
		case <-deadline:
			_, rejected, noop := f.stats(ids[0])
			t.Fatalf("packet never arrived; noop=%d rejected=%d, exit stats %+v", noop, rejected, exitTr.Stats())
		}
	}

	_, _, noop := f.stats(ids[0])
	if noop == 0 {
		t.Fatal("expected at least one silent server-side no-op that the transport recovered from")
	}

	// The sender adopts its own write (authoritative reply / its own echo
	// push) in its own goroutines a moment after the peer sees the packet;
	// poll the baseline until it converges.
	w := exitTr.wss[0]
	deadlineBase := time.Now().Add(10 * time.Second)
	var code string
	for {
		w.codeMu.Lock()
		code = w.serverCode
		w.codeMu.Unlock()
		if strings.Contains(code, "подменена") && strings.Contains(code, "//OCX-0-BEGIN") {
			break
		}
		if time.Now().After(deadlineBase) {
			t.Fatalf("exit baseline never converged after recovery; has-mutation=%v has-block=%v:\n%s",
				strings.Contains(code, "подменена"), strings.Contains(code, "//OCX-0-BEGIN"), code)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func mustPack(ids []string) string {
	raw, _ := json.Marshal(ids)
	return "?rooms=" + base64.RawURLEncoding.EncodeToString(raw)
}

// (c) Block replacement idempotency through the real patch/apply path: our
// block is rewritten repeatedly, the template and the peer's block stay
// byte-identical, and every patch the builder emits applies for real.
func TestBlockUpsertIdempotentPreservesTemplateAndPeer(t *testing.T) {
	peerB64 := b64Frame([]byte("peer-payload-that-must-survive-every-rewrite"))
	base := applyEdit(t, fakeTemplate(), "Y", 0, peerB64)

	p1 := b64Frame([]byte("first payload"))
	p2 := b64Frame([]byte("second payload"), []byte("and more"))

	c1 := applyEdit(t, base, "X", 0, p1)
	c2 := applyEdit(t, c1, "X", 0, p2)

	if n := strings.Count(c2, "//OCX-0-BEGIN") + strings.Count(c2, "//OCX-0-END"); n != 2 {
		t.Fatalf("our block markers must appear exactly once each, got %d total", n)
	}
	lines := strings.Split(c2, "\n")
	if got := extractBlockSide(lines, "X"); got != p2 {
		t.Fatalf("our block was not replaced in place: got %q want %q", got, p2)
	}
	if strings.Contains(c2, p1) {
		t.Fatal("stale first payload still present after in-place replacement")
	}
	if got := extractBlockSide(lines, "Y"); got != peerB64 {
		t.Fatal("peer block was disturbed by our rewrite")
	}
	// Template preserved line-for-line: removing both blocks rebuilds the
	// template exactly — the template's own trailing newline became the
	// separator above our block, and our block's closing newline survives as
	// the document's final line break.
	ours := removeBlockSide(lines, "X")
	theirs := removeBlockSide(ours, "Y")
	if got := strings.Join(theirs, "\n"); got != fakeTemplate() {
		t.Fatalf("template text was disturbed:\n%q", got)
	}

	// Reconnect-style third round: same block, another payload, still exactly
	// one block.
	c3 := applyEdit(t, c2, "X", 0, p1)
	if n := strings.Count(c3, "//OCX-0-BEGIN"); n != 1 {
		t.Fatalf("block count after 3rd rewrite = %d, want 1", n)
	}
	if got := extractBlockSide(strings.Split(c3, "\n"), "X"); got != p1 {
		t.Fatal("3rd rewrite did not take")
	}
	if got := extractBlockSide(strings.Split(c3, "\n"), "Y"); got != peerB64 {
		t.Fatal("peer block lost during 3rd rewrite")
	}

	// No-op detection: rewriting the SAME payload must report unchanged.
	if _, _, changed := buildBlockEdit(c3, "X", 0, p1); changed {
		t.Fatal("identical payload rewrite must be a no-op")
	}
}

// (c2) A stale duplicate of OUR block (only a fuzzy server apply could create
// it) collapses back into exactly one block through the contiguous-run path.
func TestBlockDuplicateCollapse(t *testing.T) {
	base := applyEdit(t, fakeTemplate(), "Y", 0, b64Frame([]byte("peer-data")))
	c1 := applyEdit(t, base, "X", 0, b64Frame([]byte("dup-a")))

	// Fabricate two ADJACENT copies of our block (c1 already ends with the
	// first block's closing newline, so the second starts immediately after:
	// exactly the layout the collapse path claims to handle).
	dup := c1 + blockText("X", 0, chunkLines(b64Frame([]byte("dup-b")))) + "\n"
	blocks := findBlocks(dup, "X")
	if len(blocks) != 2 {
		t.Fatalf("findBlocks found %d, want 2", len(blocks))
	}

	c2 := applyEdit(t, dup, "X", 0, b64Frame([]byte("after-collapse")))
	if n := strings.Count(c2, "//OCX-0-BEGIN"); n != 1 {
		t.Fatalf("collapse left %d blocks, want 1", n)
	}
	if got := extractBlockSide(strings.Split(c2, "\n"), "X"); got != b64Frame([]byte("after-collapse")) {
		t.Fatal("collapse payload wrong")
	}
	if got := extractBlockSide(strings.Split(c2, "\n"), "Y"); got != b64Frame([]byte("peer-data")) {
		t.Fatal("collapse disturbed the peer block")
	}
}

// (d) 2-byte length framing across chunked base64 lines: a packet far larger
// than one chunk line must round-trip through block build → extract → decode →
// split intact.
func TestFramingAcrossChunkLines(t *testing.T) {
	packets := [][]byte{[]byte("tiny"), bytes.Repeat([]byte{0xAB, 0x7F, 0x00}, 1500), []byte("last")}
	framed, total := framePackets(packets)
	if want := 4 + 4500 + 4; total != want {
		t.Fatalf("framed total = %d, want %d", total, want)
	}
	col := base64.RawStdEncoding.EncodeToString(framed)

	code := applyEdit(t, fakeTemplate(), "X", 3, col)
	lines := strings.Split(code, "\n")
	inBlock := false
	chunks := 0
	for _, ln := range lines {
		if s, _, kind, ok := parseBlockMarker(ln); ok {
			inBlock = s == "X" && kind == "BEGIN"
			continue
		}
		if inBlock {
			chunks++
			if len(ln) > b64LineChunk {
				t.Fatalf("chunk line of %d chars exceeds %d", len(ln), b64LineChunk)
			}
		}
	}
	if chunks <= 1 {
		t.Fatalf("payload should span multiple chunk lines, got %d", chunks)
	}

	body := extractBlockSide(lines, "X")
	if body != col {
		t.Fatal("extracted block body differs from written payload")
	}
	var recovered [][]byte
	n, tot := splitPackets(decodeBlockPayload(body), func(p []byte) {
		recovered = append(recovered, append([]byte(nil), p...))
	})
	if n != 3 || tot != total || !reflect.DeepEqual(recovered, packets) {
		t.Fatalf("split/join mismatch: n=%d tot=%d packets=%v", n, tot, recovered)
	}

	// A second oversized write must replace the first (multi-line → multi-line).
	code2 := applyEdit(t, code, "X", 3, base64.RawStdEncoding.EncodeToString(func() []byte {
		f2, _ := framePackets([][]byte{bytes.Repeat([]byte("Z"), 3000)})
		return f2
	}()))
	if strings.Count(code2, "//OCX-3-BEGIN") != 1 {
		t.Fatal("second oversized write must replace, not append")
	}
}

// (e) Dedupe of code_update pushes: our own edits echo back with an unchanged
// peer block and must not redeliver; replays (by version) and identical
// payloads (by hash) are filtered; genuinely new peer payloads pass.
func TestCodeUpdateDedupeAndDelivery(t *testing.T) {
	var got [][]byte
	w := &cupsWS{
		auth:        &cupsAuth{roomUUID: "11111111-2222-3333-4444-555555555555", userUUID: "u-self"},
		side:        "Y",
		peerSide:    "X",
		roomIdx:     0,
		config:      fastCupsConfig(),
		stats:       &channelStats{},
		codeVersion: -1,
		pending:     map[int64]chan rpcResp{},
		onData:      func(p []byte) { got = append(got, append([]byte(nil), p...)) },
	}

	base := applyEdit(t, fakeTemplate(), "X", 0, b64Frame([]byte("pre-existing-peer-data")))
	info, _ := json.Marshal(map[string]interface{}{"uuid": "r", "code": base, "version": 7})
	if err := w.applyRoomInfo(info); err != nil {
		t.Fatalf("applyRoomInfo: %v", err)
	}

	push := func(code string, ver int) []byte {
		raw, _ := json.Marshal(map[string]interface{}{"push": map[string]interface{}{
			"channel": "$shared_editor:room-r",
			"pub": map[string]interface{}{
				"data": map[string]interface{}{"type": "code_update",
					"payload": map[string]interface{}{"uuid": "r", "code": code, "version": ver}},
				"offset": ver,
			},
		}})
		return raw
	}

	// Our own edit echoes back (version bumped, peer block untouched): silent.
	w.handleMessage(push(base, 8))
	if len(got) != 0 {
		t.Fatalf("own-echo push delivered %d packets, want 0", len(got))
	}

	// Peer's fresh payload: delivered.
	withP2 := applyEdit(t, base, "X", 0, b64Frame([]byte("P2-a"), []byte("P2-b")))
	w.handleMessage(push(withP2, 9))
	if len(got) != 2 || string(got[0]) != "P2-a" || string(got[1]) != "P2-b" {
		t.Fatalf("peer payload delivery = %q, want [P2-a P2-b]", got)
	}

	// Duplicate of the same push, then a stale replay: both silent.
	w.handleMessage(push(withP2, 9))
	w.handleMessage(push(base, 8))
	if len(got) != 2 {
		t.Fatalf("duplicate/stale pushes leaked %d extra packets", len(got)-2)
	}

	// Our send echoes (our block changed, peer block same): silent.
	own := applyEdit(t, withP2, "Y", 0, b64Frame([]byte("our-data")))
	w.handleMessage(push(own, 10))
	if len(got) != 2 {
		t.Fatalf("our own echo leaked %d packets", len(got)-2)
	}

	// Peer payload again: delivered; baseline follows the newest document.
	withP3 := applyEdit(t, own, "X", 0, b64Frame([]byte("P3")))
	w.handleMessage(push(withP3, 11))
	if len(got) != 3 || string(got[2]) != "P3" {
		t.Fatalf("second peer payload = %q, want [P2-a P2-b P3]", got)
	}
	w.codeMu.Lock()
	if w.serverCode != withP3 || w.codeVersion != 11 {
		w.codeMu.Unlock()
		t.Fatal("baseline did not adopt the newest pushed code/version")
	}
	w.codeMu.Unlock()

	if st := w.stats; st.packetsRecv.Load() != 3 || st.batchesRecv.Load() != 2 {
		t.Fatalf("recv stats: packets=%d batches=%d, want 3/2", st.packetsRecv.Load(), st.batchesRecv.Load())
	}
}

// Same dedupe contract when the payload carries no version: fall back to the
// peer-block content hash.
func TestCodeUpdateDedupeWithoutVersion(t *testing.T) {
	var got [][]byte
	w := &cupsWS{
		auth:        &cupsAuth{roomUUID: "r", userUUID: "u-self"},
		side:        "Y",
		peerSide:    "X",
		roomIdx:     0,
		config:      fastCupsConfig(),
		stats:       &channelStats{},
		codeVersion: -1,
		pending:     map[int64]chan rpcResp{},
		onData:      func(p []byte) { got = append(got, append([]byte(nil), p...)) },
	}
	if err := w.applyRoomInfo([]byte(`{"code":"template line\n"}`)); err != nil {
		t.Fatalf("applyRoomInfo: %v", err)
	}
	pushNoVer := func(code string) []byte {
		raw, _ := json.Marshal(map[string]interface{}{"push": map[string]interface{}{
			"channel": "$shared_editor:room-r",
			"pub": map[string]interface{}{"data": map[string]interface{}{"type": "code_update",
				"payload": map[string]interface{}{"uuid": "r", "code": code}}},
		}})
		return raw
	}
	withPeer := applyEdit(t, "template line\n", "X", 0, b64Frame([]byte("V1")))
	w.handleMessage(pushNoVer(withPeer))
	if len(got) != 1 || string(got[0]) != "V1" {
		t.Fatalf("first push delivered %q", got)
	}
	w.handleMessage(pushNoVer(withPeer))
	if len(got) != 1 {
		t.Fatal("identical payload without version must be deduped by hash")
	}
}

func TestJsEncodeMatchesEncodeURIComponent(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"abcABC012-_.!~*'()", "abcABC012-_.!~*'()"},
		{" ", "%20"},
		{"Привет", "%D0%9F%D1%80%D0%B8%D0%B2%D0%B5%D1%82"},
		{"a=b&c;d", "a%3Db%26c%3Bd"},
		{`{}":,`, "%7B%7D%22%3A%2C"},
		{"%41", "%2541"},
		{"tab\there", "tab%09here"},
		{"nl\nnl", "nl%0Anl"},
	} {
		if got := jsEncode(tc.in); got != tc.want {
			t.Errorf("jsEncode(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// Byte-for-byte reproductions of the live frames captured 2026-10 (the ground
// truth that killed the line-granular generator), plus the same dialect's
// replace shape and the fake server's failure semantics.
func TestMakeDiffLiveFrameGoldens(t *testing.T) {
	// Frame 1 (APPEND): client "Y" block appended after "...yTest;\n\n".
	// 1591 rune offset = end of a 1599-rune document minus the 8-rune context
	// "yTest;\n\n"; old=8 (ctx+del), new=43 (ctx + 35-rune insertion).
	doc1 := strings.Repeat("x", 1591) + "yTest;\n\n"
	ins1 := "//OCY-1-BEGIN\nQUJDRA==\n//OCY-1-END\n"
	want1 := "@@ -1591,8 +1591,43 @@\n yTest%3B%0A%0A\n+%2F%2FOCY-1-BEGIN%0AQUJDRA%3D%3D%0A%2F%2FOCY-1-END%0A\n"
	got1 := makeDiff(1591, "yTest;\n\n", "", ins1)
	if got1 != want1 {
		t.Fatalf("append frame:\n got %q\nwant %q", got1, want1)
	}
	if res, applied, err := fakeApplyDiff(doc1, got1); err != nil || !applied || res != doc1+ins1 {
		t.Fatalf("append frame must apply: applied=%v err=%v", applied, err)
	}

	// Frame 2 (DELETE): remove "RkZGRg==" sitting right after context
	// "QUJDRA==" at rune 1564; old=8+8, new=8+0.
	doc2 := strings.Repeat("x", 1564) + "QUJDRA==RkZGRg==tail"
	want2 := "@@ -1564,16 +1564,8 @@\n QUJDRA%3D%3D\n-RkZGRg%3D%3D\n"
	got2 := makeDiff(1564, "QUJDRA==", "RkZGRg==", "")
	if got2 != want2 {
		t.Fatalf("delete frame:\n got %q\nwant %q", got2, want2)
	}
	if res, applied, err := fakeApplyDiff(doc2, got2); err != nil || !applied || res != strings.Repeat("x", 1564)+"QUJDRA==tail" {
		t.Fatalf("delete frame must apply: applied=%v err=%v", applied, err)
	}

	// Frame 3 (REPLACE): block-content swap — same context, "-" the old data,
	// "+" the new data; old=8+8, new=8+8.
	want3 := "@@ -1564,16 +1564,16 @@\n QUJDRA%3D%3D\n-RkZGRg%3D%3D\n+QUJDRQ%3D%3D\n"
	got3 := makeDiff(1564, "QUJDRA==", "RkZGRg==", "QUJDRQ==")
	if got3 != want3 {
		t.Fatalf("replace frame:\n got %q\nwant %q", got3, want3)
	}
	if res, applied, err := fakeApplyDiff(doc2, got3); err != nil || !applied || res != strings.Repeat("x", 1564)+"QUJDRA==QUJDRQ==tail" {
		t.Fatalf("replace frame must apply: applied=%v err=%v", applied, err)
	}

	// A stale patch (context moved) must be a SILENT no-op, not an error.
	if _, applied, err := fakeApplyDiff(doc2+"more", makeDiff(1564, "ZZZZZZZZ", "RkZGRg==", "")); err != nil || applied {
		t.Fatalf("stale patch: applied=%v err=%v, want no-op without error", applied, err)
	}
	// Header accounting that contradicts the chunks is Django-400 territory.
	if _, _, err := fakeApplyDiff(doc2, "@@ -1564,99 +1564,8 @@\n QUJDRA%3D%3D\n-RkZGRg%3D%3D\n"); err == nil {
		t.Fatal("bogus old length must be a malformed patch")
	}
}

// The builder's own context policy: 12-rune keep chunks, and offsets/lengths
// counted in RUNES (Cyrillic template would shift byte offsets).
func TestBuildBlockEditRuneOffsets(t *testing.T) {
	tmpl := "// Привет, мир — шаблон с юникодом\nconsole.log('тест');\n// конец\n"
	doc := applyEdit(t, tmpl, "X", 0, b64Frame([]byte("payload-one")))
	if blocks := findBlocks(doc, "X"); len(blocks) != 1 {
		t.Fatalf("blocks=%d", len(blocks))
	}
	b := findBlocks(doc, "X")[0]

	// Replace edit: ctx must be exactly 12 runes ending at the region start —
	// the tail of our BEGIN line.
	newDoc, diff, changed := buildBlockEdit(doc, "X", 0, b64Frame([]byte("payload-two")))
	if !changed {
		t.Fatal("changed")
	}
	lines := strings.Split(strings.TrimSuffix(diff, "\n"), "\n")
	ctxChunk, err := pctDecode(strings.TrimPrefix(lines[1], " "))
	if err != nil {
		t.Fatal(err)
	}
	if r := utf8.RuneCountInString(ctxChunk); r != 12 {
		t.Fatalf("ctx runes = %d, want 12 (%q)", r, ctxChunk)
	}
	if !strings.HasSuffix(ctxChunk, "\n") {
		t.Fatalf("ctx must end at the BEGIN line's newline, got %q", ctxChunk)
	}
	// Header offset must equal the rune (not byte) index of the ctx start.
	m := reFakeHunk.FindStringSubmatch(lines[0])
	if m == nil {
		t.Fatalf("bad header %q", lines[0])
	}
	off, _ := strconv.Atoi(m[1])
	olen, _ := strconv.Atoi(m[2])
	if off != b.dataStartRune-utf8.RuneCountInString(ctxChunk) {
		t.Fatalf("header offset %d != ctx start rune %d", off, b.dataStartRune-utf8.RuneCountInString(ctxChunk))
	}
	if olen != utf8.RuneCountInString(ctxChunk)+utf8.RuneCountInString(doc[b.dataStartByte:b.dataEndByte]) {
		t.Fatalf("header old length %d wrong", olen)
	}
	if got, applied, aerr := fakeApplyDiff(doc, diff); aerr != nil || !applied || got != newDoc {
		t.Fatalf("rune-offset patch must apply over Cyrillic text: applied=%v err=%v", applied, aerr)
	}
}
