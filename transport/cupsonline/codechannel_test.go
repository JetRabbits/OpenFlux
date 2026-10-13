package cupsonline

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

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
			applied, rejected := f.stats(ids[0])
			t.Fatalf("round trip incomplete: exit->client=%v client->exit=%v (server applied=%d rejected=%d, exit stats %+v, client stats %+v)",
				gotA, gotB, applied, rejected, exitTr.Stats(), clientTr.Stats())
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

// (b) Stale-baseline recovery: a server-side edit that never broadcast a push
// strands the exit's baseline; the first change_code must hit the 400, refetch
// room_info and land the packet on the retry.
func TestStaleBaseline400Recovery(t *testing.T) {
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

	// Out-of-band edit that replaces a line inside every diff's trailing
	// context — the stored document no longer matches what exit believes.
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
			_, rejected := f.stats(ids[0])
			t.Fatalf("packet never arrived; rejections so far=%d, exit stats %+v", rejected, exitTr.Stats())
		}
	}

	_, rejected := f.stats(ids[0])
	if rejected == 0 {
		t.Fatal("expected at least one server-side 400 (stale diff) that the transport recovered from")
	}

	// The sender adopts its own write (applyChangeSuccess / its own echo push)
	// in its own goroutines a moment after the peer sees the packet; poll the
	// baseline until it converges.
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

// (c) Block replacement idempotency through the real diff/apply path: our
// block is rewritten repeatedly, the template and the peer's block stay
// byte-identical, and every diff the generator emits applies cleanly.
func TestBlockUpsertIdempotentPreservesTemplateAndPeer(t *testing.T) {
	peerB64 := b64Frame([]byte("peer-payload-that-must-survive-every-rewrite"))
	base := fakeTemplate() + strings.Join(buildBlockLines("Y", 0, peerB64), "\n")

	p1 := b64Frame([]byte("first payload"))
	p2 := b64Frame([]byte("second payload"), []byte("and more"))

	apply := func(from, to string) string {
		got, err := fakeApplyDiff(from, makeDiff(from, to))
		if err != nil {
			t.Fatalf("generated diff does not apply: %v\n--- diff ---\n%s", err, makeDiff(from, to))
		}
		if got != to {
			t.Fatalf("applied result != intended newCode:\n%q\n%q", got, to)
		}
		return got
	}

	c1 := apply(base, upsertBlock(base, "X", 0, p1))
	c2 := apply(c1, upsertBlock(c1, "X", 0, p2))

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
	// Template preserved line-for-line: removing both blocks must rebuild the
	// template (the template's trailing "\n" is just the separator that joins
	// it to the peer block, so it is not part of any line).
	ours := removeBlockSide(lines, "X")
	theirs := removeBlockSide(ours, "Y")
	if got := strings.Join(theirs, "\n"); got != strings.TrimSuffix(fakeTemplate(), "\n") {
		t.Fatalf("template text was disturbed:\n%q", got)
	}

	// Reconnect-style third round: same block, another payload, still exactly one.
	c3 := apply(c2, upsertBlock(c2, "X", 0, p1))
	if n := strings.Count(c3, "//OCX-0-BEGIN"); n != 1 {
		t.Fatalf("block count after 3rd rewrite = %d, want 1", n)
	}
	if got := extractBlockSide(strings.Split(c3, "\n"), "X"); got != p1 {
		t.Fatal("3rd rewrite did not take")
	}
	if got := extractBlockSide(strings.Split(c3, "\n"), "Y"); got != peerB64 {
		t.Fatal("peer block lost during 3rd rewrite")
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

	code := upsertBlock(fakeTemplate(), "X", 3, col)
	lines := strings.Split(code, "\n")
	inBlock := false
	chunks := 0
	for _, ln := range lines {
		if _, _, kind, ok := parseBlockMarker(ln); ok {
			inBlock = kind == "BEGIN"
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

	// The whole thing must still travel as one applying diff.
	if got, err := fakeApplyDiff(fakeTemplate(), makeDiff(fakeTemplate(), code)); err != nil || got != code {
		t.Fatalf("diff for chunked block: %v", err)
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

	base := fakeTemplate() + strings.Join(buildBlockLines("X", 0, b64Frame([]byte("pre-existing-peer-data"))), "\n")
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
	withP2 := upsertBlock(base, "X", 0, b64Frame([]byte("P2-a"), []byte("P2-b")))
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
	own := upsertBlock(withP2, "Y", 0, b64Frame([]byte("our-data")))
	w.handleMessage(push(own, 10))
	if len(got) != 2 {
		t.Fatalf("our own echo leaked %d packets", len(got)-2)
	}

	// Peer payload again: delivered; baseline follows the newest document.
	withP3 := upsertBlock(own, "X", 0, b64Frame([]byte("P3")))
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
	withPeer := upsertBlock("template line\n", "X", 0, b64Frame([]byte("V1")))
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
	} {
		if got := jsEncode(tc.in); got != tc.want {
			t.Errorf("jsEncode(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestMakeDiffGolden(t *testing.T) {
	// Pure append at EOF.
	old := "alpha\nbeta\ngamma"
	new_ := "alpha\nbeta\ngamma\n//OCX-0-BEGIN\nQUJDRA\n//OCX-0-END"
	want := "@@ -1,3 +1,6 @@\n alpha\n beta\n gamma\n+%2F%2FOCX-0-BEGIN\n+QUJDRA\n+%2F%2FOCX-0-END\n"
	if got := makeDiff(old, new_); got != want {
		t.Fatalf("append hunk:\n got %q\nwant %q", got, want)
	}
	if got, err := fakeApplyDiff(old, want); err != nil || got != new_ {
		t.Fatalf("golden hunk must apply: %v", err)
	}

	// Replacement in the middle, 3 context lines each side.
	var o []string
	for i := 0; i < 10; i++ {
		o = append(o, string(rune('a'+i)))
	}
	n := append([]string{}, o...)
	n[5], n[6] = "X", "Y"
	got := makeDiff(strings.Join(o, "\n"), strings.Join(n, "\n"))
	if !strings.HasPrefix(got, "@@ -3,8 +3,8 @@\n") {
		t.Fatalf("middle hunk header wrong:\n%s", got)
	}
	if res, err := fakeApplyDiff(strings.Join(o, "\n"), got); err != nil || res != strings.Join(n, "\n") {
		t.Fatalf("middle hunk must apply: %v", err)
	}

	// Long documents: leading context must not exceed diffContextLines.
	long := strings.Repeat("ctx\n", 50) + "oldline\n"
	changed := strings.Repeat("ctx\n", 50) + "newline\n"
	d := makeDiff(strings.TrimSuffix(long, "\n"), strings.TrimSuffix(changed, "\n"))
	lines := strings.Split(strings.TrimSuffix(d, "\n"), "\n")
	ctxBefore := 0
	for _, ln := range lines[1:] {
		if strings.HasPrefix(ln, " ") {
			ctxBefore++
		} else {
			break
		}
	}
	if ctxBefore > diffContextLines {
		t.Fatalf("leading context %d exceeds %d", ctxBefore, diffContextLines)
	}
	if res, err := fakeApplyDiff(strings.TrimSuffix(long, "\n"), d); err != nil || res != strings.TrimSuffix(changed, "\n") {
		t.Fatalf("long-doc hunk must apply: %v", err)
	}
}
