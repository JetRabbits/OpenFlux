package cupsonline

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/gorilla/websocket"
)

// fakeServer emulates interview.cups.online closely enough to exercise the
// whole transport offline: the Django room page (centrifuge metas, escaped
// data-room/data-user attrs, csrftoken cookie), the subscription-token RPC
// endpoint, and the Centrifugo websocket (connect / subscribe / rpc with id
// correlation). Room state is an in-memory code document; shared_editor_change_
// code validates that the submitted diff's hunk context matches the stored text
// (rejecting stale baselines with the same 400 shape as the real Django API),
// applies it, bumps the version and broadcasts code_update pushes with the FULL
// document to every subscriber — including the sender, exactly like the real
// service.

func fakeTemplate() string {
	return strings.Join([]string{
		"// Шаблон комнаты для собеседования (cups.online)",
		"// Пишите код здесь — второй участник видит его сразу.",
		"",
		"function greet(name) {",
		"\treturn `Привет, ${name}!`;",
		"}",
		"",
		"def fib(n):",
		"\ta, b = 0, 1",
		"\tfor _ in range(n):",
		"\t\ta, b = b, a + b",
		"\treturn a",
		"",
		"SELECT имя, COUNT(*) AS cnt FROM users GROUP BY имя;",
		"-- заметка: проверка не-ASCII в контексте диффов",
		"",
		"int main() { printf(\"тест %d\\n\", 42); return 0; }",
		"console.log(greet('мир'), fib(10)); // хеллоу, мир",
	}, "\n") + "\n"
}

type fakeRoom struct {
	mu       sync.Mutex
	code     string
	version  int64
	subs     map[*fakePeer]bool
	rejected int
	applied  int
	noop     int // change_code calls whose patch did not match (silent no-op)

	roomInfo int // shared_editor_room_info calls for this room
	calls    int // shared_editor_change_code calls seen

	// ---- pipelined-writer test knobs (guarded by mu; zero/nil = off) ----

	// replyDelays holds back the change_code REPLY of the k-th call (the
	// last entry repeats) while the code_update push of that call goes out
	// immediately — the server still applies calls in arrival order, but the
	// RPC responses reach the writer late and possibly out of order, the
	// way concurrent Django workers can deliver them.
	replyDelays []time.Duration
	// gate, when non-nil, makes every change_code reply wait for a token
	// (push unaffected) — the writer's in-flight window starves unless it
	// keeps consuming replies.
	gate chan struct{}
	// forceNoop silently no-ops the next N calls whose patch WOULD apply —
	// a deterministic "server did not apply your write" for the writer's
	// first pipelined send.
	forceNoop int
}

type fakeServer struct {
	t   *testing.T
	srv *httptest.Server

	mu    sync.Mutex
	rooms map[string]*fakeRoom

	upgrader websocket.Upgrader
}

func newFakeCups(t *testing.T) *fakeServer {
	f := &fakeServer{t: t, rooms: map[string]*fakeRoom{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/live-coding/", f.handleRoom)
	mux.HandleFunc("/api/subtoken", f.handleSubToken)
	mux.HandleFunc("/cf/websocket", f.handleWS)
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

// pointBaseAt redirects the transport constructors/joins at this fake server.
func (f *fakeServer) pointBaseAt(t *testing.T) {
	old := roomBaseURL
	roomBaseURL = f.srv.URL + "/live-coding/"
	t.Cleanup(func() { roomBaseURL = old })
}

func newUUID(t *testing.T) string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func newHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func (f *fakeServer) roomObj(uuid string) *fakeRoom {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.rooms[uuid]
}

// stats returns applied/rejected/noop change_code counters for a room.
func (f *fakeServer) stats(uuid string) (applied, rejected, noop int) {
	r := f.roomObj(uuid)
	if r == nil {
		return 0, 0, 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.applied, r.rejected, r.noop
}

// silentMutate changes the stored document server-side WITHOUT broadcasting a
// push — the only way to deterministically strand a subscriber's baseline
// (models a lost push / race the stale-baseline recovery must survive).
func (f *fakeServer) silentMutate(uuid string, fn func(string) string) int64 {
	r := f.roomObj(uuid)
	if r == nil {
		f.t.Fatalf("no room %s", uuid)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.code = fn(r.code)
	r.version++
	return r.version
}

// mutateAndPush changes the stored document AND broadcasts a code_update push
// with the new version: subscribers' baselines move forward WITHOUT any RPC
// (the tracked-push case the cheap stale-baseline rebase rides on).
func (f *fakeServer) mutateAndPush(uuid string, fn func(string) string) int64 {
	r := f.roomObj(uuid)
	if r == nil {
		f.t.Fatalf("no room %s", uuid)
	}
	r.mu.Lock()
	r.code = fn(r.code)
	r.version++
	ver := r.version
	codeNow := r.code
	subs := make([]*fakePeer, 0, len(r.subs))
	for sp := range r.subs {
		subs = append(subs, sp)
	}
	r.mu.Unlock()
	ch := "$shared_editor:room-" + uuid
	for _, sp := range subs {
		sp.send(map[string]interface{}{"push": map[string]interface{}{
			"channel": ch,
			"pub": map[string]interface{}{
				"data": map[string]interface{}{
					"type": "code_update",
					"payload": map[string]interface{}{
						"uuid": uuid, "code": codeNow, "version": ver,
					},
				},
			},
		}})
	}
	return ver
}

func (f *fakeServer) roomInfoCount(uuid string) int {
	r := f.roomObj(uuid)
	if r == nil {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.roomInfo
}

// callCount is how many shared_editor_change_code calls the room has seen
// (applied, no-oped and rejected alike).
func (f *fakeServer) callCount(uuid string) int {
	r := f.roomObj(uuid)
	if r == nil {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

// setReplyDelays arms out-of-order/late RPC responses: the reply of call k is
// held for ds[min(k, len(ds)-1)] while its push goes out at commit time.
func (f *fakeServer) setReplyDelays(uuid string, ds ...time.Duration) {
	if r := f.roomObj(uuid); r != nil {
		r.mu.Lock()
		r.replyDelays = ds
		r.mu.Unlock()
	}
}

// setGate arms a reply gate: every change_code reply waits for a token from
// ch (or ch being closed); pushes stay immediate.
func (f *fakeServer) setGate(uuid string, ch chan struct{}) {
	if r := f.roomObj(uuid); r != nil {
		r.mu.Lock()
		r.gate = ch
		r.mu.Unlock()
	}
}

// setForceNoop arms deterministic rejections: the next n change_code calls
// are silently no-oped even though their patch matches the stored document.
func (f *fakeServer) setForceNoop(uuid string, n int) {
	if r := f.roomObj(uuid); r != nil {
		r.mu.Lock()
		r.forceNoop = n
		r.mu.Unlock()
	}
}

func (f *fakeServer) codeOf(uuid string) string {
	r := f.roomObj(uuid)
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.code
}

// ---- Django page + subscription token ----

func (f *fakeServer) handleRoom(w http.ResponseWriter, r *http.Request) {
	uuid := r.URL.Query().Get("room")
	f.mu.Lock()
	room, known := f.rooms[uuid]
	switch {
	case uuid == "": // exit "create room" flow: fresh room with the template
		uuid = newUUID(f.t)
		room = &fakeRoom{code: fakeTemplate(), version: 1, subs: map[*fakePeer]bool{}}
		f.rooms[uuid] = room
	case !known:
		f.mu.Unlock()
		http.Error(w, "no such room", http.StatusNotFound)
		return
	}
	f.mu.Unlock()

	user := newUUID(f.t) // every page load is an anonymous participant
	http.SetCookie(w, &http.Cookie{Name: "csrftoken", Value: newHex(16), Path: "/"})
	base := f.srv.URL
	html := fmt.Sprintf(`<!DOCTYPE html><html><head>
<meta name="centrifuge-connection-token" content="cupt-%s">
<meta name="centrifuge-connection-url" content="%s/cf">
<meta name="centrifuge-subscription-token-url" content="%s/api/subtoken">
</head><body>
<div data-room="{&quot;uuid&quot;: &quot;%s&quot;}" data-user="{&quot;uuid&quot;: &quot;%s&quot;}"></div>
</body></html>`, newHex(8), base, base, uuid, user)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	io.WriteString(w, html)
}

func (f *fakeServer) handleSubToken(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	var q struct {
		Channel string `json:"channel"`
	}
	json.Unmarshal(body, &q)
	if !strings.HasPrefix(q.Channel, "$shared_editor:room-") {
		http.Error(w, "bad channel", http.StatusBadRequest)
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"token": "subt-" + newHex(8)})
}

// ---- Centrifugo websocket ----

type fakePeer struct {
	f       *fakeServer
	conn    *websocket.Conn
	writeMu sync.Mutex

	mu   sync.Mutex
	subs map[string]*fakeRoom // channel → room
}

func (f *fakeServer) handleWS(w http.ResponseWriter, r *http.Request) {
	conn, err := f.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	p := &fakePeer{f: f, conn: conn, subs: map[string]*fakeRoom{}}
	defer func() {
		p.dropSubs()
		conn.Close()
	}()
	for {
		_, raw, err := conn.ReadMessage()
		if err != nil {
			return
		}
		p.serve(raw)
	}
}

func (p *fakePeer) send(v interface{}) {
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	p.conn.WriteMessage(websocket.TextMessage, b)
}

func (p *fakePeer) dropSubs() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for ch, room := range p.subs {
		room.mu.Lock()
		delete(room.subs, p)
		room.mu.Unlock()
		delete(p.subs, ch)
	}
}

func (p *fakePeer) serve(raw []byte) {
	var req struct {
		ID        int64           `json:"id"`
		Connect   json.RawMessage `json:"connect"`
		Subscribe *struct {
			Channel string `json:"channel"`
			Token   string `json:"token"`
		} `json:"subscribe"`
		RPC *struct {
			Method string          `json:"method"`
			Data   json.RawMessage `json:"data"`
		} `json:"rpc"`
	}
	if err := json.Unmarshal(raw, &req); err != nil {
		return
	}
	switch {
	case req.Connect != nil:
		p.send(map[string]interface{}{"id": req.ID, "connect": map[string]interface{}{}})
		return
	case req.Subscribe != nil:
		ch := req.Subscribe.Channel
		uuid := strings.TrimPrefix(ch, "$shared_editor:room-")
		room := p.f.roomObj(uuid)
		if room == nil {
			p.send(map[string]interface{}{"id": req.ID, "error": map[string]interface{}{"code": 102, "message": "channel not found"}})
			return
		}
		room.mu.Lock()
		room.subs[p] = true
		room.mu.Unlock()
		p.mu.Lock()
		p.subs[ch] = room
		p.mu.Unlock()
		p.send(map[string]interface{}{"id": req.ID, "subscribe": map[string]interface{}{}})
		return
	case req.RPC != nil:
		p.serveRPC(req.ID, req.RPC.Method, req.RPC.Data)
		return
	default:
		p.send(map[string]interface{}{"id": req.ID, "error": map[string]interface{}{"code": 102, "message": "unknown command"}})
	}
}

func (p *fakePeer) serveRPC(id int64, method string, data json.RawMessage) {
	switch method {
	case "shared_editor_room_info":
		var d struct{ Room string }
		json.Unmarshal(data, &d)
		room := p.f.roomObj(d.Room)
		if room == nil {
			p.send(map[string]interface{}{"id": id, "error": map[string]interface{}{"code": 400, "message": "no such room"}})
			return
		}
		room.mu.Lock()
		code, ver := room.code, room.version
		room.roomInfo++
		room.mu.Unlock()
		p.send(map[string]interface{}{"id": id, "rpc": map[string]interface{}{"data": map[string]interface{}{
			"uuid": d.Room, "language": nil, "code": code, "version": ver,
		}}})

	case "shared_editor_change_code":
		var d struct {
			Diff string `json:"diff"`
			Room string `json:"room"`
			User string `json:"user"`
		}
		json.Unmarshal(data, &d)
		room := p.f.roomObj(d.Room)
		if room == nil {
			p.send(map[string]interface{}{"id": id, "error": map[string]interface{}{"code": 400, "message": "no such room"}})
			return
		}
		ch := "$shared_editor:room-" + d.Room
		room.mu.Lock()
		newCode, applied, err := fakeApplyDiff(room.code, d.Diff)
		if err != nil {
			// Malformed patch: Django-level input rejection. Staleness is NOT
			// an error here — a stale patch is a SILENT no-op (see below),
			// exactly as verified against the live service.
			room.rejected++
			room.mu.Unlock()
			p.send(map[string]interface{}{"id": id, "error": map[string]interface{}{
				"code":    400,
				"message": "Неверные данные для изменения кода: " + err.Error(),
			}})
			return
		}
		if applied && room.forceNoop > 0 {
			room.forceNoop-- // test knob: pretend the (matching) patch misfired
			applied = false
		}
		callIdx := room.calls
		room.calls++
		if applied {
			room.code = newCode
			room.applied++
		} else {
			room.noop++ // document untouched, version still bumped
		}
		room.version++
		ver := room.version
		codeNow := room.code
		delay := time.Duration(0)
		if n := len(room.replyDelays); n > 0 {
			if callIdx >= n {
				callIdx = n - 1
			}
			delay = room.replyDelays[callIdx]
		}
		gate := room.gate
		subs := make([]*fakePeer, 0, len(room.subs))
		for sp := range room.subs {
			subs = append(subs, sp)
		}
		room.mu.Unlock()
		// The reply carries the FULL stored document as of this call's commit
		// (observed live shape: {"id":N,"rpc":{"data":{"uuid","code",...}}}).
		// Test knobs may hold it back (late / gated, hence possibly OUT OF
		// ORDER across calls) — concurrent server workers do exactly that.
		reply := map[string]interface{}{"id": id, "rpc": map[string]interface{}{"data": map[string]interface{}{
			"uuid": d.Room, "code": codeNow, "version": ver,
		}}}
		if delay > 0 || gate != nil {
			go func() {
				if delay > 0 {
					time.Sleep(delay)
				}
				if gate != nil {
					<-gate // closed channel releases every waiter (test cleanup)
				}
				p.send(reply)
			}()
		} else {
			p.send(reply)
		}
		// Pushes still follow the commit synchronously, in apply order.
		for _, sp := range subs {
			sp.send(map[string]interface{}{"push": map[string]interface{}{
				"channel": ch,
				"pub": map[string]interface{}{
					"data": map[string]interface{}{
						"type": "code_update",
						"payload": map[string]interface{}{
							"uuid": d.Room, "code": codeNow, "version": ver,
						},
					},
					"offset": ver,
				},
			}})
		}

	case "shared_editor_ping":
		p.send(map[string]interface{}{"id": id, "rpc": map[string]interface{}{"data": map[string]interface{}{}}})

	default:
		p.send(map[string]interface{}{"id": id, "error": map[string]interface{}{"code": 102, "message": "no such method: " + method}})
	}
}

// ---- reference patch application (mirrors what the live server does) ----
//
// The dialect proven against the live service (2026-10): the @@ numbers are
// ABSOLUTE CHARACTER (code-point, 0-based) offsets and lengths — NOT line
// numbers. Body lines are whole percent-encoded chunks (interior newlines as
// %0A inside ONE line):
//
//	" " chunk = context that must sit verbatim at the offset
//	"-" chunk = deleted text, following the context in the stored doc
//	"+" chunk = inserted text, spliced right after the context
//	header old length = |ctx|+|del| runes, new length = |ctx|+|ins| runes,
//	offset = start of the context chunk.
//
// A chunk mismatch makes the server SILENTLY no-op the patch (version still
// bumps) — applied=false here. Malformed patches (bad header/counts, unknown
// prefixes, multiple hunks) are the Django-level 400 path (applied=false + err).

var reFakeHunk = regexp.MustCompile(`^@@ -(\d+),(\d+) \+(\d+),(\d+) @@$`)

func fakeApplyDiff(code, diff string) (newCode string, applied bool, err error) {
	if !strings.HasSuffix(diff, "\n") {
		return "", false, fmt.Errorf("diff does not end with newline")
	}
	lines := strings.Split(diff, "\n")
	lines = lines[:len(lines)-1] // trailing newline artifact
	if len(lines) == 0 {
		return "", false, fmt.Errorf("empty diff")
	}
	m := reFakeHunk.FindStringSubmatch(lines[0])
	if m == nil {
		return "", false, fmt.Errorf("missing/bad hunk header %q", lines[0])
	}
	for _, ln := range lines[1:] {
		if strings.HasPrefix(ln, "@@ ") {
			return "", false, fmt.Errorf("multiple hunks not supported")
		}
	}
	a, _ := strconv.Atoi(m[1])
	b, _ := strconv.Atoi(m[2])
	d, _ := strconv.Atoi(m[4])

	var ctxB, delB, insB []byte
	for _, ln := range lines[1:] {
		if ln == "" {
			return "", false, fmt.Errorf("empty line inside hunk body")
		}
		content, derr := pctDecode(ln[1:])
		if derr != nil {
			return "", false, derr
		}
		switch ln[0] {
		case ' ':
			ctxB = append(ctxB, content...)
		case '-':
			delB = append(delB, content...)
		case '+':
			insB = append(insB, content...)
		default:
			return "", false, fmt.Errorf("unknown hunk line prefix %q", ln[0])
		}
	}
	ctx, del, ins := string(ctxB), string(delB), string(insB)
	if utf8.RuneCountInString(ctx)+utf8.RuneCountInString(del) != b {
		return "", false, fmt.Errorf("header old length %d != ctx(%d)+del(%d) runes", b, utf8.RuneCountInString(ctx), utf8.RuneCountInString(del))
	}
	if utf8.RuneCountInString(ctx)+utf8.RuneCountInString(ins) != d {
		return "", false, fmt.Errorf("header new length %d != ctx(%d)+ins(%d) runes", d, utf8.RuneCountInString(ctx), utf8.RuneCountInString(ins))
	}

	R := []rune(code)
	off := a
	if off < 0 || off+b > len(R) {
		return code, false, nil // cannot match ⇒ silent no-op
	}
	if string(R[off:off+utf8.RuneCountInString(ctx)]) != ctx {
		return code, false, nil
	}
	delStart := off + utf8.RuneCountInString(ctx)
	if string(R[delStart:off+b]) != del {
		return code, false, nil
	}
	out := make([]rune, 0, len(R)+utf8.RuneCountInString(ins))
	out = append(out, R[:delStart]...)
	out = append(out, []rune(ins)...)
	out = append(out, R[off+b:]...)
	return string(out), true, nil
}

func pctDecode(s string) (string, error) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '%' {
			b.WriteByte(s[i])
			continue
		}
		if i+3 > len(s) {
			return "", fmt.Errorf("truncated percent escape at %d", i)
		}
		v, err := strconv.ParseUint(s[i+1:i+3], 16, 8)
		if err != nil {
			return "", fmt.Errorf("bad percent escape %q", s[i:i+3])
		}
		b.WriteByte(byte(v))
		i += 2
	}
	return b.String(), nil
}
