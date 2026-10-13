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

// stats returns applied/rejected change_code counters for a room.
func (f *fakeServer) stats(uuid string) (applied, rejected int) {
	r := f.roomObj(uuid)
	if r == nil {
		return 0, 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.applied, r.rejected
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
		newCode, err := fakeApplyDiff(room.code, d.Diff)
		if err != nil {
			room.rejected++
			room.mu.Unlock()
			// The exact shape the live Django API returns for a stale diff.
			p.send(map[string]interface{}{"id": id, "error": map[string]interface{}{
				"code":    400,
				"message": "Неверные данные для изменения кода: " + err.Error(),
			}})
			return
		}
		room.code = newCode
		room.version++
		room.applied++
		ver := room.version
		subs := make([]*fakePeer, 0, len(room.subs))
		for sp := range room.subs {
			subs = append(subs, sp)
		}
		room.mu.Unlock()
		// Reply carries the new version (not the full doc, like the capture).
		p.send(map[string]interface{}{"id": id, "rpc": map[string]interface{}{"data": map[string]interface{}{"version": ver}}})
		for _, sp := range subs {
			sp.send(map[string]interface{}{"push": map[string]interface{}{
				"channel": ch,
				"pub": map[string]interface{}{
					"data": map[string]interface{}{
						"type": "code_update",
						"payload": map[string]interface{}{
							"uuid": d.Room, "code": newCode, "version": ver,
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

// ---- reference diff application (mirrors what Django does server-side) ----

var reFakeHunk = regexp.MustCompile(`^@@ -(\d+),(\d+) \+(\d+),(\d+) @@$`)

func fakeApplyDiff(code, diff string) (string, error) {
	if !strings.HasSuffix(diff, "\n") {
		return "", fmt.Errorf("diff does not end with newline")
	}
	lines := strings.Split(diff, "\n")
	lines = lines[:len(lines)-1] // trailing newline artifact
	if len(lines) == 0 {
		return "", fmt.Errorf("empty diff")
	}
	m := reFakeHunk.FindStringSubmatch(lines[0])
	if m == nil {
		return "", fmt.Errorf("missing/bad hunk header %q", lines[0])
	}
	for _, ln := range lines[1:] {
		if strings.HasPrefix(ln, "@@ ") {
			return "", fmt.Errorf("multiple hunks not supported")
		}
	}
	a, _ := strconv.Atoi(m[1])
	b, _ := strconv.Atoi(m[2])
	d, _ := strconv.Atoi(m[4])

	var oldSeq, newSeq []string
	for _, ln := range lines[1:] {
		if ln == "" {
			return "", fmt.Errorf("empty line inside hunk body")
		}
		content, err := pctDecode(ln[1:])
		if err != nil {
			return "", err
		}
		switch ln[0] {
		case ' ':
			oldSeq = append(oldSeq, content)
			newSeq = append(newSeq, content)
		case '-':
			oldSeq = append(oldSeq, content)
		case '+':
			newSeq = append(newSeq, content)
		default:
			return "", fmt.Errorf("unknown hunk line prefix %q", ln[0])
		}
	}
	if len(oldSeq) != b {
		return "", fmt.Errorf("hunk header says %d old lines, body has %d", b, len(oldSeq))
	}
	if len(newSeq) != d {
		return "", fmt.Errorf("hunk header says %d new lines, body has %d", d, len(newSeq))
	}
	doc := strings.Split(code, "\n")
	start := a - 1
	if start < 0 || start+b > len(doc) {
		return "", fmt.Errorf("hunk @@ -%d,%d @@ out of document (%d lines)", a, b, len(doc))
	}
	for i := 0; i < b; i++ {
		if doc[start+i] != oldSeq[i] {
			return "", fmt.Errorf("context mismatch at line %d: document has %q, diff expects %q", start+i+1, doc[start+i], oldSeq[i])
		}
	}
	parts := make([]string, 0, len(doc))
	parts = append(parts, doc[:start]...)
	parts = append(parts, newSeq...)
	parts = append(parts, doc[start+b:]...)
	return strings.Join(parts, "\n"), nil
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
