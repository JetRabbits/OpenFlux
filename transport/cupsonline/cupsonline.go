// Package cupsonline implements a covert tunnel over interview.cups.online
// rooms (Centrifugo 4.1.5 websocket + Django RPC validation).
//
// Data channel: shared_editor_change_code. The room's shared code document is
// the carrier: each side (exit = "X", client = "Y") owns a fenced block of
// lines at the END of the document ("//OCX-<roomidx>-BEGIN" ... "-END") whose
// body is the length-prefixed packet batch, base64'd and chunked into short
// lines. A send computes the document with our block replaced, expresses the
// edit as the server's own patch dialect (see makeDiff — CHARACTER (rune)
// offsets, not line numbers: " " keep-chunk verifies context at the rune
// offset, "-" deletes, "+" inserts, each one percent-encoded chunk with \n
// inside as %0A), and ships it through the "shared_editor_change_code" RPC.
// The change_code reply carries the FULL new document: on success we adopt it
// as baseline; if it differs from what we expected (the server SILENTLY
// no-ops — version bump, document untouched — when the patch does not match
// at its offsets) we refetch shared_editor_room_info and retry against the
// fresh document (bounded). Receivers strip their own block, decode the
// peer's block, and dedupe repeat code_update pushes by version + payload
// hash (our own edits echo back to us).
//
// Why not cursors: until 2026-10 data rode in the "column" field of
// shared_editor_change_cursors as base64. In October 2026 the server started
// validating cursor fields as integers ("Введите правильное число." on any
// string column), which kills the cursor channel outright — every send is
// rejected with a 400 and nothing relays. The code-editing RPC above is the
// live replacement observed in a real browser protocol capture: it still
// accepts arbitrary percent-encoded text and still broadcasts to everyone.
package cupsonline

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/gorilla/websocket"

	"github.com/JetRabbits/OpenFlux/transport"
	"github.com/JetRabbits/OpenFlux/utils"
)

const (
	baseRoomURL = "https://interview.cups.online/live-coding/"

	cupsUA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36"
)

// roomBaseURL is the live room endpoint the transport actually talks to. It is
// a package-level seam over baseRoomURL so in-package tests can point the
// constructors at a fake cups.online deployment (httptest). Production code
// never reassigns it.
var roomBaseURL = baseRoomURL

type CupsonlineConfig struct {
	WSHandshakeTimeout  time.Duration
	WSReadTimeout       time.Duration
	KeepAliveInterval   time.Duration
	ReconnectMinDelay   time.Duration
	ReconnectMaxDelay   time.Duration
	ReconnectMultiplier float64
	HTTPTimeout         time.Duration

	// Батчинг внутри одного WS. 32 KB — потолок Centrifugo (64 KB push).
	BatchMaxPackets int
	BatchMaxBytes   int
	BatchTimeout    time.Duration

	// MaxCodeBytesPerBatch limits the framed payload carried in ONE
	// shared_editor_change_code call (base64 of it lands in the room code
	// document). Keeps the total document around template + 2 blocks < ~8KB.
	// We own only our own block, so an oversized doc always self-heals: the
	// next send replaces our whole block with a fresh bounded payload.
	MaxCodeBytesPerBatch int

	SendQueueSize int

	ReadBufferSize  int
	WriteBufferSize int

	MaxPayloadBytes int

	NumRooms        int
	RoomCreatePause time.Duration

	StatsInterval time.Duration
}

func DefaultCupsonlineConfig() CupsonlineConfig {
	return CupsonlineConfig{
		WSHandshakeTimeout:  15 * time.Second,
		WSReadTimeout:       300 * time.Second,
		KeepAliveInterval:   20 * time.Second,
		ReconnectMinDelay:   100 * time.Millisecond,
		ReconnectMaxDelay:   10 * time.Second,
		ReconnectMultiplier: 1.3,
		HTTPTimeout:         30 * time.Second,

		// BatchMaxBytes остаётся жёстким потолком пакета (probe-era legacy);
		// фактический гейт отправки — Min(BatchMaxBytes, MaxCodeBytesPerBatch),
		// т.к. payload теперь живёт в тексте комнаты (base64 ×4/3).
		BatchMaxPackets: 64,
		BatchMaxBytes:   32 * 1024,
		BatchTimeout:    2 * time.Millisecond,

		MaxCodeBytesPerBatch: 3072,

		SendQueueSize: 65536,

		ReadBufferSize:  32 << 20,
		WriteBufferSize: 32 << 20,

		MaxPayloadBytes: 16_000_000,

		NumRooms:        4,
		RoomCreatePause: 500 * time.Millisecond,

		StatsInterval: 5 * time.Second,
	}
}

var (
	reMetaConnToken = regexp.MustCompile(`<meta[^>]+name="centrifuge-connection-token"[^>]+content="([^"]+)"`)
	reMetaConnURL   = regexp.MustCompile(`<meta[^>]+name="centrifuge-connection-url"[^>]+content="([^"]+)"`)
	reMetaSubURL    = regexp.MustCompile(`<meta[^>]+name="centrifuge-subscription-token-url"[^>]+content="([^"]+)"`)
	reDataRoomUUID  = regexp.MustCompile(`data-room="\{&quot;uuid&quot;:\s*&quot;([0-9a-f-]{36})&quot;`)
	reDataUserUUID  = regexp.MustCompile(`data-user="\{&quot;uuid&quot;:\s*&quot;([0-9a-f-]{36})&quot;`)
)

type cupsAuth struct {
	roomUUID   string
	userUUID   string
	connToken  string
	connURL    string
	subURL     string
	subToken   string
	channel    string
	httpClient *http.Client
	csrfToken  string
}

func authorizeWithJar(roomURL string, jar http.CookieJar) (*cupsAuth, error) {
	if jar == nil {
		jar, _ = cookiejar.New(nil)
	}
	client := &http.Client{
		Jar:     jar,
		Timeout: 30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	req, _ := http.NewRequest("GET", roomURL, nil)
	req.Header.Set("User-Agent", cupsUA)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "ru-RU,ru;q=0.9")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET room: %w", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("GET room status %d", resp.StatusCode)
	}

	html := string(body)
	a := &cupsAuth{
		roomUUID:   firstMatch(reDataRoomUUID, html),
		userUUID:   firstMatch(reDataUserUUID, html),
		connToken:  firstMatch(reMetaConnToken, html),
		connURL:    firstMatch(reMetaConnURL, html),
		subURL:     firstMatch(reMetaSubURL, html),
		httpClient: client,
	}
	for _, c := range jar.Cookies(mustParseURL(roomURL)) {
		if c.Name == "csrftoken" {
			a.csrfToken = c.Value
			break
		}
	}
	if a.roomUUID == "" || a.userUUID == "" {
		return nil, fmt.Errorf("room/user uuid missing")
	}
	if a.connToken == "" || a.connURL == "" || a.subURL == "" {
		return nil, fmt.Errorf("centrifuge meta missing")
	}
	if a.csrfToken == "" {
		return nil, fmt.Errorf("csrftoken missing")
	}
	a.channel = fmt.Sprintf("$shared_editor:room-%s", a.roomUUID)

	subBody, _ := json.Marshal(map[string]string{"channel": a.channel})
	req2, _ := http.NewRequest("POST", a.subURL, bytes.NewReader(subBody))
	req2.Header.Set("User-Agent", cupsUA)
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("X-CSRFToken", a.csrfToken)
	req2.Header.Set("Origin", originOf(roomURL))
	req2.Header.Set("Referer", roomURL)

	resp2, err := client.Do(req2)
	if err != nil {
		return nil, fmt.Errorf("POST sub token: %w", err)
	}
	body2, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()
	if resp2.StatusCode != 200 {
		return nil, fmt.Errorf("sub token status %d", resp2.StatusCode)
	}
	var subResp struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(body2, &subResp); err != nil {
		return nil, err
	}
	a.subToken = subResp.Token
	if a.subToken == "" {
		return nil, fmt.Errorf("empty sub token")
	}
	utils.Debugf("[CUPS] auth OK: room=%s user=%s", a.roomUUID, a.userUUID)
	return a, nil
}

func authorize(roomURL string) (*cupsAuth, error) {
	return authorizeWithJar(roomURL, nil)
}

func createRooms(baseURL string, n int, pause time.Duration) ([]*cupsAuth, error) {
	if baseURL == "" {
		baseURL = roomBaseURL
	}
	out := make([]*cupsAuth, 0, n)
	delay := pause
	if delay <= 0 {
		delay = 150 * time.Millisecond
	}
	for i := 0; i < n; i++ {
		var a *cupsAuth
		var lastErr error
		for attempt := 0; attempt < 6; attempt++ {
			a, lastErr = authorizeWithJar(baseURL, nil)
			if lastErr == nil {
				// The auto-create session (base URL, no ?room=) turns out to
				// be a "creator" context that is NOT delivered editor pushes
				// (verified live 2026-10: a creator connection subscribes and
				// RPCs fine but never sees code_update; a ?room=<uuid> joiner
				// session does). Re-authorize through our own join link and
				// run the tunnel channels from that joiner identity; the
				// creator session is left to drop (the room persists with
				// joiners present — users_update confirms).
				if a != nil && a.roomUUID != "" {
					joiner, jerr := authorizeWithJar(baseURL+"?room="+a.roomUUID, nil)
					if jerr == nil && joiner != nil && joiner.roomUUID == a.roomUUID {
						a = joiner
					} else if jerr != nil {
						utils.Debugf("[CUPS] joiner re-auth (%s): %v", a.roomUUID, jerr)
					}
				}
				break
			}
			msg := lastErr.Error()
			var wait time.Duration
			if strings.Contains(msg, "403") || strings.Contains(msg, "429") {
				wait = delay * time.Duration(1<<uint(attempt))
				if wait > 30*time.Second {
					wait = 30 * time.Second
				}
			} else {
				wait = delay * time.Duration(attempt+1)
			}
			utils.Debugf("[CUPS] room %d attempt %d failed: %v (wait %v)", i+1, attempt+1, lastErr, wait)
			<-time.After(wait)
		}
		if a == nil {
			utils.Debugf("[CUPS] room %d skipped: %v", i+1, lastErr)
			continue
		}
		out = append(out, a)
		utils.Debugf("[CUPS] created room %d/%d: %s", i+1, n, a.roomUUID)
		if i < n-1 {
			<-time.After(delay)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("could not create any room")
	}
	return out, nil
}

func packRooms(auths []*cupsAuth) string {
	ids := make([]string, 0, len(auths))
	for _, a := range auths {
		ids = append(ids, a.roomUUID)
	}
	raw, _ := json.Marshal(ids)
	return base64.RawURLEncoding.EncodeToString(raw)
}

func unpackRooms(s string) ([]string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}
	var ids []string
	if err := json.Unmarshal(raw, &ids); err != nil {
		return nil, fmt.Errorf("json decode: %w", err)
	}
	return ids, nil
}

// ---- per-channel stats ----

type channelStats struct {
	idx         int
	roomUUID    string
	packetsSent atomic.Uint64
	packetsRecv atomic.Uint64
	bytesSent   atomic.Uint64
	bytesRecv   atomic.Uint64
	batchesSent atomic.Uint64
	batchesRecv atomic.Uint64
	reconnects  atomic.Uint64
	flows       atomic.Uint64
}

// ---- WS ----

type cupsWS struct {
	auth   *cupsAuth
	config CupsonlineConfig
	conn   *websocket.Conn

	writeMu sync.Mutex
	rpcID   atomic.Int64
	onData  func([]byte)

	// Code channel identity: exit owns "X" blocks, client owns "Y" blocks.
	// roomIdx is only cosmetic (marker text); peer-block lookup matches the
	// side tag with any index so both peers stay compatible even if their
	// room lists drift apart.
	side     string // "X" (exit) or "Y" (client)
	peerSide string
	roomIdx  int

	// Code baseline, guarded by codeMu: the last known full room-code text
	// plus its server version (-1 = never learned).
	codeMu      sync.Mutex
	serverCode  string
	codeVersion int64

	// RPC reply correlation: callRPC registers a reply channel under the
	// frame id; the read loop routes {"id":N,...} frames here.
	pendingMu sync.Mutex
	pending   map[int64]chan rpcResp

	// Peer-data dedupe (own edits echo back as code_update pushes). These
	// fields are touched only from the read-loop goroutine (which includes
	// the inline baseline fetch inside connectAndServe).
	havePeerState bool
	lastPeerHash  uint64
	observedVer   int64

	ctx       chan struct{}
	closed    atomic.Bool
	connected atomic.Bool

	sendQueue chan []byte

	stats *channelStats
}

type rpcResp struct {
	data json.RawMessage
	err  error
}

var errWSReset = fmt.Errorf("websocket reconnected")

func (w *cupsWS) nextID() int64 { return w.rpcID.Add(1) }

// callRPC sends one Centrifugo RPC frame and waits for the reply correlated by
// frame id. Replies arrive through the read loop (handleMessage → pending).
func (w *cupsWS) callRPC(method string, data map[string]interface{}, timeout time.Duration) (json.RawMessage, error) {
	id := w.nextID()
	ch := make(chan rpcResp, 1)
	w.pendingMu.Lock()
	if w.pending == nil {
		w.pending = make(map[int64]chan rpcResp)
	}
	w.pending[id] = ch
	w.pendingMu.Unlock()
	defer func() {
		w.pendingMu.Lock()
		delete(w.pending, id)
		w.pendingMu.Unlock()
	}()

	msg := map[string]interface{}{
		"rpc": map[string]interface{}{"method": method, "data": data},
		"id":  id,
	}
	if err := w.writeJSON(msg); err != nil {
		return nil, err
	}
	select {
	case r := <-ch:
		return r.data, r.err
	case <-w.ctx:
		return nil, fmt.Errorf("closed")
	case <-time.After(timeout):
		return nil, fmt.Errorf("rpc %s timeout (id %d)", method, id)
	}
}

// clearPending fails every in-flight RPC call (connection reset); called when
// the active websocket goes away or a fresh one is installed, so senders never
// wait out the timeout on a reply that can no longer arrive.
func (w *cupsWS) clearPending(reason error) {
	w.pendingMu.Lock()
	for id, ch := range w.pending {
		select {
		case ch <- rpcResp{err: reason}:
		default:
		}
		delete(w.pending, id)
	}
	w.pendingMu.Unlock()
}

func (w *cupsWS) writeRaw(data []byte) error {
	w.writeMu.Lock()
	defer w.writeMu.Unlock()
	if w.conn == nil {
		return fmt.Errorf("ws not connected")
	}
	return w.conn.WriteMessage(websocket.TextMessage, data)
}

func (w *cupsWS) writeJSON(v interface{}) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return w.writeRaw(data)
}

// currentConn returns the currently active WebSocket, if any.
func (w *cupsWS) currentConn() *websocket.Conn {
	w.writeMu.Lock()
	defer w.writeMu.Unlock()
	return w.conn
}

func (w *cupsWS) run() {
	delay := w.config.ReconnectMinDelay
	for {
		select {
		case <-w.ctx:
			return
		default:
		}
		if err := w.connectAndServe(); err != nil {
			utils.Debugf("[CUPS] ws error (%s): %v", w.auth.roomUUID, err)
		}
		w.connected.Store(false)
		if w.closed.Load() {
			return
		}
		w.stats.reconnects.Add(1)
		select {
		case <-time.After(delay):
		case <-w.ctx:
			return
		}
		delay = time.Duration(float64(delay) * w.config.ReconnectMultiplier)
		if delay > w.config.ReconnectMaxDelay {
			delay = w.config.ReconnectMaxDelay
		}
	}
}

func (w *cupsWS) connectAndServe() error {
	wsURL := strings.Replace(w.auth.connURL, "https://", "wss://", 1)
	wsURL = strings.Replace(wsURL, "http://", "ws://", 1)
	wsURL = strings.TrimRight(wsURL, "/") + "/websocket"

	header := http.Header{}
	header.Set("Origin", originOf(w.auth.connURL))
	header.Set("User-Agent", cupsUA)
	for _, c := range w.auth.httpClient.Jar.Cookies(mustParseURL(w.auth.connURL)) {
		header.Add("Cookie", c.Name+"="+c.Value)
	}

	dialer := websocket.Dialer{
		HandshakeTimeout: w.config.WSHandshakeTimeout,
		ReadBufferSize:   w.config.ReadBufferSize,
		WriteBufferSize:  w.config.WriteBufferSize,
	}
	conn, _, err := dialer.Dial(wsURL, header)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	w.clearPending(errWSReset)
	w.writeMu.Lock()
	w.conn = conn
	w.writeMu.Unlock()
	defer func() {
		w.clearPending(errWSReset)
		w.writeMu.Lock()
		w.conn = nil
		w.writeMu.Unlock()
		conn.Close()
	}()

	conn.SetReadLimit(int64(w.config.ReadBufferSize))

	if err := w.writeJSON(map[string]interface{}{
		"id": 1, "connect": map[string]interface{}{"token": w.auth.connToken, "name": "js"},
	}); err != nil {
		return err
	}
	conn.SetReadDeadline(time.Now().Add(w.config.WSReadTimeout))
	if _, _, err := conn.ReadMessage(); err != nil {
		return err
	}
	if err := w.writeJSON(map[string]interface{}{
		"id": 2, "subscribe": map[string]interface{}{"channel": w.auth.channel, "token": w.auth.subToken},
	}); err != nil {
		return err
	}
	conn.SetReadDeadline(time.Now().Add(w.config.WSReadTimeout))
	if _, _, err := conn.ReadMessage(); err != nil {
		return err
	}

	// The data channel is diff-based: every change_code must apply against the
	// exact current room document, so fetch the baseline (code + version) the
	// way the real browser client does on "subscribed" before serving sends.
	if err := w.fetchBaselineInline(conn); err != nil {
		return err
	}
	w.connected.Store(true)
	utils.Debugf("[CUPS] WS ready: %s", w.auth.roomUUID)

	kaStop := make(chan struct{})
	go w.keepAliveLoop(kaStop)
	defer close(kaStop)

	for {
		select {
		case <-w.ctx:
			return nil
		default:
		}
		conn.SetReadDeadline(time.Now().Add(w.config.WSReadTimeout))
		_, raw, err := conn.ReadMessage()
		if err != nil {
			return err
		}
		w.handleMessage(raw)
	}
}

func (w *cupsWS) keepAliveLoop(stop chan struct{}) {
	t := time.NewTicker(w.config.KeepAliveInterval)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-w.ctx:
			return
		case <-t.C:
			_ = w.writeJSON(map[string]interface{}{
				"rpc": map[string]interface{}{
					"method": "shared_editor_ping",
					"data":   map[string]interface{}{"room": w.auth.roomUUID, "user": w.auth.userUUID},
				},
				"id": w.nextID(),
			})
		}
	}
}

func (w *cupsWS) sendLoop() {
	batch := make([][]byte, 0, w.config.BatchMaxPackets)
	totalBytes := 0
	timer := time.NewTimer(w.config.BatchTimeout)
	if !timer.Stop() {
		<-timer.C
	}
	defer timer.Stop()

	// Effective per-batch byte gate: the code document can only take so much.
	maxBytes := w.config.BatchMaxBytes
	if w.config.MaxCodeBytesPerBatch > 0 && (maxBytes <= 0 || w.config.MaxCodeBytesPerBatch < maxBytes) {
		maxBytes = w.config.MaxCodeBytesPerBatch
	}

	flush := func() {
		if len(batch) == 0 {
			return
		}
		for !w.connected.Load() {
			select {
			case <-w.ctx:
				return
			case <-time.After(20 * time.Millisecond):
			}
		}
		if err := w.sendBatch(batch); err != nil {
			utils.Debugf("[CUPS] batch send (%s): %v", w.auth.roomUUID, err)
		}
		batch = batch[:0]
		totalBytes = 0
	}

	for {
		select {
		case <-w.ctx:
			flush()
			return
		case pkt, ok := <-w.sendQueue:
			if !ok {
				flush()
				return
			}
			batch = append(batch, pkt)
			totalBytes += len(pkt)
			if len(batch) >= w.config.BatchMaxPackets || totalBytes >= maxBytes {
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				flush()
			} else if len(batch) == 1 {
				timer.Reset(w.config.BatchTimeout)
			}
		case <-timer.C:
			flush()
		}
	}
}

// sendBatch smuggles the batch into the room's shared code document: our block
// (at the document tail) is replaced with the base64 of the length-prefixed
// batch framing, and the resulting character-offset patch (makeDiff) is sent
// via the shared_editor_change_code RPC. The server applies the patch only if
// its chunks match verbatim at the rune offsets — a stale baseline does NOT
// error: it silently no-ops and bumps the version — so the accepted reply's
// authoritative "code" (the full new document, observed live) is compared
// against our expectation; on mismatch, or a hard rpc error, we refetch
// room_info and recompute against the fresh document (bounded retries, then
// drop + error like before). Packets are never fragmented across calls — one
// batch either lands whole or is retried/dropped, so the peer never sees a
// torn framing stream.
func (w *cupsWS) sendBatch(batch [][]byte) error {
	payload, totalRaw := framePackets(batch)
	col := base64.RawStdEncoding.EncodeToString(payload)

	var lastErr error
	for attempt := 1; attempt <= maxChangeCodeAttempts; attempt++ {
		select {
		case <-w.ctx:
			return fmt.Errorf("closed")
		default:
		}

		w.codeMu.Lock()
		base := w.serverCode
		w.codeMu.Unlock()
		newCode, diff, changed := buildBlockEdit(base, w.side, w.roomIdx, col)
		if !changed {
			// The authoritative baseline already carries exactly this payload
			// in our block — normally because a concurrent-write retry found
			// our own patch had ALREADY landed (a fuzzy apply). The batch's
			// bytes are on the server and its push went out, so account for
			// the send; a fresh RPC would only bump the version.
			utils.Debugf("[CUPS] change_code (%s): payload already in block, RPC skipped", w.auth.roomUUID)
			w.countSent(len(batch), totalRaw, base)
			return nil
		}

		data := map[string]interface{}{
			"diff": diff,
			"room": w.auth.roomUUID,
			"user": w.auth.userUUID,
		}
		resp, err := w.callRPC("shared_editor_change_code", data, changeRPCTimeout)
		if err == nil {
			utils.Debugf("[CUPS] change_code ok (%s): diff=%dB code=%dB batch=%dpkts", w.auth.roomUUID[:8], len(diff), len(newCode), len(batch))
			code, ver, haveCode, haveVer := parseCodeResp(resp)
			if haveCode {
				// The reply's code is the authoritative document.
				w.adoptServerCode(code, ver, haveVer)
				if code == newCode {
					w.countSent(len(batch), totalRaw, newCode)
					return nil
				}
				// Silent no-op / fuzzy apply: our patch did not land.
				lastErr = fmt.Errorf("server document (%d bytes) != expected result (%d bytes)", len(code), len(newCode))
				utils.Debugf("[CUPS] change_code (%s) attempt %d/%d not applied: %v", w.auth.roomUUID, attempt, maxChangeCodeAttempts, lastErr)
			} else {
				// No code in the reply: optimistic (guarded) promotion.
				w.applyChangeSuccess(base, newCode, resp)
				w.countSent(len(batch), totalRaw, newCode)
				return nil
			}
		} else {
			lastErr = err
			utils.Debugf("[CUPS] change_code (%s) attempt %d/%d rejected: %v", w.auth.roomUUID, attempt, maxChangeCodeAttempts, err)
		}
		if rerr := w.refreshBaseline(); rerr != nil {
			utils.Debugf("[CUPS] baseline refresh (%s): %v", w.auth.roomUUID, rerr)
		}
	}
	return fmt.Errorf("change_code failed after %d attempts: %w", maxChangeCodeAttempts, lastErr)
}

func (w *cupsWS) countSent(packets, rawBytes int, newCode string) {
	w.stats.packetsSent.Add(uint64(packets))
	w.stats.bytesSent.Add(uint64(rawBytes))
	w.stats.batchesSent.Add(1)
	if len(newCode) > warnCodeDocBytes {
		// We own only our block, and every send rewrites it in full, so an
		// oversized document self-heals on the next batch; the log just names
		// the culprit size.
		utils.Debugf("[CUPS] room %s code document is %d bytes after our write", w.auth.roomUUID, len(newCode))
	}
}

// parseCodeResp extracts code/version from a change_code rpc payload.
func parseCodeResp(resp json.RawMessage) (code string, ver int64, haveCode, haveVer bool) {
	if len(resp) == 0 {
		return
	}
	var d struct {
		Code    *string  `json:"code"`
		Version *float64 `json:"version"`
	}
	if err := json.Unmarshal(resp, &d); err != nil {
		return
	}
	if d.Code != nil {
		code, haveCode = *d.Code, true
	}
	if d.Version != nil {
		ver, haveVer = int64(*d.Version), true
	}
	return
}

// adoptServerCode stores an authoritative document copy (change_code reply).
// It never rolls back below a version already reached via a fresher push.
func (w *cupsWS) adoptServerCode(code string, ver int64, haveVer bool) {
	w.codeMu.Lock()
	if !haveVer || ver >= w.codeVersion {
		w.serverCode = code
		if haveVer && ver > w.codeVersion {
			w.codeVersion = ver
		}
	}
	w.codeMu.Unlock()
}

// applyChangeSuccess promotes the write into the baseline. If the read loop
// already adopted a newer full document from a push (serverCode moved past our
// snapshot), that copy is authoritative and we keep it.
func (w *cupsWS) applyChangeSuccess(base, newCode string, resp json.RawMessage) {
	var d struct {
		Code    *string  `json:"code"`
		Version *float64 `json:"version"`
	}
	if len(resp) > 0 {
		_ = json.Unmarshal(resp, &d)
	}
	w.codeMu.Lock()
	if w.serverCode == base {
		if d.Code != nil {
			w.serverCode = *d.Code
		} else {
			w.serverCode = newCode
		}
		if d.Version != nil && int64(*d.Version) > w.codeVersion {
			w.codeVersion = int64(*d.Version)
		}
	}
	w.codeMu.Unlock()
}

// refreshBaseline refetches the room document over the pending-RPC machinery
// (safe from the send goroutine; it does NOT touch the read-loop-owned dedupe
// state, so a peer payload we missed while stale is still delivered when its
// push (or any later one) arrives).
func (w *cupsWS) refreshBaseline() error {
	data, err := w.callRPC("shared_editor_room_info", map[string]interface{}{"room": w.auth.roomUUID}, changeRPCTimeout)
	if err != nil {
		return err
	}
	var info struct {
		Code    *string  `json:"code"`
		Version *float64 `json:"version"`
	}
	if err := json.Unmarshal(data, &info); err != nil {
		return fmt.Errorf("room_info decode: %w", err)
	}
	if info.Code == nil {
		return fmt.Errorf("room_info: no code in reply")
	}
	w.codeMu.Lock()
	w.serverCode = *info.Code
	if info.Version != nil {
		w.codeVersion = int64(*info.Version)
	}
	w.codeMu.Unlock()
	utils.Debugf("[CUPS] baseline refreshed (%s): %d bytes", w.auth.roomUUID, len(*info.Code))
	return nil
}

// wsFrame is the Centrifugo envelope: RPC replies carry "id" (correlated with
// our call) plus "rpc"/"error"; server pushes carry "push".
type wsFrame struct {
	ID  *int64 `json:"id"`
	RPC *struct {
		Data json.RawMessage `json:"data"`
	} `json:"rpc"`
	Error *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
	Push json.RawMessage `json:"push"`
}

// fetchBaselineInline asks shared_editor_room_info for the current document
// right after subscribe, reading straight off the socket (the read loop is not
// running yet). Frames that are not our reply — e.g. a peer's code_update that
// lands first — are served through the normal path. Runs on the read-loop
// goroutine, so seeding the dedupe state from the fresh baseline is safe.
func (w *cupsWS) fetchBaselineInline(conn *websocket.Conn) error {
	id := w.nextID()
	msg := map[string]interface{}{
		"rpc": map[string]interface{}{
			"method": "shared_editor_room_info",
			"data":   map[string]interface{}{"room": w.auth.roomUUID},
		},
		"id": id,
	}
	if err := w.writeJSON(msg); err != nil {
		return err
	}
	for {
		select {
		case <-w.ctx:
			return fmt.Errorf("closed")
		default:
		}
		conn.SetReadDeadline(time.Now().Add(w.config.WSReadTimeout))
		_, raw, err := conn.ReadMessage()
		if err != nil {
			return err
		}
		var fr wsFrame
		if err := json.Unmarshal(raw, &fr); err != nil {
			continue
		}
		if fr.ID != nil && *fr.ID == id {
			if fr.Error != nil {
				return fmt.Errorf("room_info: code=%d %s", fr.Error.Code, fr.Error.Message)
			}
			if fr.RPC == nil {
				return fmt.Errorf("room_info: empty reply")
			}
			return w.applyRoomInfo(fr.RPC.Data)
		}
		w.handleDecoded(&fr)
	}
}

// applyRoomInfo stores the baseline fetched on connect and seeds the peer-data
// dedupe state from it. Read-loop goroutine only.
func (w *cupsWS) applyRoomInfo(data json.RawMessage) error {
	var info struct {
		Code    *string  `json:"code"`
		Version *float64 `json:"version"`
	}
	if err := json.Unmarshal(data, &info); err != nil {
		return fmt.Errorf("room_info decode: %w", err)
	}
	if info.Code == nil {
		return fmt.Errorf("room_info: no code in reply")
	}
	ver := int64(-1)
	if info.Version != nil {
		ver = int64(*info.Version)
	}
	w.codeMu.Lock()
	w.serverCode = *info.Code
	w.codeVersion = ver
	w.codeMu.Unlock()

	// Anything the peer had already written was delivered in an earlier
	// session (or is stale); mark it as seen so the next push only counts as
	// traffic when the peer block actually changes.
	peer := decodeBlockPayload(extractBlockSide(strings.Split(*info.Code, "\n"), w.peerSide))
	w.lastPeerHash = hashBytes(peer)
	w.havePeerState = true
	if ver > w.observedVer {
		w.observedVer = ver
	}
	utils.Debugf("[CUPS] baseline (%s): %d bytes, version %d", w.auth.roomUUID, len(*info.Code), ver)
	return nil
}

func (w *cupsWS) handleMessage(raw []byte) {
	// Centrifugo low-level ping: bare "{}" frame, reply verbatim.
	if len(raw) == 2 && raw[0] == '{' && raw[1] == '}' {
		_ = w.writeRaw([]byte("{}"))
		return
	}
	var fr wsFrame
	if err := json.Unmarshal(raw, &fr); err != nil {
		return
	}
	w.handleDecoded(&fr)
}

func (w *cupsWS) handleDecoded(fr *wsFrame) {
	if fr.ID != nil {
		id := *fr.ID
		w.pendingMu.Lock()
		ch, ok := w.pending[id]
		if ok {
			delete(w.pending, id)
		}
		w.pendingMu.Unlock()
		if ok {
			switch {
			case fr.Error != nil:
				ch <- rpcResp{err: fmt.Errorf("server rpc error %d: %s", fr.Error.Code, fr.Error.Message)}
			case fr.RPC != nil:
				ch <- rpcResp{data: fr.RPC.Data}
			default:
				ch <- rpcResp{err: fmt.Errorf("empty rpc reply for id %d", id)}
			}
		}
	}
	if fr.Push == nil {
		return
	}
	var push struct {
		Channel string `json:"channel"`
		Pub     struct {
			Data struct {
				Type    string          `json:"type"`
				Payload json.RawMessage `json:"payload"`
			} `json:"data"`
			Offset uint64 `json:"offset"`
		} `json:"pub"`
	}
	if err := json.Unmarshal(fr.Push, &push); err != nil {
		return
	}
	switch push.Pub.Data.Type {
	case "code_update":
		w.handleCodeUpdate(push.Pub.Data.Payload)
	}
}

// handleCodeUpdate processes the {"type":"code_update","payload":{uuid,code,
// version}} push. The payload carries the FULL room document: it keeps our
// diff baseline fresh, and our side's packets are read from the peer's block.
func (w *cupsWS) handleCodeUpdate(payloadRaw json.RawMessage) {
	var p struct {
		UUID    string   `json:"uuid"`
		Code    *string  `json:"code"`
		Version *float64 `json:"version"`
	}
	if err := json.Unmarshal(payloadRaw, &p); err != nil || p.Code == nil {
		return
	}
	code := *p.Code
	haveVer := p.Version != nil
	ver := int64(-1)
	if haveVer {
		ver = int64(*p.Version)
	}

	// Adopt the full document as baseline whenever it is newer than what we
	// hold (a push we have not seen must never roll the version back).
	w.codeMu.Lock()
	if (haveVer && ver > w.codeVersion) || (!haveVer && w.codeVersion < 0) {
		w.serverCode = code
		if haveVer {
			w.codeVersion = ver
		}
	}
	w.codeMu.Unlock()

	if haveVer && w.havePeerState && ver <= w.observedVer {
		return // stale pub (resubscribe replay / duplicate delivery)
	}
	peerBytes := decodeBlockPayload(extractBlockSide(strings.Split(code, "\n"), w.peerSide))
	h := hashBytes(peerBytes)
	if w.havePeerState && h == w.lastPeerHash {
		// Peer block unchanged: this is our own edit (or a filler push)
		// echoing back. Track the version so late replays stay filtered.
		if haveVer && ver > w.observedVer {
			w.observedVer = ver
		}
		return
	}
	count, total := splitPackets(peerBytes, w.onData)
	if haveVer && ver > w.observedVer {
		w.observedVer = ver
	}
	w.lastPeerHash = h
	w.havePeerState = true
	if count > 0 {
		w.stats.packetsRecv.Add(uint64(count))
		w.stats.bytesRecv.Add(uint64(total))
		w.stats.batchesRecv.Add(1)
	}
}

func hashBytes(b []byte) uint64 {
	h := fnv.New64a()
	h.Write(b)
	return h.Sum64()
}

// ---- code channel: blocks, diff, framing ----

const (
	// diffContextChars is the size of the keep-chunk (context) the server
	// dialect verifies at the patch offset, in runes.
	diffContextChars = 12
	// b64LineChunk keeps base64 payload lines short so the diff stays
	// line-granular and chunk bodies remain small.
	b64LineChunk = 200
	// maxChangeCodeAttempts bounds the stale-baseline retry loop.
	maxChangeCodeAttempts = 3
	// changeRPCTimeout bounds one RPC round-trip on the send path.
	changeRPCTimeout = 10 * time.Second
	// warnCodeDocBytes only triggers a debug log; our block always replaces
	// itself wholesale, so oversized documents self-heal.
	warnCodeDocBytes = 64 * 1024
)

// reBlockMarker matches our fences, e.g. "//OCX-2-BEGIN". The side letter
// ("X" exit / "Y" client) is what distinguishes ours from the peer's.
var reBlockMarker = regexp.MustCompile(`^//OC([XY])-(\d+)-(BEGIN|END)$`)

func blockMarker(side string, idx int, kind string) string {
	return fmt.Sprintf("//OC%s-%d-%s", side, idx, kind)
}

func parseBlockMarker(line string) (side string, idx int, kind string, ok bool) {
	m := reBlockMarker.FindStringSubmatch(line)
	if m == nil {
		return "", 0, "", false
	}
	i, _ := strconv.Atoi(m[2])
	return m[1], i, m[3], true
}

// removeBlockSide drops every block fenced for the given side (marker lines
// inclusive). Everything else — template text, the peer's block — passes
// through byte-identical, which makes our diff hunks never touch foreign
// lines. An unterminated own block at EOF is ours too and gets dropped whole.
func removeBlockSide(lines []string, side string) []string {
	out := make([]string, 0, len(lines))
	skip := false
	for _, ln := range lines {
		if s, _, kind, ok := parseBlockMarker(ln); ok && s == side {
			if kind == "BEGIN" {
				skip = true
				continue
			}
			if kind == "END" {
				skip = false
				continue
			}
		}
		if skip {
			continue
		}
		out = append(out, ln)
	}
	return out
}

// extractBlockSide returns the concatenated body of the first complete block
// fenced for the given side, or "" when absent/unterminated.
func extractBlockSide(lines []string, side string) string {
	var sb strings.Builder
	inBlock := false
	for _, ln := range lines {
		if s, _, kind, ok := parseBlockMarker(ln); ok && s == side {
			if kind == "BEGIN" {
				if inBlock {
					sb.Reset() // unterminated earlier block: newest wins
				}
				inBlock = true
				continue
			}
			if kind == "END" {
				if inBlock {
					return sb.String()
				}
				continue
			}
		}
		if inBlock {
			sb.WriteString(strings.Join(strings.Fields(ln), ""))
		}
	}
	return ""
}

// chunkLines chops the base64 payload into lines of at most b64LineChunk
// characters.
func chunkLines(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	for i := 0; i < len(s); i += b64LineChunk {
		e := i + b64LineChunk
		if e > len(s) {
			e = len(s)
		}
		out = append(out, s[i:e])
	}
	return out
}

// blockText is the fenced block as it lives inside the document, WITHOUT a
// trailing newline: "//OCX-<i>-BEGIN\n<chunk>\n...<chunk>\n//OCX-<i>-END".
// The DATA REGION is the runes strictly between the BEGIN line's "\n" and the
// END marker text — each chunk line (including the last) is "\n"-terminated
// inside the region, so the "\n" that closes the region is its final rune and
// the END line stays intact outside it.
func blockText(side string, idx int, chunks []string) string {
	var sb strings.Builder
	sb.WriteString(blockMarker(side, idx, "BEGIN"))
	sb.WriteString("\n")
	for _, c := range chunks {
		sb.WriteString(c)
		sb.WriteString("\n")
	}
	sb.WriteString(blockMarker(side, idx, "END"))
	return sb.String()
}

// cupsBlock locates one fenced block inside the document; byte indexes are
// offsets into the raw string, rune indexes are the Unicode code-point counts
// the SERVER patch dialect uses (Cyrillic template!).
type cupsBlock struct {
	side string
	idx  int

	beginByte      int // at '/' of "//OC..." on the BEGIN line
	dataStartByte  int // just after the BEGIN line's "\n"
	dataEndByte    int // at '/' of the END marker text
	endTextEndByte int // just after the END marker text (before its "\n")

	beginRune      int
	dataStartRune  int
	endTextEndRune int
}

// reBlockMarkerML is reBlockMarker in multi-line mode: our fences always sit
// alone on their line.
var reBlockMarkerML = regexp.MustCompile(`(?m)^//OC([XY])-(\d+)-(BEGIN|END)$`)

// findBlocks locates every fenced block of one side, in order. A BEGIN whose
// marker is not followed by "\n", or that has no matching END, is ignored.
func findBlocks(doc string, side string) []cupsBlock {
	var out []cupsBlock
	for _, bm := range reBlockMarkerML.FindAllStringSubmatchIndex(doc, -1) {
		if doc[bm[2]:bm[3]] != side || doc[bm[6]:bm[7]] != "BEGIN" {
			continue
		}
		if bm[1] >= len(doc) || doc[bm[1]] != '\n' {
			continue
		}
		idx, _ := strconv.Atoi(doc[bm[4]:bm[5]])
		dataStart := bm[1] + 1
		for _, em := range reBlockMarkerML.FindAllStringSubmatchIndex(doc, -1) {
			if em[0] < dataStart || doc[em[2]:em[3]] != side || doc[em[6]:em[7]] != "END" {
				continue
			}
			if eidx, _ := strconv.Atoi(doc[em[4]:em[5]]); eidx != idx {
				continue
			}
			out = append(out, cupsBlock{
				side:           side,
				idx:            idx,
				beginByte:      bm[0],
				dataStartByte:  dataStart,
				dataEndByte:    em[0],
				endTextEndByte: em[1],
				beginRune:      utf8.RuneCountInString(doc[:bm[0]]),
				dataStartRune:  utf8.RuneCountInString(doc[:dataStart]),
				endTextEndRune: utf8.RuneCountInString(doc[:em[1]]),
			})
			break
		}
	}
	return out
}

// runeTailStart returns the BYTE index where the last n runes of s begin.
func runeTailStart(s string, n int) int {
	i := len(s)
	for r := 0; r < n && i > 0; r++ {
		_, size := utf8.DecodeLastRuneInString(s[:i])
		i -= size
	}
	return i
}

// buildBlockEdit computes (newDoc, diff, changed) for writing payloadB64 into
// our fenced block, using the server's character-offset patch dialect. Only a
// single contiguous region can be rewritten per hunk, which is exactly our
// edit shape:
//
//   - no block yet          → pure append: ctx = last diffContextChars runes
//     of the doc, no "-" line, ins = "\n"+block+"\n".
//   - exactly one block     → replace the DATA REGION in place; ctx = the 12
//     runes ending at the region start (the tail of our own BEGIN line,
//     unique per side).
//   - several contiguous    → collapse: one hunk deletes the whole run of our
//     blocks and inserts a single fresh one.
//   - several, not adjacent → rewrite the last one only (stale copies are
//     pathological — a fuzzy server apply — and the authoritative response
//     check converges them across retries).
//
// changed=false means the region already holds exactly this payload: sending
// would be a no-op patch, so the caller can skip the RPC entirely.
func buildBlockEdit(doc string, side string, idx int, payloadB64 string) (string, string, bool) {
	chunks := chunkLines(payloadB64)
	data := ""
	for _, c := range chunks {
		data += c + "\n"
	}
	text := blockText(side, idx, chunks)
	blocks := findBlocks(doc, side)

	if len(blocks) == 0 {
		a := utf8.RuneCountInString(doc)
		ctx := doc[runeTailStart(doc, diffContextChars):]
		ins := text + "\n"
		if doc != "" && !strings.HasSuffix(doc, "\n") {
			ins = "\n" + ins
		}
		return doc + ins, makeDiff(a-utf8.RuneCountInString(ctx), ctx, "", ins), true
	}

	if len(blocks) == 1 {
		b := blocks[0]
		del := doc[b.dataStartByte:b.dataEndByte]
		if del == data {
			return doc, "", false
		}
		ctxBytes := runeTailStart(doc[:b.dataStartByte], diffContextChars)
		ctx := doc[ctxBytes:b.dataStartByte]
		newDoc := doc[:b.dataStartByte] + data + doc[b.dataEndByte:]
		return newDoc, makeDiff(b.dataStartRune-utf8.RuneCountInString(ctx), ctx, del, data), true
	}

	// Contiguous run of our blocks? (the only "\n" between block k and k+1 is
	// block k's END-line terminator)
	k := 0
	for k+1 < len(blocks) && blocks[k].endTextEndByte+1 == blocks[k+1].beginByte {
		k++
	}
	if k+1 < len(blocks) {
		utils.Debugf("[CUPS] %d blocks for side %s, only %d adjacent — rewriting the last one", len(blocks), side, k+1)
		b := blocks[len(blocks)-1]
		ctxBytes := runeTailStart(doc[:b.dataStartByte], diffContextChars)
		ctx := doc[ctxBytes:b.dataStartByte]
		newDoc := doc[:b.dataStartByte] + data + doc[b.dataEndByte:]
		return newDoc, makeDiff(b.dataStartRune-utf8.RuneCountInString(ctx), ctx, doc[b.dataStartByte:b.dataEndByte], data), true
	}

	first, last := blocks[0], blocks[k]
	del := doc[first.beginByte:last.endTextEndByte]
	ctxBytes := runeTailStart(doc[:first.beginByte], diffContextChars)
	ctx := doc[ctxBytes:first.beginByte]
	newDoc := doc[:first.beginByte] + text + doc[last.endTextEndByte:]
	return newDoc, makeDiff(first.beginRune-utf8.RuneCountInString(ctx), ctx, del, text), true
}

// decodeBlockPayload decodes the concatenated base64 body written by our own
// encoder (unpadded first, padded as fallback).
func decodeBlockPayload(b64 string) []byte {
	if b64 == "" {
		return nil
	}
	raw, err := base64.RawStdEncoding.DecodeString(b64)
	if err != nil {
		raw2, err2 := base64.StdEncoding.DecodeString(b64)
		if err2 != nil {
			return nil
		}
		raw = raw2
	}
	return raw
}

// framePackets / splitPackets: the wire framing inside a block — one
// 2-byte big-endian length per packet (identical to the old cursor channel).
func framePackets(batch [][]byte) ([]byte, int) {
	var buf bytes.Buffer
	var hdr [2]byte
	total := 0
	for _, p := range batch {
		binary.BigEndian.PutUint16(hdr[:], uint16(len(p)))
		buf.Write(hdr[:])
		buf.Write(p)
		total += len(p)
	}
	return buf.Bytes(), total
}

func splitPackets(raw []byte, onData func([]byte)) (int, int) {
	count, total := 0, 0
	for len(raw) >= 2 {
		ln := int(binary.BigEndian.Uint16(raw[:2]))
		raw = raw[2:]
		if ln == 0 || len(raw) < ln {
			break
		}
		pkt := raw[:ln]
		raw = raw[ln:]
		if onData != nil {
			onData(pkt)
		}
		count++
		total += ln
	}
	return count, total
}

// jsEncode percent-encodes one diff line with JS encodeURIComponent semantics:
// alphanumerics and -_.!~*'() stay literal, every other byte becomes %XX with
// upper-hex (UTF-8 bytes for non-ASCII, exactly as the browser sends them).
func jsEncode(s string) string {
	const hex = "0123456789ABCDEF"
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '-', c == '_', c == '.', c == '!', c == '~', c == '*',
			c == '\'', c == '(', c == ')':
			b.WriteByte(c)
		default:
			b.WriteByte('%')
			b.WriteByte(hex[c>>4])
			b.WriteByte(hex[c&0x0f])
		}
	}
	return b.String()
}

// makeDiff emits the patch in the format cups.online's shared_editor_change_
// code actually accepts (verified against live frames, 2026-10): the "@@"
// numbers are ABSOLUTE CHARACTER (Unicode code point, 0-based) offsets into
// the stored document and character LENGTHS — not line numbers, not bytes.
// Body lines are whole percent-encoded chunks that may carry %0A inside:
//
//	" " chunk — keep/context: the runes at the offset must equal this chunk
//	"-" chunk — deleted text, sitting right after the context in the old doc
//	"-" line is omitted when nothing is deleted
//	"+" chunk — inserted text, spliced in right after the context
//
// Header accounting (both live probes confirm): old length = |ctx|+|del|,
// new length = |ctx|+|ins|, context counted on BOTH sides, offset = start of
// the context chunk. The server silently NO-OPS (but bumps the version) when
// the context/delete chunks do not sit verbatim at those offsets, so the
// caller must verify the code returned by the RPC against the expected
// result. jsEncode is applied per whole chunk, so interior newlines become
// %0A inside a single body line.
func makeDiff(offset int, ctx, del, ins string) string {
	oLen := utf8.RuneCountInString(ctx) + utf8.RuneCountInString(del)
	nLen := utf8.RuneCountInString(ctx) + utf8.RuneCountInString(ins)

	var b strings.Builder
	fmt.Fprintf(&b, "@@ -%d,%d +%d,%d @@\n", offset, oLen, offset, nLen)
	b.WriteString(" " + jsEncode(ctx) + "\n")
	if del != "" {
		b.WriteString("-" + jsEncode(del) + "\n")
	}
	if ins != "" {
		b.WriteString("+" + jsEncode(ins) + "\n")
	}
	return b.String()
}

func (w *cupsWS) Send(data []byte) error {
	if len(data) > w.config.MaxPayloadBytes {
		return fmt.Errorf("too large: %d", len(data))
	}
	select {
	case w.sendQueue <- data:
		return nil
	case <-w.ctx:
		return fmt.Errorf("closed")
	}
}

// ---- flow key ----

type flowKey struct {
	srcIP, dstIP     uint32
	srcPort, dstPort uint16
	proto            uint8
}

type flowSender struct {
	seq   atomic.Uint64
	chIdx int
}

// ---- Transport ----

type CupsonlineTransport struct {
	*transport.BaseTransport

	baseURL   string
	urls      []string
	config    CupsonlineConfig
	isClient  bool
	clientErr error

	auths []*cupsAuth
	wss   []*cupsWS

	flowMu sync.RWMutex
	flows  map[flowKey]*flowSender

	cookieJar *cookiejar.Jar
	jarMu     sync.RWMutex

	stopCh     chan struct{}
	statsStart time.Time
}

func NewCupsonlineTransport(rawURL string, cfg transport.TransportConfig, isClient bool) *CupsonlineTransport {
	jar, _ := cookiejar.New(nil)
	t := &CupsonlineTransport{
		BaseTransport: transport.NewBaseTransport(cfg),
		config:        DefaultCupsonlineConfig(),
		isClient:      isClient,
		flows:         make(map[flowKey]*flowSender),
		cookieJar:     jar,
		stopCh:        make(chan struct{}),
		statsStart:    time.Now(),
	}

	if !isClient {
		t.baseURL = roomBaseURL
		return t
	}

	var ids []string
	if rawURL != "" {
		if u, err := url.Parse(rawURL); err == nil {
			q := u.Query()
			if packed := q.Get("rooms"); packed != "" {
				if got, err := unpackRooms(packed); err == nil {
					ids = got
				}
			} else if single := q.Get("room"); single != "" {
				ids = []string{single}
			}
		}
	}
	if len(ids) == 0 && rawURL != "" {
		if got, err := unpackRooms(rawURL); err == nil && len(got) > 0 {
			ids = got
		}
	}
	if len(ids) == 0 {
		t.clientErr = fmt.Errorf("client mode: --url must contain base64 room list")
		return t
	}
	t.urls = make([]string, 0, len(ids))
	for _, id := range ids {
		t.urls = append(t.urls, roomBaseURL+"?room="+id)
	}
	utils.Debugf("[CUPS] client mode: %d rooms from base64", len(t.urls))
	return t
}

func (t *CupsonlineTransport) Start() error {
	if t.clientErr != nil {
		return t.clientErr
	}
	if err := t.BaseTransport.Start(); err != nil {
		return err
	}

	var auths []*cupsAuth
	var err error

	if t.isClient {
		for i, u := range t.urls {
			a, e := authorizeWithJar(u, t.jar())
			if e != nil {
				utils.Debugf("[CUPS] join %d failed: %v", i, e)
				continue
			}
			auths = append(auths, a)
		}
		if len(auths) == 0 {
			return fmt.Errorf("no rooms joined")
		}
	} else {
		auths, err = createRooms(t.baseURL, t.config.NumRooms, t.config.RoomCreatePause)
		if err != nil {
			return fmt.Errorf("create rooms: %w", err)
		}
		packed := packRooms(auths)
		fmt.Printf("\n=== COPY THIS TO CLIENT ===\n")
		fmt.Printf("%s\n", packed)
		fmt.Printf("===========================\n\n")
	}

	t.auths = auths

	side := "X"
	peerSide := "Y"
	if t.isClient {
		side = "Y"
		peerSide = "X"
	}
	for i, a := range auths {
		cs := &channelStats{idx: i, roomUUID: a.roomUUID}
		ws := &cupsWS{
			auth:        a,
			config:      t.config,
			ctx:         make(chan struct{}),
			sendQueue:   make(chan []byte, t.config.SendQueueSize),
			stats:       cs,
			side:        side,
			peerSide:    peerSide,
			roomIdx:     i,
			codeVersion: -1,
			pending:     make(map[int64]chan rpcResp),
		}
		ws.onData = t.handleIncoming
		t.wss = append(t.wss, ws)
		go ws.run()
		go ws.sendLoop()
	}

	utils.Debugf("[CUPS] transport started: %d channels", len(t.wss))
	t.SetConnected(true)

	go t.statsLoop()
	return nil
}

func (t *CupsonlineTransport) Stop() error {
	select {
	case <-t.stopCh:
	default:
		close(t.stopCh)
	}
	for _, ws := range t.wss {
		ws.closed.Store(true)
		close(ws.ctx)
	}
	t.SetConnected(false)
	return t.BaseTransport.Stop()
}

// Send — flow-hash: один TCP-flow всегда в один WS-канал.
// Это гарантирует порядок внутри потока, Centrifugo сохраняет порядок push'ей.
func (t *CupsonlineTransport) Send(data []byte) error {
	if len(t.wss) == 0 {
		return fmt.Errorf("no ws")
	}
	key := extractFlowKey(data)

	t.flowMu.RLock()
	fs, ok := t.flows[key]
	t.flowMu.RUnlock()

	if !ok {
		t.flowMu.Lock()
		fs, ok = t.flows[key]
		if !ok {
			idx := int(flowHash(key) % uint64(len(t.wss)))
			fs = &flowSender{chIdx: idx}
			t.flows[key] = fs
			t.wss[idx].stats.flows.Add(1)
			utils.Debugf("[CUPS] new flow %s:%d -> %s:%d proto=%d -> ws[%d] %s",
				ipStr(key.srcIP), key.srcPort, ipStr(key.dstIP), key.dstPort, key.proto,
				idx, t.wss[idx].auth.roomUUID[:8])
		}
		t.flowMu.Unlock()
	}

	fs.seq.Add(1)
	return t.wss[fs.chIdx].Send(data)
}

func (t *CupsonlineTransport) handleIncoming(pkt []byte) {
	t.CallReceive(pkt)
}

func (t *CupsonlineTransport) Receive(callback func([]byte)) {
	t.BaseTransport.Receive(callback)
}

func (t *CupsonlineTransport) IsConnected() bool {
	return t.BaseTransport.IsConnected()
}

func (t *CupsonlineTransport) Stats() transport.TransportStats {
	var sent, recv, bytesSent, bytesRecv, reconnects uint64
	for _, ws := range t.wss {
		sent += ws.stats.packetsSent.Load()
		recv += ws.stats.packetsRecv.Load()
		bytesSent += ws.stats.bytesSent.Load()
		bytesRecv += ws.stats.bytesRecv.Load()
		reconnects += ws.stats.reconnects.Load()
	}
	base := t.BaseTransport.Stats()
	return transport.TransportStats{
		BytesSent:     bytesSent,
		BytesReceived: bytesRecv,
		PacketsSent:   sent,
		PacketsRecv:   recv,
		Reconnects:    reconnects,
		Connected:     t.IsConnected(),
		Uptime:        base.Uptime,
	}
}

// statsLoop — печатает per-channel статистику каждые StatsInterval секунд.
func (t *CupsonlineTransport) statsLoop() {
	tick := time.NewTicker(t.config.StatsInterval)
	defer tick.Stop()

	lastSent := make([]uint64, len(t.wss))
	lastRecv := make([]uint64, len(t.wss))
	lastBytesSent := make([]uint64, len(t.wss))
	lastBytesRecv := make([]uint64, len(t.wss))
	var lastTotalSent, lastTotalRecv, lastTotalBytesSent, lastTotalBytesRecv uint64

	for {
		select {
		case <-t.stopCh:
			return
		case <-tick.C:
			var totalSent, totalRecv, totalBytesSent, totalBytesRecv uint64
			for i, ws := range t.wss {
				s := ws.stats.packetsSent.Load()
				r := ws.stats.packetsRecv.Load()
				bs := ws.stats.bytesSent.Load()
				br := ws.stats.bytesRecv.Load()

				dS := s - lastSent[i]
				dR := r - lastRecv[i]
				dBS := bs - lastBytesSent[i]
				dBR := br - lastBytesRecv[i]

				lastSent[i] = s
				lastRecv[i] = r
				lastBytesSent[i] = bs
				lastBytesRecv[i] = br

				totalSent += s
				totalRecv += r
				totalBytesSent += bs
				totalBytesRecv += br

				utils.Debugf("[CH-%02d %s] tx=%d pkt/s (%.1f KB/s)  rx=%d pkt/s (%.1f KB/s)  flows=%d  reconn=%d  conn=%v",
					i, ws.auth.roomUUID[:8],
					dS/uint64(t.config.StatsInterval.Seconds()),
					float64(dBS)/t.config.StatsInterval.Seconds()/1024,
					dR/uint64(t.config.StatsInterval.Seconds()),
					float64(dBR)/t.config.StatsInterval.Seconds()/1024,
					ws.stats.flows.Load(),
					ws.stats.reconnects.Load(),
					ws.connected.Load(),
				)
			}
			dtS := totalSent - lastTotalSent
			dtR := totalRecv - lastTotalRecv
			dtBS := totalBytesSent - lastTotalBytesSent
			dtBR := totalBytesRecv - lastTotalBytesRecv
			lastTotalSent = totalSent
			lastTotalRecv = totalRecv
			lastTotalBytesSent = totalBytesSent
			lastTotalBytesRecv = totalBytesRecv

			utils.Debugf("[CUPS-TOTAL] tx=%d pkt/s (%.1f KB/s)  rx=%d pkt/s (%.1f KB/s)  flows=%d  uptime=%v",
				dtS/uint64(t.config.StatsInterval.Seconds()),
				float64(dtBS)/t.config.StatsInterval.Seconds()/1024,
				dtR/uint64(t.config.StatsInterval.Seconds()),
				float64(dtBR)/t.config.StatsInterval.Seconds()/1024,
				len(t.flows),
				time.Since(t.statsStart).Round(time.Second),
			)
		}
	}
}

func (t *CupsonlineTransport) RoomUUIDs() []string {
	out := make([]string, 0, len(t.auths))
	for _, a := range t.auths {
		out = append(out, a.roomUUID)
	}
	return out
}

// ---- helpers ----

func extractFlowKey(pkt []byte) flowKey {
	if len(pkt) < 20 {
		return flowKey{}
	}
	if pkt[0]>>4 != 4 {
		return flowKey{}
	}
	proto := pkt[9]
	srcIP := binary.BigEndian.Uint32(pkt[12:16])
	dstIP := binary.BigEndian.Uint32(pkt[16:20])
	ihl := int(pkt[0]&0x0f) * 4
	if len(pkt) < ihl+4 {
		return flowKey{srcIP: srcIP, dstIP: dstIP, proto: proto}
	}
	if proto == 6 || proto == 17 {
		sp := binary.BigEndian.Uint16(pkt[ihl : ihl+2])
		dp := binary.BigEndian.Uint16(pkt[ihl+2 : ihl+4])
		return flowKey{srcIP: srcIP, dstIP: dstIP, srcPort: sp, dstPort: dp, proto: proto}
	}
	return flowKey{srcIP: srcIP, dstIP: dstIP, proto: proto}
}

// flowHash — детерминированный хеш от flow. Один поток всегда на один WS.
func flowHash(k flowKey) uint64 {
	h := fnv.New64a()
	var b [14]byte
	binary.BigEndian.PutUint32(b[0:4], k.srcIP)
	binary.BigEndian.PutUint32(b[4:8], k.dstIP)
	binary.BigEndian.PutUint16(b[8:10], k.srcPort)
	binary.BigEndian.PutUint16(b[10:12], k.dstPort)
	b[12] = k.proto
	b[13] = 0
	h.Write(b[:])
	return h.Sum64()
}

func ipStr(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", byte(ip>>24), byte(ip>>16), byte(ip>>8), byte(ip))
}

func firstMatch(re *regexp.Regexp, s string) string {
	m := re.FindStringSubmatch(s)
	if len(m) < 2 {
		return ""
	}
	return m[1]
}

func originOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

func mustParseURL(rawURL string) *url.URL {
	u, err := url.Parse(rawURL)
	if err != nil {
		panic(err)
	}
	return u
}

// jar returns the transport's shared cookie jar (never nil).
func (t *CupsonlineTransport) jar() *cookiejar.Jar {
	t.jarMu.RLock()
	jar := t.cookieJar
	t.jarMu.RUnlock()
	if jar == nil {
		jar, _ = cookiejar.New(nil)
		t.jarMu.Lock()
		t.cookieJar = jar
		t.jarMu.Unlock()
	}
	return jar
}

// ---- CookieExchanger ----

// FetchCookies returns a snapshot of the transport's current cookie jar as
// name -> value.
func (t *CupsonlineTransport) FetchCookies() (map[string]string, error) {
	u, err := url.Parse(roomBaseURL)
	if err != nil {
		return nil, err
	}
	out := make(map[string]string)
	for _, c := range t.jar().Cookies(u) {
		out[c.Name] = c.Value
	}
	return out, nil
}

// ApplyCookies replaces the transport's cookie jar with the provided values
// and forces active sessions to reconnect.
func (t *CupsonlineTransport) ApplyCookies(values map[string]string) error {
	if len(values) == 0 {
		return nil
	}
	u, _ := url.Parse(roomBaseURL)
	jar, _ := cookiejar.New(nil)
	cookies := make([]*http.Cookie, 0, len(values))
	for k, v := range values {
		cookies = append(cookies, &http.Cookie{Name: k, Value: v, Path: "/"})
	}
	jar.SetCookies(u, cookies)

	t.jarMu.Lock()
	t.cookieJar = jar
	t.jarMu.Unlock()

	utils.Debugf("[CUPS] applied %d cookies, forcing reconnects", len(cookies))

	// Close all WS sessions; they will reconnect with fresh cookies.
	for _, ws := range t.wss {
		if conn := ws.currentConn(); conn != nil {
			_ = conn.Close()
		}
	}
	return nil
}
