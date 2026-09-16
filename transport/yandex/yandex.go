package yandex

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"

	"universal-bypass-tool/transport"
	"universal-bypass-tool/utils"
)

// clientConfigRe extracts the embedded client-config JSON script block from
// the document HTML. Package-level so the program is built once, not per
// document fetch.
var clientConfigRe = regexp.MustCompile(`<script[^>]*id="client-config"[^>]*>(.*?)</script>`)

// Deadline tuning for the document WebSocket.
//
// Without a write deadline, gorilla WriteMessage blocks forever once the
// server (or an intermediate LB) stops draining the socket: TCP retransmits
// into a blackhole while the write buffer fills. The single writerLoop then
// freezes ON THE OLD CONNECTION while the read loop happily reconnects a new
// one, so the WriteQueue piles up behind a writer that can never return -
// the transport looks CONNECTED and downloads keep flowing, but every uplink
// session stalls until its virtual-TCP retransmit budget runs out and the
// app gets a connection reset. That is the "SpeedTest never reaches upload"
// failure mode measured on iOS on 2026-09-16 (uplink RST ~75-100 s into a
// sustained upload, downlink unaffected).
//
// The write deadline bounds the worst case; hitting it kills the connection
// (see DocSession.kill) so the read loop observes the error and the normal
// reconnect path rebuilds a usable session. The read deadline catches the
// symmetric blackhole for the reader: our own 10 s keep-alive is echoed back
// by the document server, so a healthy link always produces inbound bytes
// well inside the window; silence past the deadline means the link is dead.
// Package-level vars so unit tests can shrink them.
var (
	ydocWriteDeadline = 10 * time.Second
	ydocReadDeadline  = 75 * time.Second
)

type YandexDocsInfo struct {
	CookieStr   string
	Token       string
	DocID       string
	CallbackURL string
	UserID      string
	Origin      string
	Host        string
	WsURL       string
	Permissions map[string]interface{}
	OpenCmd     map[string]interface{}
}

type DocSession struct {
	Info       YandexDocsInfo
	Conn       *websocket.Conn
	WriteQueue chan []byte
	UserID     string
	writeMu    sync.Mutex
}

// kill force-closes the session socket. Idempotent and safe to call from any
// goroutine: websocket.Conn.Close is goroutine-safe and unblocks both the
// stalled writer and the blocked reader, which turns any half-dead link into
// an ordinary read-loop error and therefore an ordinary reconnect.
func (s *DocSession) kill() {
	if s.Conn != nil {
		_ = s.Conn.Close()
	}
}

// safeWrite writes one frame under the session write mutex, bounded by
// ydocWriteDeadline. Any failure (deadline, broken pipe, closing race) kills
// the connection so the reconnect machinery takes over instead of leaving a
// permanently stuck writer behind.
func (s *DocSession) safeWrite(messageType int, data []byte) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if s.Conn == nil {
		return fmt.Errorf("session has no connection")
	}
	if err := s.Conn.SetWriteDeadline(time.Now().Add(ydocWriteDeadline)); err != nil {
		s.kill()
		return err
	}
	if err := s.Conn.WriteMessage(messageType, data); err != nil {
		s.kill()
		return err
	}
	return nil
}

type YandexDocsTransport struct {
	*transport.BaseTransport

	url     string
	session *DocSession

	userCounter atomic.Int32
	baseUserID  string

	// sendDrops counts uplink frames dropped because the WS writer could not
	// keep up. Logged periodically so a queue-full collapse (sustained
	// uplink >> carrier capacity) is visible in stats instead of being pure
	// silent retransmission loss inside the virtual TCP stack.
	sendDrops atomic.Uint64
}

func NewYandexDocsTransport(url string, config transport.TransportConfig) *YandexDocsTransport {
	t := &YandexDocsTransport{
		BaseTransport: transport.NewBaseTransport(config),
		url:           url,
	}
	t.baseUserID = randUserID()
	return t
}

func (t *YandexDocsTransport) Start() error {
	if err := t.BaseTransport.Start(); err != nil {
		return err
	}

	t.baseUserID = randUserID()
	go t.keepAliveLoop()
	t.connectToDoc(0)

	return nil
}

func (t *YandexDocsTransport) Send(data []byte) error {
	if !t.IsConnected() {
		return fmt.Errorf("transport not connected")
	}

	t.Mu.RLock()
	session := t.session
	t.Mu.RUnlock()

	if session == nil {
		return fmt.Errorf("no active session")
	}

	select {
	case session.WriteQueue <- data:
		t.RecordSend(len(data))
		return nil
	default:
		// Uplink offered load exceeds carrier write capacity: drop the frame
		// (the virtual TCP stack retransmits) but make the condition loud.
		if d := t.sendDrops.Add(1); d == 1 || d%100 == 0 {
			utils.Debugf("[YDOCS] uplink write queue full, dropped %d frame(s) so far", d)
		}
		return fmt.Errorf("write queue full")
	}
}

func (t *YandexDocsTransport) connectToDoc(attempt int) {
	if !t.IsRunning() {
		return
	}

	utils.Debugf("[YDOCS] connectToDoc attempt %d/%d", attempt+1, t.GetConfig().MaxReconnectAttempts)

	go func() {
		t.Mu.Lock()
		existingSession := t.session
		t.Mu.Unlock()

		var userID string
		if existingSession != nil {
			userID = existingSession.UserID
		} else {
			suffix := fmt.Sprintf("%03d", t.userCounter.Add(1)%1000)
			userID = t.baseUserID + suffix
		}

		info, err := t.fetchDocInfo(t.url, userID)
		if err != nil {
			utils.Debugf("[YDOCS] fetchDocInfo failed: %v", err)
			t.scheduleReconnect(attempt)
			return
		}

		dialer := websocket.Dialer{HandshakeTimeout: 10 * time.Second}
		headers := http.Header{}
		headers.Set("User-Agent", "Mozilla/5.0")
		headers.Set("Origin", info.Origin)
		headers.Set("Cookie", info.CookieStr)
		headers.Set("Host", info.Host)

		utils.Debugf("[YDOCS] Dialing WebSocket: %s", info.WsURL)
		conn, _, err := dialer.Dial(info.WsURL, headers)
		if err != nil {
			utils.Debugf("[YDOCS] WebSocket dial failed: %v", err)
			t.scheduleReconnect(attempt)
			return
		}
		utils.Debugf("[YDOCS] WebSocket connected")

		writeQueue := make(chan []byte, t.GetConfig().MaxQueueSize)
		if existingSession != nil {
			writeQueue = existingSession.WriteQueue
		}

		session := &DocSession{
			Info:       info,
			Conn:       conn,
			WriteQueue: writeQueue,
			UserID:     userID,
		}

		t.Mu.Lock()
		t.session = session
		t.SetConnected(true)
		t.Mu.Unlock()

		if existingSession == nil {
			go t.writerLoop()
		}

		// Auth - use safeWrite
		auth1 := fmt.Sprintf(`40{"token":"%s"}`, info.Token)
		session.safeWrite(websocket.TextMessage, []byte(auth1))

		authData := map[string]interface{}{
			"type": "auth", "docid": info.DocID, "token": "fghhfgsjdgfjs",
			"user": map[string]interface{}{"id": userID}, "editorType": 0,
			"lastOtherSaveTime": -1, "permissions": info.Permissions,
			"openCmd": info.OpenCmd, "coEditingMode": "fast", "jwtOpen": info.Token,
		}
		messagePart, _ := json.Marshal([]interface{}{"message", authData})
		session.safeWrite(websocket.TextMessage, []byte(fmt.Sprintf("42%s", string(messagePart))))

		for t.IsRunning() {
			if err := conn.SetReadDeadline(time.Now().Add(ydocReadDeadline)); err != nil {
				utils.Debugf("[YDOCS] SetReadDeadline failed: %v", err)
				break
			}
			_, message, err := conn.ReadMessage()
			if err != nil {
				utils.Debugf("[YDOCS] Read error: %v", err)
				session.kill()
				t.SetConnected(false)
				t.scheduleReconnect(attempt)
				return
			}
			t.handleMessage(session, message)
		}
	}()
}

func (t *YandexDocsTransport) writerLoop() {
	for t.IsRunning() {
		t.Mu.Lock()
		session := t.session
		t.Mu.Unlock()

		if session == nil || session.Conn == nil {
			time.Sleep(10 * time.Millisecond)
			continue
		}

		select {
		case packet := <-session.WriteQueue:
			payload := base64.StdEncoding.EncodeToString(packet)
			msg := fmt.Sprintf(`42["message",{"type":"cursor","cursor":"18;%s"}]`, payload)

			if err := session.safeWrite(websocket.TextMessage, []byte(msg)); err != nil {
				utils.Debugf("[YDOCS] Write error: %v", err)
			}
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}
}

func (t *YandexDocsTransport) keepAliveLoop() {
	ticker := time.NewTicker(t.GetConfig().KeepAliveInterval)
	defer ticker.Stop()
	keepAliveMsg := `42["message",{"type":"cursor","cursor":"18;---KA---"}]`

	for t.IsRunning() {
		<-ticker.C
		t.Mu.Lock()
		session := t.session
		t.Mu.Unlock()

		if session != nil && session.Conn != nil {
			if err := session.safeWrite(websocket.TextMessage, []byte(keepAliveMsg)); err != nil {
				utils.Debugf("[YDOCS] Keep-alive failed: %v", err)
				t.SetConnected(false)
			}
		}
	}
}

func (t *YandexDocsTransport) handleMessage(session *DocSession, data []byte) {
	text := string(data)

	if strings.Contains(text, "---KA---") {
		return
	}

	// Socket.IO ping - respond with pong (use safeWrite)
	if text == "2" {
		if session != nil && session.Conn != nil {
			session.safeWrite(websocket.TextMessage, []byte("3"))
		}
		return
	}
	if text == "3" {
		return
	}

	if strings.Contains(text, "saveChanges") || strings.Contains(text, "cursor") {
		base64Str := t.extractBase64String(text)
		if base64Str == "" {
			return
		}

		decoded, err := base64.StdEncoding.DecodeString(base64Str)
		if err != nil {
			utils.Debugf("[YDOCS] Base64 decode error: %v", err)
			return
		}

		t.RecordReceive(len(decoded))
		t.CallReceive(decoded)
	}
}

// cursorMarker is the JSON key prefix whose value carries the resume cursor.
const cursorMarker = `"cursor":"`

// extractBase64String pulls the payload out of one inbound doc frame.
//
// The cursor branch used to run regexp.MustCompile inside the function, i.e.
// it recompiled `"cursor":"[^;]+;([^"]+)""` for every inbound frame. A live
// heap profile taken on iPhone under SpeedTest showed this call at 22.5% of
// all process allocation churn (25.7 MB in ~35 s): 1.5 MB of actual
// compilation plus 24.2 MB of RE2 backtracking state (`regexp.(*bitState)`)
// grown against multi-kilobyte frames. Because the transport runs with
// GOGC=15, that churn alone drove a GC every few seconds, and every GC
// clears sync.Pool - which is what forces tun2socks to re-make() its 64 KiB
// relay buffers for each new session. So this is not just a CPU cost, it is
// the feedback loop behind the memory plateau.
//
// The scan below is allocation-free and byte-for-byte equivalent to the old
// regex (see TestExtractBase64StringMatchesOldRegex): leftmost `"cursor":"`,
// then the first `;` at least one byte after the prefix ([^;]+ needs >=1),
// then capture up to the next quote ([^"]+ needs >=1). A failed candidate
// moves on to the next occurrence of the marker, like the regex engine does.
func (t *YandexDocsTransport) extractBase64String(response string) string {
	if strings.Contains(response, "saveChanges") {
		marker := `"excelAdditionalInfo":"`
		left := strings.Index(response, marker) + len(marker)
		if left < len(marker) {
			return ""
		}
		right := strings.Index(response[left:], `"`)
		if right == -1 {
			return ""
		}
		return response[left : left+right]
	}

	for off := 0; off < len(response); {
		i := strings.Index(response[off:], cursorMarker)
		if i < 0 {
			break
		}
		start := off + i + len(cursorMarker)
		off = start

		// [^;]+; - the run before the first ';' must be non-empty.
		semis := strings.IndexByte(response[start:], ';')
		if semis <= 0 {
			continue
		}
		value := response[start+semis+1:]

		// ([^"]+) - at least one byte before the closing quote.
		end := strings.IndexByte(value, '"')
		if end <= 0 {
			continue
		}
		return value[:end]
	}
	return ""
}

func (t *YandexDocsTransport) scheduleReconnect(attempt int) {
	if !t.IsRunning() || attempt >= t.GetConfig().MaxReconnectAttempts {
		return
	}

	t.RecordReconnect()
	delay := time.Duration(float64(t.GetConfig().ReconnectDelay) *
		math.Pow(t.GetConfig().ReconnectMultiplier, float64(attempt)))
	if delay <= 0 {
		delay = time.Second
	}

	utils.Debugf("[YDOCS] Reconnecting in %v...", delay)
	time.Sleep(delay)
	t.connectToDoc(attempt + 1)
}

func (t *YandexDocsTransport) fetchDocInfo(url, userID string) (YandexDocsInfo, error) {
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return nil },
		Timeout:       30 * time.Second,
	}

	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	utils.Debugf("[YDOCS] Fetching document URL: %s", url)
	resp, err := client.Do(req)
	if err != nil {
		return YandexDocsInfo{}, err
	}
	defer resp.Body.Close()
	utils.Debugf("[YDOCS] Document response: status=%d final_url=%s", resp.StatusCode, resp.Request.URL.String())

	htmlBytes, _ := io.ReadAll(resp.Body)
	html := string(htmlBytes)
	utils.Debugf("[YDOCS] Document HTML read: bytes=%d", len(htmlBytes))

	var cookies []string
	for _, c := range resp.Cookies() {
		cookies = append(cookies, fmt.Sprintf("%s=%s", c.Name, c.Value))
	}

	// Compiled once at package level: this runs against the full document
	// HTML, so compiling per fetch showed up in the iOS alloc-space profile.
	matches := clientConfigRe.FindStringSubmatch(html)
	if len(matches) < 2 {
		return YandexDocsInfo{}, fmt.Errorf("config not found")
	}
	utils.Debugf("[YDOCS] client-config found")

	var config map[string]interface{}
	if err := json.Unmarshal([]byte(matches[1]), &config); err != nil {
		return YandexDocsInfo{}, fmt.Errorf("client-config JSON parse failed: %w", err)
	}
	officeAction, ok := config["officeActionData"].(map[string]interface{})
	if !ok || officeAction == nil {
		return YandexDocsInfo{}, fmt.Errorf("officeActionData not found in client-config")
	}

	editorConfigRaw, ok := officeAction["editor_config"].(map[string]interface{})
	if !ok || editorConfigRaw == nil {
		return YandexDocsInfo{}, fmt.Errorf("editor_config nil - will reconnect")
	}

	balancerURL, ok := stringValue(officeAction, "balancer_url")
	if !ok || balancerURL == "" {
		return YandexDocsInfo{}, t.unsupportedVolgaError(officeAction, editorConfigRaw)
	}
	host := strings.TrimPrefix(balancerURL, "https://")
	utils.Debugf("[YDOCS] legacy schema detected: host=%s", host)
	document, ok := editorConfigRaw["document"].(map[string]interface{})
	if !ok || document == nil {
		return YandexDocsInfo{}, t.unsupportedVolgaError(officeAction, editorConfigRaw)
	}
	token, ok := stringValue(editorConfigRaw, "token")
	if !ok || token == "" {
		return YandexDocsInfo{}, t.unsupportedVolgaError(officeAction, editorConfigRaw)
	}
	docID, ok := stringValue(document, "key")
	if !ok || docID == "" {
		return YandexDocsInfo{}, fmt.Errorf("document.key not found in editor_config")
	}

	perms, _ := document["permissions"].(map[string]interface{})
	if perms == nil {
		perms = make(map[string]interface{})
	}
	fileType, _ := stringValue(document, "fileType")
	docURL, _ := stringValue(document, "url")
	title, _ := stringValue(document, "title")

	return YandexDocsInfo{
		CookieStr:   strings.Join(cookies, "; "),
		Token:       token,
		DocID:       docID,
		Origin:      balancerURL,
		Host:        host,
		WsURL:       fmt.Sprintf("wss://%s/2024.1.1-375/doc/%s/c/?EIO=4&transport=websocket", host, docID),
		Permissions: perms,
		OpenCmd: map[string]interface{}{
			"c":      "open",
			"id":     docID,
			"userid": userID,
			"format": fileType,
			"url":    docURL,
			"title":  title,
			"lcid":   25,
		},
	}, nil
}

func stringValue(m map[string]interface{}, key string) (string, bool) {
	v, ok := m[key]
	if !ok || v == nil {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

func (t *YandexDocsTransport) unsupportedVolgaError(officeAction map[string]interface{}, editorConfig map[string]interface{}) error {
	if actionURL, ok := stringValue(officeAction, "action_url"); ok && actionURL != "" {
		resourceURL, _ := stringValue(officeAction, "resource_url")
		return fmt.Errorf(
			"unsupported Yandex Volga/WOPI document schema: missing legacy balancer_url/editor_config.token/document.key; action_url=%s resource_url=%s",
			actionURL,
			resourceURL,
		)
	}
	return fmt.Errorf(
		"unsupported Yandex document schema: missing legacy balancer_url/editor_config.token/document.key; editor_config_keys=%v office_action_keys=%v",
		mapKeys(editorConfig),
		mapKeys(officeAction),
	)
}

func mapKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func randUserID() string {
	return fmt.Sprintf("%010d", rand.New(rand.NewSource(time.Now().UnixNano())).Intn(1000000000))
}
