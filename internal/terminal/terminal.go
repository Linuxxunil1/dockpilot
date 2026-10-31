// Package terminal provides WebSocket-based SSH terminal sessions.
package terminal

import (
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/gorilla/websocket"
)

// Die Konsole hängt am Session-Cookie, deshalb nur Verbindungen von der eigenen Seite zulassen.
var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		origin := r.Header.Get("Origin")
		if origin == "" {
			return true
		}
		u, err := url.Parse(origin)
		return err == nil && u.Host == r.Host
	},
}

// readLimit begrenzt eine einzelne eingehende Nachricht (Tastatur, Einfügen, Resize).
const readLimit = 1 << 20

// safeConn serialisiert Schreibzugriffe: gorilla/websocket erlaubt nur einen Schreiber
// gleichzeitig und bricht sonst mit einer Panic ab, die den ganzen Prozess beendet.
type safeConn struct {
	*websocket.Conn
	mu sync.Mutex
}

func (c *safeConn) WriteMessage(mt int, data []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.Conn.WriteMessage(mt, data)
}

func wrap(c *websocket.Conn) *safeConn {
	c.SetReadLimit(readLimit)
	return &safeConn{Conn: c}
}

// upgrade wandelt die Anfrage in eine WebSocket-Verbindung zum Browser.
func upgrade(w http.ResponseWriter, r *http.Request) (*safeConn, error) {
	c, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return nil, err
	}
	return wrap(c), nil
}

// msg is used only for INCOMING messages from the browser.
// Outgoing PTY data is sent as raw binary — no JSON wrapping.
type msg struct {
	Type string `json:"type"` // "resize" | "ping"
	Data string `json:"data,omitempty"`
	Cols uint16 `json:"cols,omitempty"`
	Rows uint16 `json:"rows,omitempty"`
}

// readMsg reads one message from the browser.
// Resize/ping events come as JSON; keyboard input is raw bytes.
func readMsg(conn *safeConn) (*msg, error) {
	_, raw, err := conn.ReadMessage()
	if err != nil {
		return nil, err
	}
	var m msg
	if err := json.Unmarshal(raw, &m); err != nil || m.Type == "" {
		// Raw keyboard input — treat as data to write to PTY.
		return &msg{Type: "data", Data: string(raw)}, nil
	}
	return &m, nil
}

// sendData sends raw PTY output to the browser as a binary WebSocket frame.
// The browser's xterm.js onmessage handler calls _term.write(new Uint8Array(e.data)).
func sendData(conn *safeConn, data []byte) error {
	return conn.WriteMessage(websocket.BinaryMessage, data)
}

// closeConn sends a clean WebSocket close frame before closing.
func closeConn(conn *safeConn, reason string) {
	conn.WriteMessage(websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, shortReason(reason)))
	// Noch eingehende Nachrichten abholen, bis der Browser das Schließen bestätigt.
	// Sonst setzt TCP die Verbindung zurück und der Grund geht verloren.
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			break
		}
	}
	conn.Close()
	log.Printf("terminal: closed (%s)", reason)
}

// shortReason kürzt den Grund auf die 123 Bytes, die ein WebSocket-Close-Frame erlaubt.
// Längere Gründe würden sonst stillschweigend verworfen.
func shortReason(reason string) string {
	reason = strings.ReplaceAll(reason, "Error response from daemon: ", "")
	if len(reason) <= 123 {
		return reason
	}
	cut := 120
	for cut > 0 && !utf8.RuneStart(reason[cut]) {
		cut--
	}
	return reason[:cut] + "…"
}
