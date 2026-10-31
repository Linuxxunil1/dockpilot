package terminal

import (
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/websocket"

	"dockpilot/internal/servers"
)

// ServeAgentProxy verbindet die Browser-WebSocket mit dem WebSocket-Endpunkt path
// auf dem Agent und reicht die Nachrichten in beide Richtungen unverändert durch.
func ServeAgentProxy(w http.ResponseWriter, r *http.Request, agentURL, agentToken, path string) {
	wsURL := strings.Replace(agentURL, "https://", "wss://", 1)
	wsURL = strings.Replace(wsURL, "http://", "ws://", 1) + path

	hdr := http.Header{"Authorization": {"Bearer " + agentToken}}
	dialer := websocket.Dialer{HandshakeTimeout: 15 * time.Second, TLSClientConfig: servers.AgentTLSConfig()}
	agentRaw, resp, err := dialer.Dial(wsURL, hdr)
	if err != nil {
		log.Printf("terminal/agent: dial %s: %v", wsURL, err)
		reason := "Agent nicht erreichbar"
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			reason = "Agent unterstützt die Konsole nicht – bitte Agent aktualisieren"
		} else if resp != nil {
			reason = "Agent lehnt ab: " + resp.Status
		}
		if browser, uerr := upgrade(w, r); uerr == nil {
			closeConn(browser, reason)
		}
		return
	}
	agent := wrap(agentRaw)
	defer agent.Close()

	browser, err := upgrade(w, r)
	if err != nil {
		log.Printf("terminal/agent: browser upgrade: %v", err)
		return
	}
	defer browser.Close()

	done := make(chan string, 2)
	pipe := func(from, to *safeConn) {
		for {
			mt, msg, err := from.ReadMessage()
			if err != nil {
				reason := ""
				if ce, ok := err.(*websocket.CloseError); ok {
					reason = ce.Text
				}
				done <- reason
				return
			}
			if to.WriteMessage(mt, msg) != nil {
				done <- ""
				return
			}
		}
	}
	go pipe(agent, browser)
	go pipe(browser, agent)
	reason := <-done

	// Grund (z. B. "Shell beendet") an beide Seiten weitergeben.
	cf := websocket.FormatCloseMessage(websocket.CloseNormalClosure, shortReason(reason))
	browser.WriteMessage(websocket.CloseMessage, cf)
	agent.WriteMessage(websocket.CloseMessage, cf)
}
