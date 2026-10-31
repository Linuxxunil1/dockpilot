package terminal

import (
	"log"
	"net/http"
	"strings"

	"github.com/gorilla/websocket"
)

// ServeAgentProxy verbindet die Browser-WebSocket mit dem WebSocket-Endpunkt path
// auf dem Agent und reicht die Nachrichten in beide Richtungen unverändert durch.
func ServeAgentProxy(w http.ResponseWriter, r *http.Request, agentURL, agentToken, path string) {
	wsURL := strings.Replace(agentURL, "https://", "wss://", 1)
	wsURL = strings.Replace(wsURL, "http://", "ws://", 1) + path

	hdr := http.Header{"Authorization": {"Bearer " + agentToken}}
	agent, resp, err := websocket.DefaultDialer.Dial(wsURL, hdr)
	if err != nil {
		log.Printf("terminal/agent: dial %s: %v", wsURL, err)
		reason := "Agent nicht erreichbar"
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			reason = "Agent unterstützt die Konsole nicht – bitte Agent aktualisieren"
		} else if resp != nil {
			reason = "Agent lehnt ab: " + resp.Status
		}
		if browser, uerr := upgrader.Upgrade(w, r, nil); uerr == nil {
			closeConn(browser, reason)
		}
		return
	}
	defer agent.Close()

	browser, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("terminal/agent: browser upgrade: %v", err)
		return
	}
	defer browser.Close()

	done := make(chan string, 2)
	pipe := func(from, to *websocket.Conn) {
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
