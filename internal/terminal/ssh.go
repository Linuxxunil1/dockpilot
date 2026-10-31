package terminal

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"

	"github.com/gorilla/websocket"
	gossh "golang.org/x/crypto/ssh"

	"dockpilot/internal/servers"
)

// ServeSSH upgrades the request to a WebSocket and proxies a PTY over SSH.
func ServeSSH(w http.ResponseWriter, r *http.Request, serverID string) {
	srv := servers.Get(serverID)
	if srv == nil {
		http.Error(w, "server nicht gefunden", http.StatusNotFound)
		return
	}

	conn, err := upgrade(w, r)
	if err != nil {
		log.Printf("terminal/ssh: upgrade: %v", err)
		return
	}
	defer conn.Close()

	client, err := servers.Connect(srv)
	if err != nil {
		closeConn(conn, fmt.Sprintf("SSH-Verbindung fehlgeschlagen: %v", err))
		return
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		closeConn(conn, fmt.Sprintf("SSH-Session fehlgeschlagen: %v", err))
		return
	}
	defer session.Close()

	modes := gossh.TerminalModes{
		gossh.ECHO:          1,
		gossh.TTY_OP_ISPEED: 14400,
		gossh.TTY_OP_OSPEED: 14400,
	}
	if err := session.RequestPty("xterm-256color", 24, 80, modes); err != nil {
		closeConn(conn, "PTY anfordern fehlgeschlagen")
		return
	}

	stdin, _ := session.StdinPipe()
	stdout, _ := session.StdoutPipe()
	stderr, _ := session.StderrPipe()

	if err := session.Shell(); err != nil {
		closeConn(conn, "Shell starten fehlgeschlagen")
		return
	}

	// stdout+stderr → WebSocket
	var pumps sync.WaitGroup
	pump := func(rd io.Reader) {
		defer pumps.Done()
		buf := make([]byte, 4096)
		for {
			n, err := rd.Read(buf)
			if n > 0 {
				sendData(conn, buf[:n])
			}
			if err != nil {
				return
			}
		}
	}
	pumps.Add(2)
	go pump(stdout)
	go pump(stderr)

	// Shell beendet (z. B. "exit"): restliche Ausgabe senden, dann die Verbindung schließen.
	shellDone := make(chan struct{})
	go func() {
		session.Wait()
		pumps.Wait()
		close(shellDone)
	}()

	// WebSocket → SSH stdin / resize
	browserGone := make(chan struct{})
	go func() {
		defer close(browserGone)
		for {
			m, err := readMsg(conn)
			if err != nil {
				return
			}
			switch m.Type {
			case "data":
				io.WriteString(stdin, m.Data)
			case "resize":
				if m.Cols > 0 && m.Rows > 0 {
					session.WindowChange(int(m.Rows), int(m.Cols))
				}
			}
		}
	}()

	reason := ""
	select {
	case <-shellDone:
		reason = "Shell beendet"
	case <-browserGone:
	}
	conn.WriteMessage(websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, reason))
}
