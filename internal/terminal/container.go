package terminal

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"github.com/docker/docker/api/types/container"
	"github.com/gorilla/websocket"

	"dockpilot/internal/docker"
)

// Startet bash, falls vorhanden, sonst sh – viele schlanke Images haben kein bash.
var shellCmd = []string{"/bin/sh", "-c", "if command -v bash >/dev/null 2>&1; then exec bash; else exec sh; fi"}

// ServeContainer öffnet per WebSocket eine interaktive Shell (docker exec) im Container.
func ServeContainer(w http.ResponseWriter, r *http.Request, containerID string) {
	conn, err := upgrade(w, r)
	if err != nil {
		log.Printf("terminal/container: upgrade: %v", err)
		return
	}
	defer conn.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if docker.IsSelf(ctx, containerID) {
		closeConn(conn, docker.ErrSelf.Error())
		return
	}

	exec, err := docker.CLI.ContainerExecCreate(ctx, containerID, container.ExecOptions{
		Tty:          true,
		AttachStdin:  true,
		AttachStdout: true,
		AttachStderr: true,
		Env:          []string{"TERM=xterm-256color"},
		Cmd:          shellCmd,
	})
	if err != nil {
		closeConn(conn, fmt.Sprintf("Shell starten fehlgeschlagen: %v", err))
		return
	}
	hijack, err := docker.CLI.ContainerExecAttach(ctx, exec.ID, container.ExecAttachOptions{Tty: true})
	if err != nil {
		closeConn(conn, fmt.Sprintf("Verbinden fehlgeschlagen: %v", err))
		return
	}
	defer hijack.Close()

	// Container → Browser
	go func() {
		defer cancel()
		buf := make([]byte, 4096)
		for {
			n, err := hijack.Reader.Read(buf)
			if n > 0 {
				if sendData(conn, buf[:n]) != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()

	// Browser → Container / Größenänderung
	go func() {
		defer cancel()
		for {
			m, err := readMsg(conn)
			if err != nil {
				return
			}
			switch m.Type {
			case "data":
				if _, err := hijack.Conn.Write([]byte(m.Data)); err != nil {
					return
				}
			case "resize":
				if m.Cols > 0 && m.Rows > 0 {
					docker.CLI.ContainerExecResize(ctx, exec.ID, container.ResizeOptions{Height: uint(m.Rows), Width: uint(m.Cols)})
				}
			}
		}
	}()

	<-ctx.Done()
	conn.WriteMessage(websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, "Shell beendet"))
}
