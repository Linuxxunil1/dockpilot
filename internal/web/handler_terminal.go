package web

import (
	"net/http"
	"net/url"

	"github.com/gorilla/mux"

	"dockpilot/internal/auth"
	"dockpilot/internal/servers"
	"dockpilot/internal/terminal"
	"dockpilot/internal/users"
)

func handleWSSSH(w http.ResponseWriter, r *http.Request) {
	u := auth.SessionUser(r)
	if u == nil {
		http.Error(w, "Nicht autorisiert", http.StatusUnauthorized)
		return
	}
	id := mux.Vars(r)["id"]
	if a := u.Access(); !a.Can(users.PermSSHConsole) || !a.CanServer(id) {
		http.Error(w, "Keine Berechtigung", http.StatusForbidden)
		return
	}
	if srv := servers.Get(id); srv == nil || srv.Type == "agent" {
		http.Error(w, "SSH-Server nicht gefunden", http.StatusNotFound)
		return
	}
	terminal.ServeSSH(w, r, id)
}

// handleWSContainer: Shell in einem Container dieses Servers (auch Hub → Agent per Bearer).
func handleWSContainer(w http.ResponseWriter, r *http.Request) {
	if !auth.ValidBearer(r) {
		u := auth.SessionUser(r)
		if u == nil {
			http.Error(w, "Nicht autorisiert", http.StatusUnauthorized)
			return
		}
		if a := u.Access(); !a.Can(users.PermContainersExec) || !a.CanServer(users.ServerLocal) {
			http.Error(w, "Keine Berechtigung", http.StatusForbidden)
			return
		}
	}
	terminal.ServeContainer(w, r, mux.Vars(r)["cid"])
}

// handleWSServerContainer reicht die Container-Konsole an den Agent weiter.
func handleWSServerContainer(w http.ResponseWriter, r *http.Request) {
	u := auth.SessionUser(r)
	if u == nil {
		http.Error(w, "Nicht autorisiert", http.StatusUnauthorized)
		return
	}
	vars := mux.Vars(r)
	if a := u.Access(); !a.Can(users.PermContainersExec) || !a.CanServer(vars["id"]) {
		http.Error(w, "Keine Berechtigung", http.StatusForbidden)
		return
	}
	srv := servers.Get(vars["id"])
	if srv == nil || srv.Type != "agent" || srv.URL == "" {
		http.Error(w, "Agent nicht gefunden", http.StatusNotFound)
		return
	}
	terminal.ServeAgentProxy(w, r, srv.URL, srv.Token, "/ws/container/"+url.PathEscape(vars["cid"]))
}
