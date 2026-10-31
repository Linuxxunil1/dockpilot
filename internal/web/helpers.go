package web

import (
	"encoding/json"
	"net/http"
	"regexp"

	"dockpilot/internal/auth"
	"dockpilot/internal/users"
)

var safeNameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$`)

func jsonOK(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func jsonErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"detail": msg})
}

func parseJSON(r *http.Request, v interface{}) error {
	return json.NewDecoder(r.Body).Decode(v)
}

// requireAuth rejects if not authenticated via cookie (any role).
func requireAuth(w http.ResponseWriter, r *http.Request) bool {
	if !auth.IsCookieAuth(r) {
		jsonErr(w, http.StatusUnauthorized, "Nicht autorisiert")
		return false
	}
	return true
}

// requireAdmin rejects unless a cookie-authenticated admin is logged in.
func requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	u := auth.SessionUser(r)
	if u == nil {
		jsonErr(w, http.StatusUnauthorized, "Nicht autorisiert")
		return false
	}
	if !u.IsAdmin() {
		jsonErr(w, http.StatusForbidden, "Nur für Administratoren")
		return false
	}
	return true
}

// requireAdminAny accepts an admin session or the agent Bearer token (hub → agent).
func requireAdminAny(w http.ResponseWriter, r *http.Request) bool {
	if auth.ValidBearer(r) {
		return true
	}
	return requireAdmin(w, r)
}

// requireServerPerm verlangt eine Session mit dem Recht perm (leer = keins nötig)
// und Zugriff auf den Server serverID (users.ServerLocal für diesen Server).
func requireServerPerm(w http.ResponseWriter, r *http.Request, serverID, perm string) bool {
	u := auth.SessionUser(r)
	if u == nil {
		jsonErr(w, http.StatusUnauthorized, "Nicht autorisiert")
		return false
	}
	a := u.Access()
	if perm != "" && !a.Can(perm) {
		jsonErr(w, http.StatusForbidden, "Keine Berechtigung für diese Aktion")
		return false
	}
	if !a.CanServer(serverID) {
		jsonErr(w, http.StatusForbidden, "Kein Zugriff auf diesen Server")
		return false
	}
	return true
}

// requireLocalPerm prüft das Recht für diesen Server. Der Hub (Agent-Bearer) darf alles.
func requireLocalPerm(w http.ResponseWriter, r *http.Request, perm string) bool {
	if auth.ValidBearer(r) {
		return true
	}
	return requireServerPerm(w, r, users.ServerLocal, perm)
}

// containerActionPerm: start/stop/restart sind Steuerung, alles andere (update) eigenes Recht.
func containerActionPerm(action string) string {
	if action == "start" || action == "stop" || action == "restart" {
		return users.PermContainersControl
	}
	return users.PermContainersUpdate
}

// stackActionPerm: up/down steuern, logs ansehen, alles andere (pull) bearbeiten.
func stackActionPerm(action string) string {
	switch action {
	case "up", "down":
		return users.PermStacksControl
	case "logs":
		return users.PermStacksView
	}
	return users.PermStacksEdit
}

// requireAuthAny accepts cookie or Bearer token.
func requireAuthAny(w http.ResponseWriter, r *http.Request) bool {
	if !auth.IsAuthenticated(r) {
		jsonErr(w, http.StatusUnauthorized, "Nicht autorisiert")
		return false
	}
	return true
}

func htmlPage(w http.ResponseWriter, body string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(body))
}
