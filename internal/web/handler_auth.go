package web

import (
	"html/template"
	"net/http"
	"strings"

	"dockpilot/internal/auth"
	"dockpilot/internal/config"
	"dockpilot/internal/release"
	"dockpilot/internal/users"
	"dockpilot/internal/version"
)

func handleLoginPage(w http.ResponseWriter, r *http.Request) {
	if config.NeedsSetup() {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	m := config.LoadMode()
	if m.Mode == "agent" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	errMsg := r.URL.Query().Get("error")
	page := strings.ReplaceAll(templateContent("login.html"), "{{ERROR}}", template.HTMLEscapeString(errMsg))
	htmlPage(w, page)
}

func handleLoginPost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/login?error=Fehler", http.StatusSeeOther)
		return
	}
	username := r.FormValue("username")
	password := r.FormValue("password")

	u := users.Authenticate(username, password)
	if u == nil {
		http.Redirect(w, r, "/login?error=Falsche+Zugangsdaten", http.StatusSeeOther)
		return
	}
	token := auth.MakeToken(u.Username)
	auth.SetSessionCookie(w, token)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	auth.ClearSessionCookie(w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	if config.NeedsSetup() {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	m := config.LoadMode()
	if m.Mode == "agent" {
		htmlPage(w, templateContent("agent.html"))
		return
	}
	if !auth.IsCookieAuth(r) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	htmlPage(w, templateContent("index.html"))
}

func handleChangePassword(w http.ResponseWriter, r *http.Request) {
	u := auth.SessionUser(r)
	if u == nil {
		jsonErr(w, http.StatusUnauthorized, "Nicht autorisiert")
		return
	}
	var body struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if err := parseJSON(r, &body); err != nil {
		jsonErr(w, http.StatusBadRequest, "Ungültige Anfrage")
		return
	}
	if users.Authenticate(u.Username, body.CurrentPassword) == nil {
		jsonErr(w, http.StatusForbidden, "Aktuelles Passwort falsch")
		return
	}
	if err := users.SetPassword(u.Username, body.NewPassword); err != nil {
		jsonErr(w, http.StatusBadRequest, err.Error())
		return
	}
	jsonOK(w, map[string]bool{"ok": true})
}

// handleMe — aktueller Benutzer, Rolle und Version für die Oberfläche.
func handleMe(w http.ResponseWriter, r *http.Request) {
	u := auth.SessionUser(r)
	if u == nil {
		jsonErr(w, http.StatusUnauthorized, "Nicht autorisiert")
		return
	}
	acc := u.Access()
	jsonOK(w, map[string]interface{}{"username": u.Username, "role": u.Role, "version": version.Version,
		"permissions": acc.Permissions, "servers": acc.Servers, "release": release.Current()})
}

func handleVersion(w http.ResponseWriter, r *http.Request) {
	st := release.Current()
	st.Error = ""
	jsonOK(w, map[string]interface{}{"version": version.Version, "release": st})
}

// handleReleaseStatus zeigt Admins das volle Ergebnis der Update-Prüfung.
func handleReleaseStatus(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}
	jsonOK(w, map[string]interface{}{"version": version.Version, "release": release.Current()})
}

func handleReleaseCheck(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}
	jsonOK(w, map[string]interface{}{"version": version.Version, "release": release.CheckNow()})
}
