package web

import (
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"

	"dockpilot/internal/auth"
	"dockpilot/internal/config"
	"dockpilot/internal/users"
)

func handleSetupPage(w http.ResponseWriter, r *http.Request) {
	htmlPage(w, templateContent("setup.html"))
}

// validSetupRequest: Während der Ersteinrichtung muss der Setup-Code aus dem Log mitkommen.
// Sonst könnte jeder, der den Port erreicht, den ersten Admin anlegen.
func validSetupRequest(w http.ResponseWriter, r *http.Request) bool {
	if config.ValidSetupToken(r.Header.Get("X-Setup-Token")) {
		return true
	}
	jsonErr(w, http.StatusForbidden, "Setup-Code fehlt oder ist falsch – er steht im Log des Containers (docker logs dockpilot)")
	return false
}

// setupAllowed: Während der Ersteinrichtung nur mit Setup-Code. Danach im Agent-Modus
// nur mit dem Agent-Token (es gibt dort keine Benutzer), sonst nur für Admins.
func setupAllowed(w http.ResponseWriter, r *http.Request) bool {
	if config.NeedsSetup() {
		return validSetupRequest(w, r)
	}
	if config.LoadMode().Mode == "agent" {
		if auth.ValidBearer(r) {
			return true
		}
		jsonErr(w, http.StatusUnauthorized, "Agent-Token erforderlich")
		return false
	}
	return requireAdmin(w, r)
}

func handleSetupCredentials(w http.ResponseWriter, r *http.Request) {
	if !config.NeedsSetup() || users.Any() {
		jsonErr(w, http.StatusForbidden, "Einrichtung bereits abgeschlossen – Benutzer unter Wartung → Benutzer verwalten")
		return
	}
	if config.LoadMode().Mode == "agent" {
		jsonErr(w, http.StatusForbidden, "Im Agent-Modus gibt es keine Benutzer")
		return
	}
	if !validSetupRequest(w, r) {
		return
	}
	var body struct {
		User     string `json:"user"`
		Password string `json:"password"`
	}
	if err := parseJSON(r, &body); err != nil {
		jsonErr(w, http.StatusBadRequest, "Ungültige Anfrage")
		return
	}
	user := strings.TrimSpace(body.User)
	if user == "" || len(body.Password) < 8 {
		jsonErr(w, http.StatusBadRequest, "Benutzername und Passwort (min. 8 Zeichen) erforderlich")
		return
	}
	if err := config.SaveCreds(config.Credentials{Secret: auth.RandomToken()}); err != nil {
		jsonErr(w, http.StatusInternalServerError, "Speichern fehlgeschlagen")
		return
	}
	if err := users.Create(user, body.Password, users.RoleAdmin, nil); err != nil {
		jsonErr(w, http.StatusBadRequest, err.Error())
		return
	}
	jsonOK(w, map[string]bool{"ok": true})
}

// handleSetupModeGet gibt die Konfiguration ohne Agent-Token aus.
func handleSetupModeGet(w http.ResponseWriter, r *http.Request) {
	if !setupAllowed(w, r) {
		return
	}
	jsonOK(w, config.LoadMode().Public())
}

// validHTTPURL akzeptiert nur absolute http(s)-URLs.
func validHTTPURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

func handleSetupModePost(w http.ResponseWriter, r *http.Request) {
	if !setupAllowed(w, r) {
		return
	}
	var body struct {
		Mode       string `json:"mode"`
		HubURL     string `json:"hub_url"`
		AgentToken string `json:"agent_token"`
		AgentName  string `json:"agent_name"`
		AgentURL   string `json:"agent_url"`
	}
	if err := parseJSON(r, &body); err != nil {
		jsonErr(w, http.StatusBadRequest, "Ungültige Anfrage")
		return
	}
	mode := strings.TrimSpace(body.Mode)
	if mode != "standalone" && mode != "hub" && mode != "agent" {
		jsonErr(w, http.StatusBadRequest, "Ungültiger Modus")
		return
	}
	m := config.Mode{Mode: mode}
	if mode == "agent" {
		hubURL := strings.TrimRight(strings.TrimSpace(body.HubURL), "/")
		if !validHTTPURL(hubURL) {
			jsonErr(w, http.StatusBadRequest, "Hub-URL erforderlich (http:// oder https://)")
			return
		}
		agentURL := strings.TrimRight(strings.TrimSpace(body.AgentURL), "/")
		if agentURL != "" && !validHTTPURL(agentURL) {
			jsonErr(w, http.StatusBadRequest, "Eigene URL muss mit http:// oder https:// beginnen")
			return
		}
		// Leerer Token heißt: bisherigen behalten. Ein neuer Agent braucht den Token vom Hub.
		token := strings.TrimSpace(body.AgentToken)
		if cur := config.LoadMode(); token == "" && cur.Mode == "agent" {
			token = cur.AgentToken
		}
		if token == "" {
			jsonErr(w, http.StatusBadRequest, "Agent-Token vom Hub erforderlich")
			return
		}
		name := strings.TrimSpace(body.AgentName)
		if name == "" {
			if h, err := os.Hostname(); err == nil {
				name = h
			} else {
				name = "agent"
			}
		}
		m.HubURL = hubURL
		m.AgentToken = token
		m.AgentName = name
		m.AgentURL = agentURL
	}
	wasSetup := config.NeedsSetup()
	if err := config.SaveMode(m); err != nil {
		jsonErr(w, http.StatusInternalServerError, "Speichern fehlgeschlagen")
		return
	}
	// Führt ein Moduswechsel (z. B. Agent → Standalone) zurück in die Einrichtung,
	// steht der Code sonst nirgends im Log.
	if !wasSetup && config.NeedsSetup() {
		log.Printf("Ersteinrichtung: Setup-Code %s (im Browser unter /setup eingeben)", config.SetupToken())
	}
	jsonOK(w, map[string]interface{}{"ok": true, "mode": mode})
}
