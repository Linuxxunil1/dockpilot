package web

import (
	"net/http"
	"os"
	"strings"

	"dockpilot/internal/auth"
	"dockpilot/internal/config"
	"dockpilot/internal/users"
)

func handleSetupPage(w http.ResponseWriter, r *http.Request) {
	htmlPage(w, templateContent("setup.html"))
}

// setupAllowed: Setup-Endpunkte sind nur während der Ersteinrichtung offen,
// danach nur für Admins. Im Agent-Modus gibt es keinen Login – dort bleibt
// die Agent-Konfiguration wie bisher erreichbar.
func setupAllowed(w http.ResponseWriter, r *http.Request) bool {
	if config.NeedsSetup() || config.LoadMode().Mode == "agent" {
		return true
	}
	return requireAdmin(w, r)
}

func handleSetupCredentials(w http.ResponseWriter, r *http.Request) {
	if users.Any() {
		jsonErr(w, http.StatusForbidden, "Einrichtung bereits abgeschlossen – Benutzer unter Wartung → Benutzer verwalten")
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

func handleSetupModeGet(w http.ResponseWriter, r *http.Request) {
	if !setupAllowed(w, r) {
		return
	}
	m := config.LoadMode()
	jsonOK(w, m)
}

func handleSetupModePost(w http.ResponseWriter, r *http.Request) {
	if !setupAllowed(w, r) {
		return
	}
	var body struct {
		Mode      string `json:"mode"`
		HubURL    string `json:"hub_url"`
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
		if hubURL == "" {
			jsonErr(w, http.StatusBadRequest, "Hub-URL erforderlich")
			return
		}
		token := strings.TrimSpace(body.AgentToken)
		if token == "" {
			token = auth.RandomToken()
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
		m.AgentURL = strings.TrimRight(strings.TrimSpace(body.AgentURL), "/")
	}
	if err := config.SaveMode(m); err != nil {
		jsonErr(w, http.StatusInternalServerError, "Speichern fehlgeschlagen")
		return
	}
	jsonOK(w, map[string]interface{}{"ok": true, "mode": mode, "agent_token": m.AgentToken})
}
