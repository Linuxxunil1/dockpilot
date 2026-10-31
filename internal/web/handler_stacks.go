package web

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"dockpilot/internal/auth"
	"dockpilot/internal/config"
	"dockpilot/internal/docker"
	"dockpilot/internal/users"
)

func handleStacks(w http.ResponseWriter, r *http.Request) {
	if !requireLocalPerm(w, r, users.PermStacksView) {
		return
	}
	list, err := docker.ListStacks()
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	jsonOK(w, list)
}

func handleStackFileGet(w http.ResponseWriter, r *http.Request) {
	if !requireLocalPerm(w, r, users.PermStacksView) {
		return
	}
	name, ok := stackName(w, r)
	if !ok {
		return
	}
	content, err := docker.ReadStackFile(name)
	if err != nil {
		jsonErr(w, http.StatusNotFound, "Stack nicht gefunden")
		return
	}
	jsonOK(w, map[string]string{"content": content})
}

func handleStackFilePut(w http.ResponseWriter, r *http.Request) {
	if !requireLocalPerm(w, r, users.PermStacksEdit) {
		return
	}
	name, ok := stackName(w, r)
	if !ok {
		return
	}
	var body struct {
		Content string `json:"content"`
	}
	if err := parseJSON(r, &body); err != nil {
		jsonErr(w, http.StatusBadRequest, "Ungültige Anfrage")
		return
	}
	if err := docker.WriteStackFile(name, body.Content); err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	jsonOK(w, map[string]bool{"ok": true})
}

func handleStackAction(action string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireLocalPerm(w, r, stackActionPerm(action)) {
			return
		}
		name, ok := stackName(w, r)
		if !ok {
			return
		}
		timeout := 120 * time.Second
		if action == "up" || action == "pull" {
			timeout = 300 * time.Second
		}
		var args []string
		switch action {
		case "up":
			args = []string{"-p", name, "up", "-d", "--remove-orphans"}
		case "down":
			args = []string{"-p", name, "down"}
		case "pull":
			args = []string{"-p", name, "pull"}
		default:
			jsonErr(w, http.StatusBadRequest, "Unbekannte Aktion")
			return
		}
		result := docker.RunCompose(name, timeout, args...)
		jsonOK(w, result)
	}
}

func handleStackLogs(w http.ResponseWriter, r *http.Request) {
	if !requireLocalPerm(w, r, users.PermStacksView) {
		return
	}
	name, ok := stackName(w, r)
	if !ok {
		return
	}
	result := docker.RunCompose(name, 30*time.Second, "-p", name, "logs", "--no-color", "--tail=200")
	jsonOK(w, result)
}

func handleStackDelete(w http.ResponseWriter, r *http.Request) {
	if !requireLocalPerm(w, r, users.PermStacksEdit) {
		return
	}
	name, ok := stackName(w, r)
	if !ok {
		return
	}
	if err := docker.DeleteStack(name); err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	jsonOK(w, map[string]bool{"ok": true})
}

// stackImportRequest prüft die Import-Anfrage und lädt die Compose-Datei.
// Gespeicherte Tokens dürfen nur Admins verwenden: Ein Benutzer könnte sonst eine eigene
// URL angeben und den Token-Wert abgreifen. Aus internen Netzen dürfen ebenfalls nur Admins laden.
func stackImportRequest(w http.ResponseWriter, r *http.Request) (name, content string, ok bool) {
	var body struct {
		URL   string `json:"url"`
		Token string `json:"token"`
		Name  string `json:"name"`
	}
	if err := parseJSON(r, &body); err != nil {
		jsonErr(w, http.StatusBadRequest, "Ungültige Anfrage")
		return "", "", false
	}
	body.URL = strings.TrimSpace(body.URL)
	body.Name = strings.TrimSpace(body.Name)
	if body.URL == "" || body.Name == "" {
		jsonErr(w, http.StatusBadRequest, "URL und Stack-Name erforderlich")
		return "", "", false
	}
	if !docker.ValidStackName(body.Name) {
		jsonErr(w, http.StatusBadRequest, "Ungültiger Stack-Name")
		return "", "", false
	}
	u := auth.SessionUser(r)
	admin := u != nil && u.IsAdmin()
	var tokenValue string
	if body.Token != "" {
		if !admin {
			jsonErr(w, http.StatusForbidden, "Gespeicherte Tokens dürfen nur Admins verwenden")
			return "", "", false
		}
		val, found := config.TokenValue(body.Token)
		if !found {
			jsonErr(w, http.StatusBadRequest, fmt.Sprintf("Token '%s' nicht gefunden", body.Token))
			return "", "", false
		}
		tokenValue = val
	}
	content, err := docker.FetchStack(body.URL, tokenValue, admin)
	if err != nil {
		jsonErr(w, http.StatusBadRequest, err.Error())
		return "", "", false
	}
	return body.Name, content, true
}

func handleStackImport(w http.ResponseWriter, r *http.Request) {
	if !requireLocalPerm(w, r, users.PermStacksEdit) {
		return
	}
	name, content, ok := stackImportRequest(w, r)
	if !ok {
		return
	}
	if err := docker.WriteStackFile(name, content); err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	jsonOK(w, map[string]bool{"ok": true})
}
