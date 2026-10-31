package web

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"

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
	name := mux.Vars(r)["name"]
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
	name := mux.Vars(r)["name"]
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
		name := mux.Vars(r)["name"]
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
	name := mux.Vars(r)["name"]
	result := docker.RunCompose(name, 30*time.Second, "-p", name, "logs", "--no-color", "--tail=200")
	jsonOK(w, result)
}

func handleStackDelete(w http.ResponseWriter, r *http.Request) {
	if !requireLocalPerm(w, r, users.PermStacksEdit) {
		return
	}
	name := mux.Vars(r)["name"]
	if err := docker.DeleteStack(name); err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	jsonOK(w, map[string]bool{"ok": true})
}

func handleStackImport(w http.ResponseWriter, r *http.Request) {
	if !requireLocalPerm(w, r, users.PermStacksEdit) {
		return
	}
	var body struct {
		URL   string `json:"url"`
		Token string `json:"token"`
		Name  string `json:"name"`
	}
	if err := parseJSON(r, &body); err != nil {
		jsonErr(w, http.StatusBadRequest, "Ungültige Anfrage")
		return
	}
	body.URL = strings.TrimSpace(body.URL)
	body.Name = strings.TrimSpace(body.Name)
	if body.URL == "" || body.Name == "" {
		jsonErr(w, http.StatusBadRequest, "URL und Stack-Name erforderlich")
		return
	}
	if !safeNameRe.MatchString(body.Name) {
		jsonErr(w, http.StatusBadRequest, "Ungültiger Stack-Name")
		return
	}
	var tokenValue string
	if body.Token != "" {
		tokens := config.LoadTokens()
		val, ok := tokens[body.Token]
		if !ok {
			jsonErr(w, http.StatusBadRequest, fmt.Sprintf("Token '%s' nicht gefunden", body.Token))
			return
		}
		tokenValue = val
	}
	if err := docker.ImportStack(body.Name, body.URL, tokenValue); err != nil {
		jsonErr(w, http.StatusBadRequest, err.Error())
		return
	}
	jsonOK(w, map[string]bool{"ok": true})
}
