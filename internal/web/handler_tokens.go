package web

import (
	"net/http"
	"strings"

	"github.com/gorilla/mux"

	"dockpilot/internal/config"
)

func handleTokensList(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}
	tokens := config.LoadTokens()
	names := make([]string, 0, len(tokens))
	for k := range tokens {
		names = append(names, k)
	}
	jsonOK(w, names)
}

func handleTokenSave(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}
	name := mux.Vars(r)["name"]
	if !safeNameRe.MatchString(name) {
		jsonErr(w, http.StatusBadRequest, "Ungültiger Token-Name")
		return
	}
	var body struct {
		Value string `json:"value"`
	}
	if err := parseJSON(r, &body); err != nil {
		jsonErr(w, http.StatusBadRequest, "Ungültige Anfrage")
		return
	}
	value := strings.TrimSpace(body.Value)
	if value == "" {
		jsonErr(w, http.StatusBadRequest, "Token-Wert darf nicht leer sein")
		return
	}
	tokens := config.LoadTokens()
	tokens[name] = value
	if err := config.SaveTokens(tokens); err != nil {
		jsonErr(w, http.StatusInternalServerError, "Speichern fehlgeschlagen")
		return
	}
	jsonOK(w, map[string]bool{"ok": true})
}

func handleTokenDelete(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}
	name := mux.Vars(r)["name"]
	tokens := config.LoadTokens()
	if _, ok := tokens[name]; !ok {
		jsonErr(w, http.StatusNotFound, "Token nicht gefunden")
		return
	}
	delete(tokens, name)
	if err := config.SaveTokens(tokens); err != nil {
		jsonErr(w, http.StatusInternalServerError, "Speichern fehlgeschlagen")
		return
	}
	jsonOK(w, map[string]bool{"ok": true})
}
