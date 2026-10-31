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
	jsonOK(w, config.TokenNames())
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
	if err := config.SetToken(name, value); err != nil {
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
	found, err := config.DeleteToken(name)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "Speichern fehlgeschlagen")
		return
	}
	if !found {
		jsonErr(w, http.StatusNotFound, "Token nicht gefunden")
		return
	}
	jsonOK(w, map[string]bool{"ok": true})
}
