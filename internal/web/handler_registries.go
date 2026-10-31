package web

import (
	"io"
	"net/http"
	"strings"

	"github.com/gorilla/mux"

	"dockpilot/internal/config"
	"dockpilot/internal/regcerts"
	"dockpilot/internal/release"
)

// handleRegistriesSync is called by the hub before stack up/pull.
// It merges the hub's registry credentials into the agent's own config so
// docker compose can pull from private registries without separate configuration.
func handleRegistriesSync(w http.ResponseWriter, r *http.Request) {
	if !requireAdminAny(w, r) {
		return
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil || len(data) == 0 {
		jsonErr(w, http.StatusBadRequest, "Kein Body")
		return
	}
	if err := config.MergeDockerCfg(data); err != nil {
		jsonErr(w, http.StatusBadRequest, err.Error())
		return
	}
	jsonOK(w, map[string]bool{"ok": true})
}

// ── Insecure Registries ──────────────────────────────────────────────────────

// handleInsecureSync accepts the hub's full insecure-registry list and applies it
// to the agent's daemon.json so HTTP registries work without manual configuration.
func handleInsecureSync(w http.ResponseWriter, r *http.Request) {
	if !requireAdminAny(w, r) {
		return
	}
	var list []string
	if err := parseJSON(r, &list); err != nil {
		jsonErr(w, http.StatusBadRequest, "Ungültige Anfrage")
		return
	}
	if err := config.SetInsecureRegistries(list); err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	jsonOK(w, map[string]bool{"ok": true})
}

func handleInsecureList(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}
	jsonOK(w, config.InsecureRegistries())
}

func handleInsecureAdd(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}
	var body struct {
		Registry string `json:"registry"`
	}
	if err := parseJSON(r, &body); err != nil {
		jsonErr(w, http.StatusBadRequest, "Ungültige Anfrage")
		return
	}
	registry := strings.TrimSpace(body.Registry)
	if registry == "" {
		jsonErr(w, http.StatusBadRequest, "Registry-Adresse erforderlich")
		return
	}
	if err := config.AddInsecureRegistry(registry); err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	release.CheckSoon()
	jsonOK(w, map[string]bool{"ok": true})
}

func handleInsecureDelete(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}
	registry := mux.Vars(r)["registry"]
	if err := config.RemoveInsecureRegistry(registry); err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	release.CheckSoon()
	jsonOK(w, map[string]bool{"ok": true})
}

func handleRegistriesList(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}
	jsonOK(w, config.RegistryEntries())
}

func handleRegistryAdd(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}
	var body struct {
		Registry string `json:"registry"`
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := parseJSON(r, &body); err != nil {
		jsonErr(w, http.StatusBadRequest, "Ungültige Anfrage")
		return
	}
	registry := strings.TrimSpace(body.Registry)
	username := strings.TrimSpace(body.Username)
	password := strings.TrimSpace(body.Password)
	if registry == "" || username == "" || password == "" {
		jsonErr(w, http.StatusBadRequest, "Registry, Benutzername und Passwort/Token erforderlich")
		return
	}
	if err := config.AddRegistry(registry, username, password); err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	release.CheckSoon()
	jsonOK(w, map[string]bool{"ok": true})
}

func handleRegistryDelete(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}
	registry := mux.Vars(r)["registry"]
	list := config.RegistryList()
	found := false
	for _, r := range list {
		if r == registry {
			found = true
			break
		}
	}
	if !found {
		jsonErr(w, http.StatusNotFound, "Registry nicht gefunden")
		return
	}
	if err := config.RemoveRegistry(registry); err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	release.CheckSoon()
	jsonOK(w, map[string]bool{"ok": true})
}

// ── Registry-Zertifikate ─────────────────────────────────────────────────────

func handleRegistryCertsList(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}
	jsonOK(w, map[string]interface{}{"dir": regcerts.Dir, "certs": regcerts.List()})
}

func handleRegistryCertSave(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}
	var body regcerts.SyncEntry
	if err := parseJSON(r, &body); err != nil {
		jsonErr(w, http.StatusBadRequest, "Ungültige Anfrage")
		return
	}
	if err := regcerts.Save(body.Registry, body.CA, body.ClientCert, body.ClientKey); err != nil {
		jsonErr(w, http.StatusBadRequest, err.Error())
		return
	}
	release.CheckSoon()
	jsonOK(w, map[string]bool{"ok": true})
}

func handleRegistryCertFetch(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}
	var body struct {
		Registry string `json:"registry"`
	}
	if err := parseJSON(r, &body); err != nil {
		jsonErr(w, http.StatusBadRequest, "Ungültige Anfrage")
		return
	}
	f, err := regcerts.Fetch(body.Registry)
	if err != nil {
		jsonErr(w, http.StatusBadGateway, err.Error())
		return
	}
	jsonOK(w, f)
}

func handleRegistryCertDelete(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}
	if err := regcerts.Delete(mux.Vars(r)["registry"]); err != nil {
		jsonErr(w, http.StatusBadRequest, err.Error())
		return
	}
	release.CheckSoon()
	jsonOK(w, map[string]bool{"ok": true})
}

// handleRegistryCertsSync übernimmt die Zertifikate des Hubs auf dem Agent.
func handleRegistryCertsSync(w http.ResponseWriter, r *http.Request) {
	if !requireAdminAny(w, r) {
		return
	}
	var list []regcerts.SyncEntry
	if err := parseJSON(r, &list); err != nil {
		jsonErr(w, http.StatusBadRequest, "Ungültige Anfrage")
		return
	}
	if err := regcerts.Import(list); err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	jsonOK(w, map[string]bool{"ok": true})
}
