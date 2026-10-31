package web

import (
	"crypto/hmac"
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"

	"dockpilot/internal/auth"
	"dockpilot/internal/config"
	"dockpilot/internal/regcerts"
	"dockpilot/internal/servers"
	"dockpilot/internal/users"
)

// handleAgentRegister — hub-side: agent registers its URL with a Bearer token.
func handleAgentRegister(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		jsonErr(w, http.StatusUnauthorized, "Bearer token required")
		return
	}
	token := authHeader[7:]

	var body struct {
		URL  string `json:"url"`
		Name string `json:"name"`
	}
	if err := parseJSON(r, &body); err != nil {
		jsonErr(w, http.StatusBadRequest, "Ungültige Anfrage")
		return
	}

	agentURL := strings.TrimRight(strings.TrimSpace(body.URL), "/")
	if agentURL != "" && !validHTTPURL(agentURL) {
		jsonErr(w, http.StatusBadRequest, "Agent-URL muss mit http:// oder https:// beginnen")
		return
	}
	name := strings.TrimSpace(body.Name)
	if len(name) > 128 {
		name = name[:128]
	}

	list := servers.Load()
	for _, s := range list {
		if s.Type == "agent" && hmac.Equal([]byte(s.Token), []byte(token)) {
			// Die URL gilt nur bei der ersten Registrierung sofort. Eine spätere Änderung
			// muss ein Admin bestätigen – sonst könnte, wer den Token kennt, den Hub samt
			// Registry-Zugangsdaten auf einen eigenen Server umleiten.
			changed := agentURL != "" && s.URL != "" && agentURL != s.URL
			servers.Update(s.ID, func(srv *servers.Server) {
				switch {
				case agentURL == "":
				case srv.URL == "":
					srv.URL = agentURL
					if strings.HasPrefix(agentURL, "http://") {
						log.Printf("Agent %s registriert sich unverschlüsselt (%s) – HTTPS empfohlen", srv.Name, agentURL)
					}
				case agentURL != srv.URL:
					srv.PendingURL = agentURL
				default:
					srv.PendingURL = ""
				}
				if name != "" {
					srv.Name = name
				}
			})
			servers.TouchLastSeen(s.ID)
			if changed {
				log.Printf("Agent %s meldet neue URL %s – wartet auf Bestätigung durch einen Admin", s.Name, agentURL)
				jsonErr(w, http.StatusConflict, "Neue Agent-URL muss auf dem Hub von einem Admin bestätigt werden")
				return
			}
			jsonOK(w, map[string]bool{"ok": true})
			return
		}
	}
	jsonErr(w, http.StatusUnauthorized, "Unbekannter Agent-Token")
}

// handleAgentInvite — hub generates an invite token for a new agent.
func handleAgentInvite(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}
	var body struct {
		Name string `json:"name"`
	}
	if err := parseJSON(r, &body); err != nil {
		jsonErr(w, http.StatusBadRequest, "Ungültige Anfrage")
		return
	}
	name := strings.TrimSpace(body.Name)
	if name == "" {
		name = "Neuer Agent"
	}
	token := auth.RandomToken()
	srv := servers.Server{
		ID:    uuid.New().String(),
		Name:  name,
		Type:  "agent",
		Token: token,
	}
	if err := servers.Add(srv); err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	jsonOK(w, map[string]interface{}{"ok": true, "id": srv.ID, "token": token})
}

// handleAgentHubStatus: Die Statusseite des Agents zeigt ohne Anmeldung nur online/offline.
// Details (eigene URL, Fehlermeldung) gibt es nur mit dem Agent-Token.
func handleAgentHubStatus(w http.ResponseWriter, r *http.Request) {
	if config.LoadMode().Mode != "agent" {
		jsonErr(w, http.StatusNotFound, "Kein Agent")
		return
	}
	result := servers.Status()
	resp := map[string]interface{}{"online": result.Online}
	if auth.ValidBearer(r) {
		resp["agent_url"] = servers.AgentURL()
		if result.Error != "" {
			resp["error"] = result.Error
		}
	}
	jsonOK(w, resp)
}

func handleServersList(w http.ResponseWriter, r *http.Request) {
	if !requireAuth(w, r) {
		return
	}
	access := auth.SessionUser(r).Access()
	list := servers.Load()
	safe := make([]map[string]interface{}, 0, len(list))
	for _, s := range list {
		if access.CanServer(s.ID) {
			safe = append(safe, s.Safe())
		}
	}
	jsonOK(w, safe)
}

func handleServerAdd(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}
	var body struct {
		Type       string `json:"type"`
		Name       string `json:"name"`
		Host       string `json:"host"`
		Port       int    `json:"port"`
		Username   string `json:"username"`
		AuthType   string `json:"auth_type"`
		Password   string `json:"password"`
		SSHKey     string `json:"ssh_key"`
		Passphrase string `json:"passphrase"`
		SSHCert    string `json:"ssh_cert"`
		Token      string `json:"token"`
		URL        string `json:"url"`
		HostKey    string `json:"host_key"`
	}
	if err := parseJSON(r, &body); err != nil {
		jsonErr(w, http.StatusBadRequest, "Ungültige Anfrage")
		return
	}
	name := strings.TrimSpace(body.Name)
	if name == "" {
		jsonErr(w, http.StatusBadRequest, "Name ist erforderlich")
		return
	}

	srv := servers.Server{
		ID:   uuid.New().String(),
		Name: name,
		Type: body.Type,
	}

	if body.Type == "agent" {
		token := strings.TrimSpace(body.Token)
		if token == "" {
			jsonErr(w, http.StatusBadRequest, "Token ist erforderlich")
			return
		}
		srv.Token = token
		srv.URL = strings.TrimRight(strings.TrimSpace(body.URL), "/")
		if srv.URL != "" && !validHTTPURL(srv.URL) {
			jsonErr(w, http.StatusBadRequest, "URL muss mit http:// oder https:// beginnen")
			return
		}
	} else {
		host := strings.TrimSpace(body.Host)
		username := strings.TrimSpace(body.Username)
		if host == "" || username == "" {
			jsonErr(w, http.StatusBadRequest, "Host und Benutzer sind erforderlich")
			return
		}
		srv.Host = host
		srv.Port = body.Port
		if srv.Port == 0 {
			srv.Port = 22
		}
		srv.Username = username
		srv.Type = "ssh"
		srv.AuthType = body.AuthType
		if body.AuthType == "password" {
			if body.Password == "" {
				jsonErr(w, http.StatusBadRequest, "Passwort ist erforderlich")
				return
			}
			srv.Password = body.Password
		} else {
			srv.AuthType = "key"
			srv.SSHKey = strings.TrimSpace(body.SSHKey) + "\n"
			srv.Passphrase = body.Passphrase
			srv.SSHCert = strings.TrimSpace(body.SSHCert)
		}
		if err := servers.ValidateAuth(&srv); err != nil {
			jsonErr(w, http.StatusBadRequest, err.Error())
			return
		}
		if hk := strings.TrimSpace(body.HostKey); hk != "" {
			if err := servers.PinHostKey(srv.ID, hk); err != nil {
				jsonErr(w, http.StatusBadRequest, err.Error())
				return
			}
		}
	}
	if err := servers.Add(srv); err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	jsonOK(w, map[string]interface{}{"ok": true, "id": srv.ID})
}

func handleServerUpdate(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}
	id := mux.Vars(r)["id"]
	var body map[string]interface{}
	if err := parseJSON(r, &body); err != nil {
		jsonErr(w, http.StatusBadRequest, "Ungültige Anfrage")
		return
	}
	srv := servers.Get(id)
	if srv == nil {
		jsonErr(w, http.StatusNotFound, "Server nicht gefunden")
		return
	}
	str := func(k string) string { v, _ := body[k].(string); return strings.TrimSpace(v) }
	// Leere Geheimnisse bedeuten "unverändert lassen".
	if v := str("name"); v != "" {
		srv.Name = v
	}
	if v := str("host"); v != "" {
		srv.Host = v
	}
	if v := str("username"); v != "" {
		srv.Username = v
	}
	if v, ok := body["port"].(float64); ok && v > 0 {
		srv.Port = int(v)
	}
	switch at := str("auth_type"); {
	case at == "password" || at == "key":
		srv.AuthType = at
	case str("ssh_key") != "":
		srv.AuthType = "key"
	case str("password") != "":
		srv.AuthType = "password"
	}
	if srv.AuthType == "password" {
		if v, _ := body["password"].(string); v != "" {
			srv.Password = v
		}
		srv.SSHKey, srv.Passphrase, srv.SSHCert = "", "", ""
	} else {
		if v := str("ssh_key"); v != "" {
			srv.SSHKey = v + "\n"
		}
		if v, _ := body["passphrase"].(string); v != "" {
			srv.Passphrase = v
		}
		if v, ok := body["ssh_cert"].(string); ok {
			srv.SSHCert = strings.TrimSpace(v)
		}
		srv.Password = ""
	}
	if srv.Type != "agent" {
		if err := servers.ValidateAuth(srv); err != nil {
			jsonErr(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	updated := *srv
	if err := servers.Update(id, func(s *servers.Server) { *s = updated }); err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	jsonOK(w, map[string]bool{"ok": true})
}

func handleServerPatch(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}
	id := mux.Vars(r)["id"]
	var body map[string]interface{}
	if err := parseJSON(r, &body); err != nil {
		jsonErr(w, http.StatusBadRequest, "Ungültige Anfrage")
		return
	}
	// Vom Agent gemeldete neue URL übernehmen ("confirm_url": angezeigte URL) bzw.
	// verwerfen ("reject_url": true). Die URL muss mitkommen: Hat der Agent inzwischen
	// eine andere gemeldet, wird nichts übernommen.
	confirm, _ := body["confirm_url"].(string)
	reject, _ := body["reject_url"].(bool)
	stale := false
	err := servers.Update(id, func(s *servers.Server) {
		if v, ok := body["name"].(string); ok {
			if len(v) > 128 {
				v = v[:128]
			}
			s.Name = v
		}
		switch {
		case confirm != "" && confirm == s.PendingURL:
			s.URL, s.PendingURL = s.PendingURL, ""
		case confirm != "":
			stale = true
		case reject:
			s.PendingURL = ""
		}
	})
	if err != nil {
		jsonErr(w, http.StatusNotFound, err.Error())
		return
	}
	if stale {
		jsonErr(w, http.StatusConflict, "Der Agent hat inzwischen eine andere URL gemeldet – bitte neu laden und erneut prüfen")
		return
	}
	jsonOK(w, map[string]bool{"ok": true})
}

// handleServerHostKey liest den SSH-Hostkey, damit der Admin ihn vor dem Speichern prüfen kann.
func handleServerHostKey(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}
	var body struct {
		Host string `json:"host"`
		Port int    `json:"port"`
	}
	if err := parseJSON(r, &body); err != nil || strings.TrimSpace(body.Host) == "" {
		jsonErr(w, http.StatusBadRequest, "Host erforderlich")
		return
	}
	fp, err := servers.ScanHostKey(strings.TrimSpace(body.Host), body.Port)
	if err != nil {
		jsonErr(w, http.StatusBadGateway, "Hostkey nicht lesbar: "+err.Error())
		return
	}
	jsonOK(w, map[string]string{"fingerprint": fp})
}

func handleServerDelete(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}
	id := mux.Vars(r)["id"]
	if err := servers.Delete(id); err != nil {
		jsonErr(w, http.StatusNotFound, "Server nicht gefunden")
		return
	}
	jsonOK(w, map[string]bool{"ok": true})
}

func handleServerResetKnownHost(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}
	id := mux.Vars(r)["id"]
	srv := servers.Get(id)
	if srv == nil {
		jsonErr(w, http.StatusNotFound, "Server nicht gefunden")
		return
	}
	servers.ResetKnownHost(id)
	jsonOK(w, map[string]bool{"ok": true})
}

func handleServerTest(w http.ResponseWriter, r *http.Request) {
	if !requireServerPerm(w, r, mux.Vars(r)["id"], "") {
		return
	}
	id := mux.Vars(r)["id"]
	srv := servers.Get(id)
	if srv == nil {
		jsonErr(w, http.StatusNotFound, "Server nicht gefunden")
		return
	}
	if srv.Type == "agent" {
		if srv.URL == "" {
			jsonErr(w, http.StatusServiceUnavailable, "Agent noch nicht registriert (URL unbekannt)")
			return
		}
		if _, err := servers.AgentGet(srv, "/api/host"); err != nil {
			jsonErr(w, http.StatusBadRequest, err.Error())
			return
		}
		jsonOK(w, map[string]bool{"ok": true})
		return
	}
	if err := servers.TestConnection(srv); err != nil {
		jsonErr(w, http.StatusBadRequest, err.Error())
		return
	}
	jsonOK(w, map[string]bool{"ok": true})
}

// ── Hub→Agent proxy handlers ──────────────────────────────────────────────────

func agentServer(w http.ResponseWriter, r *http.Request) *servers.Server {
	id := mux.Vars(r)["id"]
	srv := servers.Get(id)
	if srv == nil {
		jsonErr(w, http.StatusNotFound, "Server nicht gefunden")
		return nil
	}
	if srv.Type != "agent" {
		jsonErr(w, http.StatusBadRequest, "Nur für Agent-Server")
		return nil
	}
	if srv.URL == "" {
		jsonErr(w, http.StatusServiceUnavailable, "Agent-URL unbekannt – Agent noch nicht registriert")
		return nil
	}
	return srv
}

func handleServerContainers(w http.ResponseWriter, r *http.Request) {
	if !requireServerPerm(w, r, mux.Vars(r)["id"], users.PermContainersView) {
		return
	}
	srv := agentServer(w, r)
	if srv == nil {
		return
	}
	data, err := servers.AgentGet(srv, "/api/containers")
	if err != nil {
		jsonErr(w, http.StatusBadGateway, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

func handleServerContainerAction(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	if !requireServerPerm(w, r, vars["id"], containerActionPerm(vars["action"])) {
		return
	}
	switch vars["action"] {
	case "start", "stop", "restart", "update":
	default:
		jsonErr(w, http.StatusBadRequest, "Unbekannte Aktion")
		return
	}
	srv := agentServer(w, r)
	if srv == nil {
		return
	}
	if vars["action"] == "update" {
		syncRegistriesToAgent(srv)
		syncInsecureRegistriesToAgent(srv)
		syncRegistryCertsToAgent(srv)
	}
	path := "/api/containers/" + url.PathEscape(vars["cid"]) + "/" + vars["action"]
	data, err := servers.AgentPost(srv, path, nil, 120*time.Second)
	if err != nil {
		jsonErr(w, http.StatusBadGateway, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

func handleServerHost(w http.ResponseWriter, r *http.Request) {
	if !requireServerPerm(w, r, mux.Vars(r)["id"], users.PermContainersView) {
		return
	}
	srv := agentServer(w, r)
	if srv == nil {
		return
	}
	data, err := servers.AgentGet(srv, "/api/host")
	if err != nil {
		jsonErr(w, http.StatusBadGateway, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

func handleServerVersion(w http.ResponseWriter, r *http.Request) {
	if !requireServerPerm(w, r, mux.Vars(r)["id"], "") {
		return
	}
	srv := agentServer(w, r)
	if srv == nil {
		return
	}
	data, err := servers.AgentGet(srv, "/api/version")
	if err != nil && strings.Contains(err.Error(), "HTTP 404") {
		// Agent ist älter als die Versionsanzeige.
		jsonOK(w, map[string]string{"version": "unbekannt (alte Version)"})
		return
	}
	if err != nil {
		jsonErr(w, http.StatusBadGateway, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

func handleServerStacks(w http.ResponseWriter, r *http.Request) {
	if !requireServerPerm(w, r, mux.Vars(r)["id"], users.PermStacksView) {
		return
	}
	srv := agentServer(w, r)
	if srv == nil {
		return
	}
	data, err := servers.AgentGet(srv, "/api/stacks")
	if err != nil {
		jsonErr(w, http.StatusBadGateway, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

func handleServerStackFileGet(w http.ResponseWriter, r *http.Request) {
	if !requireServerPerm(w, r, mux.Vars(r)["id"], users.PermStacksView) {
		return
	}
	srv := agentServer(w, r)
	if srv == nil {
		return
	}
	name, ok := stackName(w, r)
	if !ok {
		return
	}
	data, err := servers.AgentGet(srv, "/api/stacks/"+url.PathEscape(name)+"/file")
	if err != nil {
		jsonErr(w, http.StatusBadGateway, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

func handleServerStackFilePut(w http.ResponseWriter, r *http.Request) {
	if !requireServerPerm(w, r, mux.Vars(r)["id"], users.PermStacksEdit) {
		return
	}
	srv := agentServer(w, r)
	if srv == nil {
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
	data, err := servers.AgentPut(srv, "/api/stacks/"+url.PathEscape(name)+"/file", body)
	if err != nil {
		jsonErr(w, http.StatusBadGateway, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

// syncRegistriesToAgent pushes the hub's docker registry credentials to the agent
// so docker compose can authenticate with private registries during pull/up.
func syncRegistriesToAgent(srv *servers.Server) {
	raw := config.DockerCfgRaw()
	if raw == nil {
		log.Printf("registry-sync: hub hat keine Credentials — übersprungen")
		return
	}
	if _, err := servers.AgentPost(srv, "/api/registries/sync", json.RawMessage(raw), 10*time.Second); err != nil {
		log.Printf("registry-sync → agent %s FEHLGESCHLAGEN: %v", srv.Name, err)
	} else {
		log.Printf("registry-sync → agent %s: OK", srv.Name)
	}
}

// syncInsecureRegistriesToAgent pushes the hub's insecure-registry list to the agent
// so the agent's dockerd also allows HTTP registries.
func syncInsecureRegistriesToAgent(srv *servers.Server) {
	list := config.InsecureRegistries()
	if len(list) == 0 {
		return
	}
	if _, err := servers.AgentPost(srv, "/api/insecure-registries/sync", list, 10*time.Second); err != nil {
		log.Printf("insecure-sync → agent %s FEHLGESCHLAGEN: %v", srv.Name, err)
	} else {
		log.Printf("insecure-sync → agent %s: %v", srv.Name, list)
	}
}

// syncRegistryCertsToAgent überträgt die Registry-Zertifikate des Hubs zum Agent.
func syncRegistryCertsToAgent(srv *servers.Server) {
	list := regcerts.Export()
	if len(list) == 0 {
		return
	}
	if _, err := servers.AgentPost(srv, "/api/registry-certs/sync", list, 10*time.Second); err != nil {
		log.Printf("cert-sync → agent %s FEHLGESCHLAGEN: %v", srv.Name, err)
	} else {
		log.Printf("cert-sync → agent %s: %d Registries", srv.Name, len(list))
	}
}

func handleServerStackAction(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	action := vars["action"]
	if !requireServerPerm(w, r, vars["id"], stackActionPerm(action)) {
		return
	}
	switch action {
	case "up", "down", "pull", "logs":
	default:
		jsonErr(w, http.StatusBadRequest, "Unbekannte Aktion")
		return
	}
	name, ok := stackName(w, r)
	if !ok {
		return
	}
	srv := agentServer(w, r)
	if srv == nil {
		return
	}
	timeout := 120 * time.Second
	if action == "up" || action == "pull" {
		timeout = 300 * time.Second
		syncRegistriesToAgent(srv)
		syncInsecureRegistriesToAgent(srv)
		syncRegistryCertsToAgent(srv)
	}
	data, err := servers.AgentPost(srv, "/api/stacks/"+url.PathEscape(name)+"/"+action, nil, timeout)
	if err != nil {
		jsonErr(w, http.StatusBadGateway, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

func handleServerStackDelete(w http.ResponseWriter, r *http.Request) {
	if !requireServerPerm(w, r, mux.Vars(r)["id"], users.PermStacksEdit) {
		return
	}
	srv := agentServer(w, r)
	if srv == nil {
		return
	}
	name, ok := stackName(w, r)
	if !ok {
		return
	}
	data, err := servers.AgentDelete(srv, "/api/stacks/"+url.PathEscape(name))
	if err != nil {
		jsonErr(w, http.StatusBadGateway, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

func handleServerImages(w http.ResponseWriter, r *http.Request) {
	if !requireServerPerm(w, r, mux.Vars(r)["id"], users.PermImagesManage) {
		return
	}
	srv := agentServer(w, r)
	if srv == nil {
		return
	}
	data, err := servers.AgentGet(srv, "/api/images")
	if err != nil {
		jsonErr(w, http.StatusBadGateway, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

func handleServerImagesPrune(w http.ResponseWriter, r *http.Request) {
	if !requireServerPerm(w, r, mux.Vars(r)["id"], users.PermImagesManage) {
		return
	}
	srv := agentServer(w, r)
	if srv == nil {
		return
	}
	data, err := servers.AgentPost(srv, "/api/images/prune", nil, 300*time.Second)
	if err != nil {
		jsonErr(w, http.StatusBadGateway, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

func handleServerImageDelete(w http.ResponseWriter, r *http.Request) {
	if !requireServerPerm(w, r, mux.Vars(r)["id"], users.PermImagesManage) {
		return
	}
	srv := agentServer(w, r)
	if srv == nil {
		return
	}
	iid := mux.Vars(r)["iid"]
	data, err := servers.AgentDelete(srv, "/api/images/"+url.PathEscape(iid))
	if err != nil {
		jsonErr(w, http.StatusBadGateway, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

// handleServerStackImport lädt die Compose-Datei auf dem Hub (Tokens verlassen den Hub nicht)
// und legt sie auf dem Agent als neuen Stack ab.
func handleServerStackImport(w http.ResponseWriter, r *http.Request) {
	if !requireServerPerm(w, r, mux.Vars(r)["id"], users.PermStacksEdit) {
		return
	}
	srv := agentServer(w, r)
	if srv == nil {
		return
	}
	name, content, ok := stackImportRequest(w, r)
	if !ok {
		return
	}
	body := map[string]string{"content": content}
	if _, err := servers.AgentPut(srv, "/api/stacks/"+url.PathEscape(name)+"/file", body); err != nil {
		jsonErr(w, http.StatusBadGateway, err.Error())
		return
	}
	jsonOK(w, map[string]bool{"ok": true})
}
