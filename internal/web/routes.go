package web

import (
	"net/http"

	"github.com/gorilla/mux"
)

func registerRoutes(r *mux.Router) {
	// ── Setup ────────────────────────────────────────────────────────
	r.HandleFunc("/setup", handleSetupPage).Methods("GET")
	r.HandleFunc("/api/setup/credentials", handleSetupCredentials).Methods("POST")
	r.HandleFunc("/api/setup/mode", handleSetupModeGet).Methods("GET")
	r.HandleFunc("/api/setup/mode", handleSetupModePost).Methods("POST")

	// ── Auth ─────────────────────────────────────────────────────────
	r.HandleFunc("/login", handleLoginPage).Methods("GET")
	r.HandleFunc("/login", handleLoginPost).Methods("POST")
	r.HandleFunc("/logout", handleLogout).Methods("POST")

	// ── UI ───────────────────────────────────────────────────────────
	r.HandleFunc("/", handleIndex).Methods("GET")

	// ── Local docker ─────────────────────────────────────────────────
	r.HandleFunc("/api/containers", handleContainers).Methods("GET")
	r.HandleFunc("/api/containers/{cid}/{action}", handleContainerAction).Methods("POST")
	r.HandleFunc("/api/host", handleHost).Methods("GET")
	r.HandleFunc("/api/sizes", handleSizes).Methods("GET")

	// ── Stacks ───────────────────────────────────────────────────────
	r.HandleFunc("/api/stacks", handleStacks).Methods("GET")
	r.HandleFunc("/api/stacks/import", handleStackImport).Methods("POST")
	r.HandleFunc("/api/stacks/{name}/file", handleStackFileGet).Methods("GET")
	r.HandleFunc("/api/stacks/{name}/file", handleStackFilePut).Methods("PUT")
	r.HandleFunc("/api/stacks/{name}/up", handleStackAction("up")).Methods("POST")
	r.HandleFunc("/api/stacks/{name}/down", handleStackAction("down")).Methods("POST")
	r.HandleFunc("/api/stacks/{name}/pull", handleStackAction("pull")).Methods("POST")
	r.HandleFunc("/api/stacks/{name}/logs", handleStackLogs).Methods("POST")
	r.HandleFunc("/api/stacks/{name}", handleStackDelete).Methods("DELETE")

	// ── Tokens ───────────────────────────────────────────────────────
	r.HandleFunc("/api/tokens", handleTokensList).Methods("GET")
	r.HandleFunc("/api/tokens/{name}", handleTokenSave).Methods("PUT")
	r.HandleFunc("/api/tokens/{name}", handleTokenDelete).Methods("DELETE")

	// ── Registries ───────────────────────────────────────────────────
	r.HandleFunc("/api/registries", handleRegistriesList).Methods("GET")
	r.HandleFunc("/api/registries", handleRegistryAdd).Methods("POST")
	r.HandleFunc("/api/registries/sync", handleRegistriesSync).Methods("POST")
	r.HandleFunc("/api/registries/{registry:.+}", handleRegistryDelete).Methods("DELETE")

	// ── Insecure registries (daemon.json) ────────────────────────────
	r.HandleFunc("/api/registry-certs", handleRegistryCertsList).Methods("GET")
	r.HandleFunc("/api/registry-certs", handleRegistryCertSave).Methods("POST")
	r.HandleFunc("/api/registry-certs/fetch", handleRegistryCertFetch).Methods("POST")
	r.HandleFunc("/api/registry-certs/sync", handleRegistryCertsSync).Methods("POST")
	r.HandleFunc("/api/registry-certs/{registry}", handleRegistryCertDelete).Methods("DELETE")

	r.HandleFunc("/api/insecure-registries", handleInsecureList).Methods("GET")
	r.HandleFunc("/api/insecure-registries", handleInsecureAdd).Methods("POST")
	r.HandleFunc("/api/insecure-registries/sync", handleInsecureSync).Methods("POST")
	r.HandleFunc("/api/insecure-registries/{registry:.+}", handleInsecureDelete).Methods("DELETE")

	// ── Images ───────────────────────────────────────────────────────
	r.HandleFunc("/api/images", handleImages).Methods("GET")
	r.HandleFunc("/api/images/prune", handleImagesPrune).Methods("POST")
	r.HandleFunc("/api/images/{id:.+}", handleImageDelete).Methods("DELETE")

	// ── Agent registration (hub-side) ─────────────────────────────────
	r.HandleFunc("/api/agents/register", handleAgentRegister).Methods("POST")
	r.HandleFunc("/api/servers/agent-invite", handleAgentInvite).Methods("POST")

	// ── Servers (hub manages remote servers) ──────────────────────────
	r.HandleFunc("/api/servers", handleServersList).Methods("GET")
	r.HandleFunc("/api/servers", handleServerAdd).Methods("POST")
	r.HandleFunc("/api/servers/{id}", handleServerUpdate).Methods("PUT")
	r.HandleFunc("/api/servers/{id}", handleServerPatch).Methods("PATCH")
	r.HandleFunc("/api/servers/{id}", handleServerDelete).Methods("DELETE")
	r.HandleFunc("/api/servers/host-key", handleServerHostKey).Methods("POST")
	r.HandleFunc("/api/servers/{id}/test", handleServerTest).Methods("POST")
	r.HandleFunc("/api/servers/{id}/known-host", handleServerResetKnownHost).Methods("DELETE")

	// ── Server proxy endpoints (hub → agent) ──────────────────────────
	r.HandleFunc("/api/servers/{id}/containers", handleServerContainers).Methods("GET")
	r.HandleFunc("/api/servers/{id}/containers/{cid}/{action}", handleServerContainerAction).Methods("POST")
	r.HandleFunc("/api/servers/{id}/host", handleServerHost).Methods("GET")
	r.HandleFunc("/api/servers/{id}/version", handleServerVersion).Methods("GET")
	r.HandleFunc("/api/servers/{id}/stacks", handleServerStacks).Methods("GET")
	r.HandleFunc("/api/servers/{id}/stacks/import", handleServerStackImport).Methods("POST")
	r.HandleFunc("/api/servers/{id}/stacks/{name}/file", handleServerStackFileGet).Methods("GET")
	r.HandleFunc("/api/servers/{id}/stacks/{name}/file", handleServerStackFilePut).Methods("PUT")
	r.HandleFunc("/api/servers/{id}/stacks/{name}/{action}", handleServerStackAction).Methods("POST")
	r.HandleFunc("/api/servers/{id}/stacks/{name}", handleServerStackDelete).Methods("DELETE")
	r.HandleFunc("/api/servers/{id}/images", handleServerImages).Methods("GET")
	r.HandleFunc("/api/servers/{id}/images/prune", handleServerImagesPrune).Methods("POST")
	r.HandleFunc("/api/servers/{id}/images/{iid:.+}", handleServerImageDelete).Methods("DELETE")

	// ── Konsolen (SSH, Container) ───────────────────────────────────────────────
	r.HandleFunc("/ws/ssh/{id}", handleWSSSH)
	r.HandleFunc("/ws/container/{cid}", handleWSContainer)
	r.HandleFunc("/ws/servers/{id}/container/{cid}", handleWSServerContainer)

	// ── Agent hub-status (agent-side) ─────────────────────────────────
	r.HandleFunc("/api/agent/hub-status", handleAgentHubStatus).Methods("GET")

	// ── Account & Benutzer ────────────────────────────────────────────
	r.HandleFunc("/api/me", handleMe).Methods("GET")
	r.HandleFunc("/api/version", handleVersion).Methods("GET")
	r.HandleFunc("/api/release", handleReleaseStatus).Methods("GET")
	r.HandleFunc("/api/release/check", handleReleaseCheck).Methods("POST")
	r.HandleFunc("/api/account/password", handleChangePassword).Methods("POST")
	r.HandleFunc("/api/users", handleUsersList).Methods("GET")
	r.HandleFunc("/api/users", handleUserCreate).Methods("POST")
	r.HandleFunc("/api/users/{name}", handleUserUpdate).Methods("PUT")
	r.HandleFunc("/api/users/{name}", handleUserDelete).Methods("DELETE")
	r.HandleFunc("/api/groups", handleGroupsList).Methods("GET")
	r.HandleFunc("/api/groups", handleGroupSave).Methods("POST")
	r.HandleFunc("/api/groups/{id}", handleGroupSave).Methods("PUT")
	r.HandleFunc("/api/groups/{id}", handleGroupDelete).Methods("DELETE")

	// ── Healthcheck ───────────────────────────────────────────────────
	r.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}).Methods("GET")
}
