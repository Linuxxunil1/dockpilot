package config

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

var (
	StacksDir              = env("STACKS_DIR", "/opt/dockpilot/stacks")
	DataDir                = env("DATA_DIR", "/data")
	CredsFile              = filepath.Join(DataDir, "credentials.json")
	UsersFile              = filepath.Join(DataDir, "users.json")
	GroupsFile             = filepath.Join(DataDir, "groups.json")
	ModeFile               = filepath.Join(DataDir, "mode.json")
	ServersFile            = filepath.Join(DataDir, "servers.json")
	TokensFile             = filepath.Join(DataDir, "tokens.json")
	DockerCfgDir           = filepath.Join(DataDir, "docker")
	InsecureRegistriesFile = filepath.Join(DataDir, "insecure_registries.json")
	KnownHostsFile         = filepath.Join(DataDir, "known_hosts.json")
	SecretFile             = filepath.Join(DataDir, "secret_key")
	CertsDir               = filepath.Join(DataDir, "certs")
	DaemonConfigFile       = env("DOCKER_DAEMON_CONFIG", "/etc/docker/daemon.json")
	SessionTTL             = 7 * 24 * 3600 // seconds
	CookieName             = "dockpilot_session"
	CookieSecure           = os.Getenv("COOKIE_SECURE") != "false"
	// Optional: eigenes TLS statt Reverse Proxy.
	TLSCert = os.Getenv("TLS_CERT")
	TLSKey  = os.Getenv("TLS_KEY")
	// Optional: CA (PEM) für Hub bzw. Agents mit selbst signiertem HTTPS-Zertifikat.
	AgentCAFile = os.Getenv("AGENT_CA_FILE")
)

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// Credentials holds login data.
type Credentials struct {
	User     string `json:"user"`
	Password string `json:"password"`
	Secret   string `json:"secret"`
}

func LoadCreds() (Credentials, error) {
	secret := loadSecret()
	if data, err := os.ReadFile(CredsFile); err == nil {
		var c Credentials
		if err := json.Unmarshal(data, &c); err == nil {
			if c.Secret == "" {
				c.Secret = secret
			}
			return c, nil
		}
	}
	// Keine Standard-Zugangsdaten: Fehlt die Datei, muss die Ersteinrichtung laufen.
	return Credentials{Secret: secret}, nil
}

func SaveCreds(c Credentials) error {
	data, _ := json.MarshalIndent(c, "", "  ")
	return WriteFileAtomic(CredsFile, data, 0600)
}

func randomHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func loadSecret() string {
	insecure := map[string]bool{"changeme": true, "insecure": true, "": true}
	if v := os.Getenv("DASH_SECRET"); v != "" && !insecure[v] {
		return v
	}
	if data, err := os.ReadFile(SecretFile); err == nil {
		return string(data)
	}
	secret := randomHex(32)
	WriteFileAtomic(SecretFile, []byte(secret), 0600)
	return secret
}

// Mode configuration.
type Mode struct {
	Mode       string `json:"mode"` // standalone | hub | agent
	HubURL     string `json:"hub_url,omitempty"`
	AgentToken string `json:"agent_token,omitempty"`
	AgentName  string `json:"agent_name,omitempty"`
	AgentURL   string `json:"agent_url,omitempty"`
}

// Public enthält alles außer dem Agent-Token.
func (m Mode) Public() map[string]string {
	return map[string]string{"mode": m.Mode, "hub_url": m.HubURL, "agent_name": m.AgentName, "agent_url": m.AgentURL}
}

func LoadMode() Mode {
	if data, err := os.ReadFile(ModeFile); err == nil {
		var m Mode
		if json.Unmarshal(data, &m) == nil {
			return m
		}
	}
	return Mode{Mode: "standalone"}
}

func SaveMode(m Mode) error {
	data, _ := json.MarshalIndent(m, "", "  ")
	return WriteFileAtomic(ModeFile, data, 0600)
}

func NeedsSetup() bool {
	if _, err := os.Stat(ModeFile); os.IsNotExist(err) {
		return true
	}
	m := LoadMode()
	if m.Mode == "agent" {
		return m.AgentToken == ""
	}
	if _, err := os.Stat(UsersFile); err == nil {
		return false
	}
	// Altinstallation: credentials.json mit Benutzer wird beim ersten Zugriff migriert.
	c, err := LoadCreds()
	if _, statErr := os.Stat(CredsFile); statErr != nil || err != nil {
		return true
	}
	return c.User == "" || c.Password == ""
}

// Tokens for stack imports.
var tokensMu sync.Mutex

// loadTokens liest tokens.json. Ist die Datei kaputt, gibt es einen Fehler statt
// einer leeren Liste, damit sie beim nächsten Speichern nicht überschrieben wird.
func loadTokens() (map[string]string, error) {
	t := map[string]string{}
	data, err := os.ReadFile(TokensFile)
	if os.IsNotExist(err) {
		return t, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, &t); err != nil {
		return nil, err
	}
	if t == nil {
		t = map[string]string{}
	}
	return t, nil
}

func saveTokens(t map[string]string) error {
	data, _ := json.Marshal(t)
	return WriteFileAtomic(TokensFile, data, 0600)
}

// TokenNames listet die Namen der gespeicherten Import-Tokens, sortiert.
func TokenNames() []string {
	tokensMu.Lock()
	defer tokensMu.Unlock()
	t, _ := loadTokens()
	names := make([]string, 0, len(t))
	for k := range t {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

func TokenValue(name string) (string, bool) {
	tokensMu.Lock()
	defer tokensMu.Unlock()
	t, _ := loadTokens()
	v, ok := t[name]
	return v, ok
}

func SetToken(name, value string) error {
	tokensMu.Lock()
	defer tokensMu.Unlock()
	t, err := loadTokens()
	if err != nil {
		return err
	}
	t[name] = value
	return saveTokens(t)
}

// DeleteToken meldet false, wenn es den Token nicht gab.
func DeleteToken(name string) (bool, error) {
	tokensMu.Lock()
	defer tokensMu.Unlock()
	t, err := loadTokens()
	if err != nil {
		return false, err
	}
	if _, ok := t[name]; !ok {
		return false, nil
	}
	delete(t, name)
	return true, saveTokens(t)
}

// Docker config.json helpers for registry auth (used for stack pulls).
type dockerAuth struct {
	Auth string `json:"auth"`
}

type dockerConfig struct {
	Auths map[string]dockerAuth `json:"auths"`
}

func loadDockerCfg() dockerConfig {
	cfgFile := filepath.Join(DockerCfgDir, "config.json")
	if data, err := os.ReadFile(cfgFile); err == nil {
		var c dockerConfig
		if json.Unmarshal(data, &c) == nil {
			return c
		}
	}
	return dockerConfig{Auths: map[string]dockerAuth{}}
}

// dockerCfgMu schützt das Lesen-Ändern-Schreiben von config.json.
var dockerCfgMu sync.Mutex

func saveDockerCfg(c dockerConfig) error {
	data, _ := json.MarshalIndent(c, "", "  ")
	return WriteFileAtomic(filepath.Join(DockerCfgDir, "config.json"), data, 0600)
}

// DockerCfgRaw returns the raw bytes of the Docker config.json for syncing to agents.
// Returns nil if the file doesn't exist or is empty.
func DockerCfgRaw() []byte {
	data, err := os.ReadFile(filepath.Join(DockerCfgDir, "config.json"))
	if err != nil || len(data) == 0 {
		return nil
	}
	return data
}

// MergeDockerCfg merges incoming docker config.json bytes into the existing local config.
// Writes to both our own credential store and Docker's system default (/root/.docker)
// so credentials are used regardless of DOCKER_CONFIG environment variable support.
func MergeDockerCfg(incoming []byte) error {
	var hub dockerConfig
	if err := json.Unmarshal(incoming, &hub); err != nil {
		return err
	}
	dockerCfgMu.Lock()
	defer dockerCfgMu.Unlock()

	// Our credential store
	existing := loadDockerCfg()
	if existing.Auths == nil {
		existing.Auths = map[string]dockerAuth{}
	}
	for k, v := range hub.Auths {
		existing.Auths[k] = v
	}
	if err := saveDockerCfg(existing); err != nil {
		return err
	}

	// Docker system default — ensures docker CLI and compose find credentials
	// even on Docker versions that don't respect DOCKER_CONFIG env var.
	mergeIntoDir(hub, "/root/.docker")
	return nil
}

// mergeIntoDir merges auth entries into the config.json in the given directory.
func mergeIntoDir(incoming dockerConfig, dir string) {
	cfgFile := filepath.Join(dir, "config.json")
	existing := dockerConfig{Auths: map[string]dockerAuth{}}
	if data, err := os.ReadFile(cfgFile); err == nil {
		json.Unmarshal(data, &existing)
	}
	if existing.Auths == nil {
		existing.Auths = map[string]dockerAuth{}
	}
	for k, v := range incoming.Auths {
		existing.Auths[k] = v
	}
	if data, err := json.MarshalIndent(existing, "", "  "); err == nil {
		if err := WriteFileAtomic(cfgFile, data, 0600); err != nil {
			log.Printf("config: %s schreiben: %v", cfgFile, err)
		}
	}
}

type RegistryEntry struct {
	Registry string `json:"registry"`
	Username string `json:"username"`
}

// RegistryEntries listet die gespeicherten Registry-Logins mit Benutzernamen (ohne Passwort), sortiert.
func RegistryEntries() []RegistryEntry {
	cfg := loadDockerCfg()
	out := make([]RegistryEntry, 0, len(cfg.Auths))
	for k, a := range cfg.Auths {
		user := ""
		if dec, err := base64.StdEncoding.DecodeString(a.Auth); err == nil {
			user, _, _ = strings.Cut(string(dec), ":")
		}
		out = append(out, RegistryEntry{Registry: k, Username: user})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Registry < out[j].Registry })
	return out
}

func RegistryList() []string {
	cfg := loadDockerCfg()
	keys := make([]string, 0, len(cfg.Auths))
	for k := range cfg.Auths {
		keys = append(keys, k)
	}
	return keys
}

// normalizeRegistry strips protocol prefix and trailing slash so the key
// matches what Docker uses internally (e.g. "registry:5000", not "http://registry:5000/").
func normalizeRegistry(registry string) string {
	registry = strings.TrimPrefix(registry, "https://")
	registry = strings.TrimPrefix(registry, "http://")
	registry = strings.TrimRight(registry, "/")
	return registry
}

// WriteAuthToDockercfg writes credentials for the given registry directly into
// the DOCKER_CONFIG store without going through any credential helper.
// registry must be the exact key Docker uses (e.g. "https://index.docker.io/v1/"
// for Docker Hub, or "registry.host:port" for a custom registry).
func WriteAuthToDockercfg(registry, username, password string) error {
	token := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
	dockerCfgMu.Lock()
	defer dockerCfgMu.Unlock()
	cfg := loadDockerCfg()
	if cfg.Auths == nil {
		cfg.Auths = map[string]dockerAuth{}
	}
	cfg.Auths[registry] = dockerAuth{Auth: token}
	return saveDockerCfg(cfg)
}

// EncodeRegistryAuth encodes credentials into the base64 JSON format that the
// Docker SDK expects as image.PullOptions.RegistryAuth.
func EncodeRegistryAuth(serverAddress, username, password string) string {
	type ac struct {
		Username      string `json:"username"`
		Password      string `json:"password"`
		ServerAddress string `json:"serveraddress"`
	}
	data, _ := json.Marshal(ac{Username: username, Password: password, ServerAddress: serverAddress})
	return base64.URLEncoding.EncodeToString(data)
}

// PullAuthForImage returns a Docker SDK RegistryAuth header for the registry
// serving imageRef by looking up credentials in our docker config.json.
// Returns "" if no credentials are found (anonymous pull will be attempted).
func PullAuthForImage(imageRef string) string {
	registry := imageRegistry(imageRef)
	cfg := loadDockerCfg()
	if entry, ok := cfg.Auths[registry]; ok && entry.Auth != "" {
		return authHeaderFromToken(registry, entry.Auth)
	}
	// For Docker Hub, also try normalized variants stored under different keys
	if registry == "https://index.docker.io/v1/" {
		for k, entry := range cfg.Auths {
			if strings.Contains(k, "docker.io") && entry.Auth != "" {
				return authHeaderFromToken(k, entry.Auth)
			}
		}
	}
	return ""
}

// imageRegistry extracts the registry host from an image reference,
// matching the key format used in docker config.json auth entries.
func imageRegistry(ref string) string {
	namepart := ref
	if i := strings.Index(ref, "@"); i >= 0 {
		namepart = ref[:i]
	} else if i := strings.LastIndex(ref, ":"); i > strings.LastIndex(ref, "/") {
		namepart = ref[:i]
	}
	first := strings.SplitN(namepart, "/", 2)[0]
	if strings.ContainsAny(first, ".:") {
		return first
	}
	return "https://index.docker.io/v1/"
}

// authHeaderFromToken converts a stored auth token (base64(user:pass)) into
// the Docker SDK RegistryAuth header format.
func authHeaderFromToken(serverAddress, authToken string) string {
	decoded, err := base64.StdEncoding.DecodeString(authToken)
	if err != nil {
		return ""
	}
	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return ""
	}
	return EncodeRegistryAuth(serverAddress, parts[0], parts[1])
}

func AddRegistry(registry, username, password string) error {
	registry = normalizeRegistry(registry)
	token := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
	dockerCfgMu.Lock()
	defer dockerCfgMu.Unlock()
	cfg := loadDockerCfg()
	if cfg.Auths == nil {
		cfg.Auths = map[string]dockerAuth{}
	}
	cfg.Auths[registry] = dockerAuth{Auth: token}
	return saveDockerCfg(cfg)
}

func RemoveRegistry(registry string) error {
	registry = normalizeRegistry(registry)
	dockerCfgMu.Lock()
	defer dockerCfgMu.Unlock()
	cfg := loadDockerCfg()
	delete(cfg.Auths, registry)
	return saveDockerCfg(cfg)
}

// RegistryCredentials liefert Benutzer und Passwort aus dem Docker-Config-Store
// für die Registry, aus der imageRef stammt.
func RegistryCredentials(imageRef string) (user, pass string, ok bool) {
	entry, found := loadDockerCfg().Auths[imageRegistry(imageRef)]
	if !found || entry.Auth == "" {
		return "", "", false
	}
	decoded, err := base64.StdEncoding.DecodeString(entry.Auth)
	if err != nil {
		return "", "", false
	}
	user, pass, ok = strings.Cut(string(decoded), ":")
	return user, pass, ok
}

// InsecureRegistries returns the list of registries that should be treated as insecure (HTTP).
func InsecureRegistries() []string {
	data, err := os.ReadFile(InsecureRegistriesFile)
	if err != nil {
		return []string{}
	}
	var list []string
	if json.Unmarshal(data, &list) != nil {
		return []string{}
	}
	return list
}

var insecureMu sync.Mutex

func saveInsecureRegistries(list []string) error {
	data, _ := json.Marshal(list)
	return WriteFileAtomic(InsecureRegistriesFile, data, 0600)
}

// SetInsecureRegistries replaces the insecure registry list and applies it to daemon.json.
// Used by agents to accept the hub's full list in one call.
func SetInsecureRegistries(list []string) error {
	for _, r := range list {
		if !ValidRegistryHost(r) {
			return fmt.Errorf("ungültige Registry-Adresse: %q", r)
		}
	}
	insecureMu.Lock()
	defer insecureMu.Unlock()
	if err := saveInsecureRegistries(list); err != nil {
		return err
	}
	return ApplyInsecureRegistries()
}

// AddInsecureRegistry adds a registry to the insecure list and applies it to daemon.json.
func AddInsecureRegistry(registry string) error {
	registry = normalizeRegistry(registry)
	if !ValidRegistryHost(registry) {
		return fmt.Errorf("ungültige Registry-Adresse (erwartet: host oder host:port)")
	}
	insecureMu.Lock()
	defer insecureMu.Unlock()
	list := InsecureRegistries()
	for _, r := range list {
		if r == registry {
			return nil
		}
	}
	list = append(list, registry)
	if err := saveInsecureRegistries(list); err != nil {
		return err
	}
	return ApplyInsecureRegistries()
}

// RemoveInsecureRegistry removes a registry from the insecure list and applies it to daemon.json.
func RemoveInsecureRegistry(registry string) error {
	insecureMu.Lock()
	defer insecureMu.Unlock()
	list := InsecureRegistries()
	var filtered []string
	for _, r := range list {
		if r != registry {
			filtered = append(filtered, r)
		}
	}
	if err := saveInsecureRegistries(filtered); err != nil {
		return err
	}
	return ApplyInsecureRegistries()
}

// ApplyInsecureRegistries writes the current insecure registry list to the Docker daemon.json
// and reloads the daemon via SIGHUP so the change takes effect without a full restart.
func ApplyInsecureRegistries() error {
	list := InsecureRegistries()

	// Read existing daemon.json preserving all other settings.
	raw := map[string]json.RawMessage{}
	if data, err := os.ReadFile(DaemonConfigFile); err == nil {
		json.Unmarshal(data, &raw) // best-effort; ignore parse errors
	}

	// Encode our list and replace the insecure-registries key.
	encoded, _ := json.Marshal(list)
	raw["insecure-registries"] = json.RawMessage(encoded)

	data, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return err
	}
	os.MkdirAll(filepath.Dir(DaemonConfigFile), 0755)
	if err := os.WriteFile(DaemonConfigFile, data, 0644); err != nil {
		return err
	}

	// Send SIGHUP to dockerd to reload config without full restart.
	reloadDockerDaemon()
	return nil
}

// reloadDockerDaemon tries to send SIGHUP to the Docker daemon process so it reloads
// its configuration. Errors are logged but not returned — it's best-effort.
func reloadDockerDaemon() {
	for _, pidFile := range []string{"/var/run/docker.pid", "/run/docker.pid"} {
		data, err := os.ReadFile(pidFile)
		if err != nil {
			continue
		}
		pid := strings.TrimSpace(string(data))
		if pid == "" {
			continue
		}
		if err := exec.Command("kill", "-HUP", pid).Run(); err != nil {
			log.Printf("config: SIGHUP an dockerd (PID %s): %v", pid, err)
		} else {
			log.Printf("config: dockerd (PID %s) neu geladen", pid)
		}
		return
	}
	log.Printf("config: PID-Datei von dockerd nicht gefunden — daemon.json manuell neu laden")
}
