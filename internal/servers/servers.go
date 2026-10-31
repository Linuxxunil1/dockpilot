package servers

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"dockpilot/internal/config"
)

type Server struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Type     string `json:"type"` // "ssh" | "agent"
	Host     string `json:"host,omitempty"`
	Port     int    `json:"port,omitempty"`
	Username string `json:"username,omitempty"`
	AuthType string `json:"auth_type,omitempty"` // "password" | "key"
	Password string `json:"password,omitempty"`
	SSHKey   string `json:"ssh_key,omitempty"`
	// Optional: Passphrase des privaten Schlüssels und OpenSSH-Zertifikat (*-cert.pub).
	Passphrase string `json:"passphrase,omitempty"`
	SSHCert    string `json:"ssh_cert,omitempty"`
	Token      string `json:"token,omitempty"`
	URL        string `json:"url,omitempty"`
	// PendingURL: Der Agent meldet eine neue URL. Sie gilt erst, wenn ein Admin sie bestätigt.
	PendingURL string   `json:"pending_url,omitempty"`
	LastSeen   *float64 `json:"last_seen,omitempty"` // float64 handles both Python (float) and Go (int) timestamps
}

func (s Server) Safe() map[string]interface{} {
	m := map[string]interface{}{
		"id":   s.ID,
		"name": s.Name,
		"type": s.Type,
	}
	if s.Host != "" {
		m["host"] = s.Host
	}
	if s.Port != 0 {
		m["port"] = s.Port
	}
	if s.Username != "" {
		m["username"] = s.Username
	}
	if s.AuthType != "" {
		m["auth_type"] = s.AuthType
	}
	if s.SSHCert != "" {
		m["has_cert"] = true
	}
	if s.URL != "" {
		m["url"] = s.URL
	}
	if s.PendingURL != "" {
		m["pending_url"] = s.PendingURL
	}
	if s.LastSeen != nil {
		m["last_seen"] = s.LastSeen
	}
	return m
}

// mu schützt das Lesen-Ändern-Schreiben von servers.json (Admin-Änderungen und
// Agent-Registrierungen alle 60 s laufen gleichzeitig).
var mu sync.Mutex

// load liest servers.json. Eine unlesbare Datei ergibt einen Fehler statt einer
// leeren Liste, damit sie beim nächsten Speichern nicht überschrieben wird.
func load() ([]Server, error) {
	data, err := os.ReadFile(config.ServersFile)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var list []Server
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, fmt.Errorf("servers.json unlesbar: %w", err)
	}
	return list, nil
}

func save(list []Server) error {
	data, _ := json.MarshalIndent(list, "", "  ")
	return config.WriteFileAtomic(config.ServersFile, data, 0600)
}

func Load() []Server {
	mu.Lock()
	defer mu.Unlock()
	list, _ := load()
	return list
}

func Get(id string) *Server {
	for _, s := range Load() {
		if s.ID == id {
			cp := s
			return &cp
		}
	}
	return nil
}

func Add(s Server) error {
	mu.Lock()
	defer mu.Unlock()
	list, err := load()
	if err != nil {
		return err
	}
	return save(append(list, s))
}

func Update(id string, fn func(*Server)) error {
	mu.Lock()
	defer mu.Unlock()
	list, err := load()
	if err != nil {
		return err
	}
	for i := range list {
		if list[i].ID == id {
			fn(&list[i])
			return save(list)
		}
	}
	return fmt.Errorf("server nicht gefunden")
}

func Delete(id string) error {
	mu.Lock()
	defer mu.Unlock()
	list, err := load()
	if err != nil {
		return err
	}
	newList := list[:0]
	for _, s := range list {
		if s.ID != id {
			newList = append(newList, s)
		}
	}
	if len(newList) == len(list) {
		return fmt.Errorf("server nicht gefunden")
	}
	return save(newList)
}

func TouchLastSeen(id string) {
	now := float64(time.Now().Unix())
	Update(id, func(s *Server) {
		s.LastSeen = &now
	})
}

// AgentServers returns only connected agent-type servers.
func AgentServers() []Server {
	var result []Server
	for _, s := range Load() {
		if s.Type == "agent" && s.URL != "" {
			result = append(result, s)
		}
	}
	return result
}
