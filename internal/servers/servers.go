package servers

import (
	"encoding/json"
	"os"
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
	Passphrase string   `json:"passphrase,omitempty"`
	SSHCert    string   `json:"ssh_cert,omitempty"`
	Token      string   `json:"token,omitempty"`
	URL        string   `json:"url,omitempty"`
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
	if s.LastSeen != nil {
		m["last_seen"] = s.LastSeen
	}
	return m
}

func Load() []Server {
	data, err := os.ReadFile(config.ServersFile)
	if err != nil {
		return nil
	}
	var list []Server
	json.Unmarshal(data, &list)
	return list
}

func Save(list []Server) error {
	os.MkdirAll(config.DataDir, 0700)
	data, _ := json.MarshalIndent(list, "", "  ")
	return os.WriteFile(config.ServersFile, data, 0600)
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
	list := Load()
	list = append(list, s)
	return Save(list)
}

func Update(id string, fn func(*Server)) error {
	list := Load()
	for i := range list {
		if list[i].ID == id {
			fn(&list[i])
			return Save(list)
		}
	}
	return nil
}

func Delete(id string) error {
	list := Load()
	newList := list[:0]
	for _, s := range list {
		if s.ID != id {
			newList = append(newList, s)
		}
	}
	return Save(newList)
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
