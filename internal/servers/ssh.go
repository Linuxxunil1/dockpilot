package servers

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"dockpilot/internal/config"
)

// Connect opens an SSH connection to a server. Caller must close.
func Connect(s *Server) (*ssh.Client, error) {
	authMethods, err := authMethod(s)
	if err != nil {
		return nil, err
	}
	cfg := &ssh.ClientConfig{
		User:            s.Username,
		Auth:            authMethods,
		HostKeyCallback: tofuCallback(s.ID),
		Timeout:         10 * time.Second,
	}
	host := fmt.Sprintf("%s:%d", s.Host, port(s.Port))
	return ssh.Dial("tcp", host, cfg)
}

func TestConnection(s *Server) error {
	client, err := Connect(s)
	if err != nil {
		return err
	}
	client.Close()
	return nil
}

func port(p int) int {
	if p == 0 {
		return 22
	}
	return p
}

func authMethod(s *Server) ([]ssh.AuthMethod, error) {
	if s.AuthType == "password" {
		return []ssh.AuthMethod{ssh.Password(s.Password)}, nil
	}
	if s.SSHKey == "" {
		return nil, fmt.Errorf("kein SSH-Key konfiguriert")
	}
	signer, err := parsePrivateKey([]byte(s.SSHKey), s.Passphrase)
	if err != nil {
		return nil, fmt.Errorf("SSH-Key ungültig: %w", err)
	}
	if s.SSHCert != "" {
		signer, err = certSigner(signer, s.SSHCert)
		if err != nil {
			return nil, fmt.Errorf("SSH-Zertifikat ungültig: %w", err)
		}
	}
	return []ssh.AuthMethod{ssh.PublicKeys(signer)}, nil
}

func parsePrivateKey(pemData []byte, passphrase string) (ssh.Signer, error) {
	if passphrase != "" {
		return ssh.ParsePrivateKeyWithPassphrase(pemData, []byte(passphrase))
	}
	return ssh.ParsePrivateKey(pemData)
}

// certSigner kombiniert den privaten Schlüssel mit einem OpenSSH-Zertifikat im authorized_keys-Format.
func certSigner(signer ssh.Signer, certData string) (ssh.Signer, error) {
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(certData))
	if err != nil {
		return nil, err
	}
	cert, ok := pub.(*ssh.Certificate)
	if !ok {
		return nil, fmt.Errorf("kein OpenSSH-Zertifikat")
	}
	return ssh.NewCertSigner(cert, signer)
}

// ValidateAuth prüft die hinterlegten Zugangsdaten, ohne eine Verbindung aufzubauen.
func ValidateAuth(s *Server) error {
	_, err := authMethod(s)
	return err
}

// TOFU (trust-on-first-use) host key verification.
var knownMu sync.Mutex

type knownHosts map[string]string // "host:port" -> base64 key

func loadKnownHosts() knownHosts {
	data, err := os.ReadFile(config.KnownHostsFile)
	if err != nil {
		return knownHosts{}
	}
	var kh knownHosts
	json.Unmarshal(data, &kh)
	if kh == nil {
		return knownHosts{}
	}
	return kh
}

func saveKnownHosts(kh knownHosts) {
	os.MkdirAll(config.DataDir, 0700)
	data, _ := json.Marshal(kh)
	os.WriteFile(config.KnownHostsFile, data, 0600)
}

func tofuCallback(serverID string) ssh.HostKeyCallback {
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		knownMu.Lock()
		defer knownMu.Unlock()
		kh := loadKnownHosts()
		fingerprint := ssh.FingerprintSHA256(key)
		if existing, ok := kh[serverID]; ok {
			if existing != fingerprint {
				return fmt.Errorf("host key geändert: %s", fingerprint)
			}
			return nil
		}
		kh[serverID] = fingerprint
		saveKnownHosts(kh)
		return nil
	}
}

func ResetKnownHost(serverID string) {
	knownMu.Lock()
	defer knownMu.Unlock()
	kh := loadKnownHosts()
	delete(kh, serverID)
	saveKnownHosts(kh)
}
