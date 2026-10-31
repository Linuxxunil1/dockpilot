// Package regcerts verwaltet Zertifikate für Registries im Docker-Format:
// <certs.d>/<registry>/ca.crt sowie optional client.cert und client.key (mTLS).
// Der Docker-Daemon liest diese Dateien bei jedem Pull, ein Neustart ist nicht nötig.
package regcerts

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"dockpilot/internal/config"
)

// Dir ist das certs.d-Verzeichnis des Docker-Daemons (neben daemon.json).
var Dir = func() string {
	if v := os.Getenv("DOCKER_CERTS_DIR"); v != "" {
		return v
	}
	return filepath.Join(filepath.Dir(config.DaemonConfigFile), "certs.d")
}()

const (
	caFile     = "ca.crt"
	clientCert = "client.cert"
	clientKey  = "client.key"
)

var nameRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?(:[0-9]{1,5})?$`)

var (
	ErrBadName     = errors.New("Ungültige Registry-Adresse (z. B. registry.example.com oder host:5000)")
	ErrNoDockerDir = errors.New("/etc/docker ist nicht im Container eingebunden – Zertifikate würden vom Docker-Daemon nicht gelesen")
)

type Cert struct {
	Subject     string `json:"subject"`
	Issuer      string `json:"issuer"`
	NotAfter    int64  `json:"not_after"`
	Fingerprint string `json:"fingerprint"`
	IsCA        bool   `json:"is_ca"`
	SelfSigned  bool   `json:"self_signed"`
}

type Entry struct {
	Registry string `json:"registry"`
	CA       []Cert `json:"ca,omitempty"`
	Client   *Cert  `json:"client,omitempty"`
	Error    string `json:"error,omitempty"`
}

func normalize(registry string) (string, error) {
	r := strings.TrimSpace(registry)
	r = strings.TrimPrefix(strings.TrimPrefix(r, "https://"), "http://")
	r = strings.TrimRight(r, "/")
	if !nameRe.MatchString(r) {
		return "", ErrBadName
	}
	return r, nil
}

func info(c *x509.Certificate) Cert {
	sum := sha256.Sum256(c.Raw)
	h := strings.ToUpper(hex.EncodeToString(sum[:]))
	parts := make([]string, 0, 32)
	for i := 0; i < len(h); i += 2 {
		parts = append(parts, h[i:i+2])
	}
	name := func(n string, o []string) string {
		if n != "" {
			return n
		}
		return strings.Join(o, ", ")
	}
	return Cert{
		Subject:     name(c.Subject.CommonName, c.Subject.Organization),
		Issuer:      name(c.Issuer.CommonName, c.Issuer.Organization),
		NotAfter:    c.NotAfter.Unix(),
		Fingerprint: strings.Join(parts, ":"),
		IsCA:        c.IsCA,
		SelfSigned:  c.CheckSignatureFrom(c) == nil,
	}
}

func parsePEM(data []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	for {
		var b *pem.Block
		b, data = pem.Decode(data)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, errors.New("kein Zertifikat im PEM-Format gefunden")
	}
	return out, nil
}

// List liefert alle Registries mit hinterlegten Zertifikaten.
func List() []Entry {
	out := []Entry{}
	dirs, _ := os.ReadDir(Dir)
	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		e := Entry{Registry: d.Name()}
		base := filepath.Join(Dir, d.Name())
		if data, err := os.ReadFile(filepath.Join(base, caFile)); err == nil {
			if cs, err := parsePEM(data); err == nil {
				for _, c := range cs {
					e.CA = append(e.CA, info(c))
				}
			} else {
				e.Error = "ca.crt: " + err.Error()
			}
		}
		if data, err := os.ReadFile(filepath.Join(base, clientCert)); err == nil {
			if cs, err := parsePEM(data); err == nil {
				ci := info(cs[0])
				e.Client = &ci
			}
		}
		if len(e.CA) > 0 || e.Client != nil || e.Error != "" {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Registry < out[j].Registry })
	return out
}

// Save legt CA und/oder Client-Zertifikat für die Registry ab. Leere Teile bleiben unverändert.
func Save(registry, caPEM, certPEM, keyPEM string) error {
	reg, err := normalize(registry)
	if err != nil {
		return err
	}
	caPEM, certPEM, keyPEM = strings.TrimSpace(caPEM), strings.TrimSpace(certPEM), strings.TrimSpace(keyPEM)
	if caPEM == "" && certPEM == "" && keyPEM == "" {
		return errors.New("CA-Zertifikat oder Client-Zertifikat erforderlich")
	}
	if caPEM != "" {
		if _, err := parsePEM([]byte(caPEM)); err != nil {
			return fmt.Errorf("CA-Zertifikat ungültig: %w", err)
		}
	}
	if (certPEM == "") != (keyPEM == "") {
		return errors.New("Client-Zertifikat und privater Schlüssel gehören zusammen")
	}
	if certPEM != "" {
		if _, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM)); err != nil {
			return fmt.Errorf("Client-Zertifikat oder Schlüssel ungültig: %w", err)
		}
	}
	if os.Getenv("DOCKER_CERTS_DIR") == "" {
		if _, err := os.Stat(filepath.Dir(Dir)); err != nil {
			return ErrNoDockerDir
		}
	}
	base := filepath.Join(Dir, reg)
	if err := os.MkdirAll(base, 0755); err != nil {
		return err
	}
	if caPEM != "" {
		if err := os.WriteFile(filepath.Join(base, caFile), []byte(caPEM+"\n"), 0644); err != nil {
			return err
		}
	}
	if certPEM != "" {
		if err := os.WriteFile(filepath.Join(base, clientCert), []byte(certPEM+"\n"), 0644); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(base, clientKey), []byte(keyPEM+"\n"), 0600); err != nil {
			return err
		}
	}
	return nil
}

// Delete entfernt alle Zertifikate der Registry.
func Delete(registry string) error {
	reg, err := normalize(registry)
	if err != nil {
		return err
	}
	base := filepath.Join(Dir, reg)
	if _, err := os.Stat(base); err != nil {
		return errors.New("Keine Zertifikate für diese Registry")
	}
	for _, f := range []string{caFile, clientCert, clientKey} {
		os.Remove(filepath.Join(base, f))
	}
	// Nur das (dann leere) Verzeichnis entfernen, fremde Dateien bleiben erhalten.
	os.Remove(base)
	return nil
}

// Fetched ist das Ergebnis eines Abrufs vom Server.
type Fetched struct {
	PEM     string `json:"pem"`
	Chain   []Cert `json:"chain"`
	Trusted bool   `json:"trusted"` // Kette wird bereits vom System bzw. hinterlegter CA vertraut
}

// Fetch liest die Zertifikatskette direkt vom Server. Vorgeschlagen wird das oberste
// Zertifikat der Kette (bei selbst signierten Servern das Serverzertifikat selbst).
func Fetch(registry string) (Fetched, error) {
	reg, err := normalize(registry)
	if err != nil {
		return Fetched{}, err
	}
	host, port, err := net.SplitHostPort(reg)
	if err != nil {
		host, port = reg, "443"
	}
	// Absichtlich ohne Prüfung: Hier wird das (oft selbst signierte) Zertifikat erst gelesen,
	// damit der Admin es anhand des Fingerprints prüfen und hinterlegen kann. Es werden keine
	// Daten gesendet; ob die Kette schon vertrauenswürdig ist, steht getrennt in Trusted.
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", net.JoinHostPort(host, port),
		&tls.Config{ServerName: host, InsecureSkipVerify: true})
	if err != nil {
		return Fetched{}, fmt.Errorf("Verbindung zu %s fehlgeschlagen: %w", net.JoinHostPort(host, port), err)
	}
	defer conn.Close()
	peers := conn.ConnectionState().PeerCertificates
	if len(peers) == 0 {
		return Fetched{}, errors.New("Server liefert kein Zertifikat")
	}
	f := Fetched{}
	for _, c := range peers {
		f.Chain = append(f.Chain, info(c))
	}
	top := peers[len(peers)-1]
	f.PEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: top.Raw}))
	inter := x509.NewCertPool()
	for _, c := range peers[1:] {
		inter.AddCert(c)
	}
	_, verr := peers[0].Verify(x509.VerifyOptions{DNSName: host, Roots: Pool(reg), Intermediates: inter})
	f.Trusted = verr == nil
	return f, nil
}

// Pool liefert die System-CAs plus die für registry hinterlegte CA.
func Pool(registry string) *x509.CertPool {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if data, err := os.ReadFile(filepath.Join(Dir, registry, caFile)); err == nil {
		pool.AppendCertsFromPEM(data)
	}
	return pool
}

// ClientCertificates liefert ein hinterlegtes Client-Zertifikat für mTLS.
func ClientCertificates(registry string) []tls.Certificate {
	base := filepath.Join(Dir, registry)
	pair, err := tls.LoadX509KeyPair(filepath.Join(base, clientCert), filepath.Join(base, clientKey))
	if err != nil {
		return nil
	}
	return []tls.Certificate{pair}
}

// SyncEntry überträgt die Dateien einer Registry vom Hub zum Agent.
type SyncEntry struct {
	Registry   string `json:"registry"`
	CA         string `json:"ca,omitempty"`
	ClientCert string `json:"client_cert,omitempty"`
	ClientKey  string `json:"client_key,omitempty"`
}

func Export() []SyncEntry {
	var out []SyncEntry
	for _, e := range List() {
		base := filepath.Join(Dir, e.Registry)
		ca, _ := os.ReadFile(filepath.Join(base, caFile))
		cc, _ := os.ReadFile(filepath.Join(base, clientCert))
		ck, _ := os.ReadFile(filepath.Join(base, clientKey))
		out = append(out, SyncEntry{Registry: e.Registry, CA: string(ca), ClientCert: string(cc), ClientKey: string(ck)})
	}
	return out
}

// Import schreibt die vom Hub übertragenen Zertifikate. Andere Registries bleiben unberührt.
func Import(list []SyncEntry) error {
	var errs []string
	for _, e := range list {
		if err := Save(e.Registry, e.CA, e.ClientCert, e.ClientKey); err != nil {
			errs = append(errs, e.Registry+": "+err.Error())
		}
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}
