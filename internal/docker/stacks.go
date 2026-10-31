package docker

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"syscall"
	"time"

	"dockpilot/internal/config"
)

type StackInfo struct {
	Name string `json:"name"`
	Dir  string `json:"dir"`
}

var safeStackName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$`)

var errBadStackName = errors.New("Ungültiger Stack-Name")

// ValidStackName lässt nur Namen zu, die weder Pfade noch URL-Sonderzeichen enthalten.
func ValidStackName(name string) bool { return safeStackName.MatchString(name) }

func StackDir(name string) string {
	return filepath.Join(config.StacksDir, name)
}

func ListStacks() ([]StackInfo, error) {
	os.MkdirAll(config.StacksDir, 0755)
	entries, err := os.ReadDir(config.StacksDir)
	if err != nil {
		return nil, err
	}
	result := []StackInfo{}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		cf := filepath.Join(config.StacksDir, e.Name(), "docker-compose.yaml")
		if _, err := os.Stat(cf); err == nil {
			result = append(result, StackInfo{
				Name: e.Name(),
				Dir:  filepath.Join(config.StacksDir, e.Name()),
			})
		}
	}
	return result, nil
}

func ReadStackFile(name string) (string, error) {
	if !ValidStackName(name) {
		return "", errBadStackName
	}
	cf := filepath.Join(StackDir(name), "docker-compose.yaml")
	data, err := os.ReadFile(cf)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func WriteStackFile(name, content string) error {
	if !ValidStackName(name) {
		return errBadStackName
	}
	d := StackDir(name)
	// Compose-Dateien enthalten oft Passwörter, deshalb nur für root lesbar.
	os.MkdirAll(d, 0700)
	return os.WriteFile(filepath.Join(d, "docker-compose.yaml"), []byte(content), 0600)
}

func DeleteStack(name string) error {
	if !ValidStackName(name) {
		return errBadStackName
	}
	d := StackDir(name)
	if _, err := os.Stat(d); os.IsNotExist(err) {
		return fmt.Errorf("stack not found")
	}
	return os.RemoveAll(d)
}

type ComposeResult struct {
	OK  bool   `json:"ok"`
	Out string `json:"out"`
}

func RunCompose(name string, timeout time.Duration, args ...string) ComposeResult {
	if !ValidStackName(name) {
		return ComposeResult{OK: false, Out: errBadStackName.Error()}
	}
	dir := StackDir(name)
	cf := filepath.Join(dir, "docker-compose.yaml")
	cmdArgs := append([]string{"compose", "-f", cf}, args...)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Pass DOCKER_CONFIG so compose picks up stored registry credentials.
	dockerCfg := config.DockerCfgDir
	cfgFile := filepath.Join(dockerCfg, "config.json")
	if _, err := os.Stat(cfgFile); err != nil {
		log.Printf("compose[%s]: WARNUNG — %s nicht gefunden, keine Registry-Credentials", name, cfgFile)
	} else {
		log.Printf("compose[%s]: DOCKER_CONFIG=%s (config.json vorhanden)", name, dockerCfg)
	}

	var buf bytes.Buffer
	cmd := execCommand(ctx, "docker", cmdArgs...)
	cmd.Dir = dir
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	cmd.Env = append(os.Environ(), "DOCKER_CONFIG="+dockerCfg)

	err := cmd.Run()
	out := buf.String()
	if len(out) > 50000 {
		out = out[len(out)-50000:]
	}
	return ComposeResult{OK: err == nil, Out: out}
}

// FetchStack lädt eine Compose-Datei per http(s). token ist optional (Bearer-Wert, kein Name)
// und wird nur über HTTPS gesendet. Ziele auf localhost, Link-Local (z. B. Cloud-Metadaten)
// und Multicast sind immer gesperrt, private Netze nur mit allowPrivate (Admins).
// Die Prüfung läuft auf die aufgelöste IP, also auch nach Weiterleitungen und DNS-Tricks.
func FetchStack(rawURL, token string, allowPrivate bool) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", errors.New("URL muss mit http:// oder https:// beginnen")
	}
	if token != "" && u.Scheme != "https" {
		return "", errors.New("Tokens werden nur über https:// gesendet")
	}
	dialer := &net.Dialer{
		Timeout: 10 * time.Second,
		Control: func(_, address string, _ syscall.RawConn) error {
			return checkImportTarget(address, allowPrivate)
		},
	}
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			DialContext:         dialer.DialContext,
			TLSHandshakeTimeout: 10 * time.Second,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("zu viele Weiterleitungen")
			}
			if req.URL.Scheme != "https" && (token != "" || req.URL.Scheme != "http") {
				return errors.New("Weiterleitung auf unsicheres Ziel abgelehnt")
			}
			return nil
		},
	}
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "dockpilot/2.0")
	if token != "" {
		// Go entfernt Authorization bei Weiterleitungen auf einen anderen Host selbst.
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 5<<20))
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func checkImportTarget(address string, allowPrivate bool) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("ungültige Zieladresse %s", host)
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() || reservedNet(ip) {
		return fmt.Errorf("Ziel %s ist für Importe gesperrt", ip)
	}
	if (ip.IsPrivate() || internalNet(ip)) && !allowPrivate {
		return fmt.Errorf("Import aus dem internen Netz (%s) nur für Admins", ip)
	}
	return nil
}

func mustCIDRs(list ...string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(list))
	for _, c := range list {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			panic(err)
		}
		out = append(out, n)
	}
	return out
}

var (
	// Nie ein sinnvolles Importziel: IETF-Protokoll, Benchmark, Broadcast, Doku-Netze.
	reservedNets = mustCIDRs("192.0.0.0/24", "198.18.0.0/15", "255.255.255.255/32",
		"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")
	// Wie private Netze behandeln: CGNAT (z. B. Tailscale) und NAT64.
	internalNets = mustCIDRs("100.64.0.0/10", "64:ff9b::/96", "64:ff9b:1::/48")
)

func inNets(ip net.IP, nets []*net.IPNet) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func reservedNet(ip net.IP) bool { return inNets(ip, reservedNets) }
func internalNet(ip net.IP) bool { return inNets(ip, internalNets) }
