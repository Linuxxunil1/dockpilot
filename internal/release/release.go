// Package release prüft, ob in der Registry des eigenen Images eine neuere
// DockPilot-Version liegt. Die CI taggt jedes Release mit seiner Version (z. B. 0.3.0).
package release

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/moby/moby/client"

	"dockpilot/internal/config"
	"dockpilot/internal/docker"
	"dockpilot/internal/regcerts"
	"dockpilot/internal/version"
)

type Status struct {
	Latest          string `json:"latest,omitempty"`
	UpdateAvailable bool   `json:"update_available"`
	CheckedAt       int64  `json:"checked_at,omitempty"`
	Error           string `json:"error,omitempty"`
	Image           string `json:"image,omitempty"`
	Checking        bool   `json:"checking,omitempty"`
}

var (
	mu      sync.RWMutex
	status  Status
	checkMu sync.Mutex // verhindert parallele Prüfungen
)

func Current() Status {
	mu.RLock()
	defer mu.RUnlock()
	return status
}

// Start prüft kurz nach dem Start und danach im angegebenen Intervall.
func Start(interval time.Duration) {
	go func() {
		time.Sleep(20 * time.Second)
		for {
			check()
			time.Sleep(interval)
		}
	}()
}

// CheckNow prüft sofort und liefert das Ergebnis. Läuft schon eine Prüfung,
// wird auf sie gewartet statt eine zweite zu starten.
func CheckNow() Status {
	check()
	return Current()
}

// CheckSoon stößt eine Prüfung im Hintergrund an, z. B. nach geänderten Zugangsdaten.
func CheckSoon() { go check() }

func check() {
	checkMu.Lock()
	defer checkMu.Unlock()
	mu.Lock()
	status.Checking = true
	mu.Unlock()

	image, latest, err := latestVersion()
	st := Status{CheckedAt: time.Now().Unix(), Image: image}
	if err != nil {
		st.Error = err.Error()
		log.Printf("release: Versionsprüfung: %v", err)
	} else {
		st.Latest = latest
		st.UpdateAvailable = Newer(latest, version.Version)
	}
	mu.Lock()
	status = st
	mu.Unlock()
}

var semverRe = regexp.MustCompile(`^v?(\d+)\.(\d+)\.(\d+)$`)

func parse(v string) ([3]int, bool) {
	m := semverRe.FindStringSubmatch(strings.TrimSpace(v))
	if m == nil {
		return [3]int{}, false
	}
	var out [3]int
	for i := range out {
		out[i], _ = strconv.Atoi(m[i+1])
	}
	return out, true
}

// Newer meldet, ob a eine höhere Version als b ist. Nicht-Versionen (z. B. "dev") sind nie neuer.
func Newer(a, b string) bool {
	va, okA := parse(a)
	vb, okB := parse(b)
	if !okA || !okB {
		return false
	}
	for i := range va {
		if va[i] != vb[i] {
			return va[i] > vb[i]
		}
	}
	return false
}

// selfImage liefert die Image-Referenz des eigenen Containers (oder DOCKPILOT_IMAGE).
func selfImage() (string, error) {
	if v := os.Getenv("DOCKPILOT_IMAGE"); v != "" {
		return v, nil
	}
	id := docker.SelfContainerID()
	if id == "" {
		id, _ = os.Hostname()
	}
	r, err := docker.CLI.ContainerInspect(context.Background(), id, client.ContainerInspectOptions{})
	if err != nil {
		return "", fmt.Errorf("eigener Container nicht gefunden: %w", err)
	}
	return r.Container.Config.Image, nil
}

// splitRef zerlegt "host/pfad/name:tag" in Registry-Host und Repository.
func splitRef(ref string) (host, repo string) {
	if i := strings.Index(ref, "@"); i >= 0 {
		ref = ref[:i]
	}
	if i := strings.LastIndex(ref, ":"); i > strings.LastIndex(ref, "/") {
		ref = ref[:i]
	}
	first, rest, found := strings.Cut(ref, "/")
	if found && strings.ContainsAny(first, ".:") {
		return first, rest
	}
	if !strings.Contains(ref, "/") {
		ref = "library/" + ref
	}
	return "registry-1.docker.io", ref
}

func latestVersion() (ref, latest string, err error) {
	ref, err = selfImage()
	if err != nil {
		return "", "", err
	}
	host, repo := splitRef(ref)
	tags, err := listTags(ref, host, repo)
	if err != nil {
		return ref, "", err
	}
	best := ""
	for _, t := range tags {
		if _, ok := parse(t); ok && (best == "" || Newer(t, best)) {
			best = t
		}
	}
	if best == "" {
		return ref, "", errors.New("keine Versions-Tags (z. B. 0.5.0) in der Registry gefunden")
	}
	return ref, strings.TrimPrefix(best, "v"), nil
}

func insecure(host string) bool {
	for _, r := range config.InsecureRegistries() {
		r = strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(r, "https://"), "http://"), "/")
		if r == host {
			return true
		}
	}
	return false
}

func listTags(ref, host, repo string) ([]string, error) {
	// Hinterlegte Registry-CA und Client-Zertifikat (certs.d) verwenden wie der Docker-Daemon.
	// Als HTTP-Registry eingetragene Registries haben oft selbst signierte Zertifikate; nur für
	// diese ist die Prüfung abgeschaltet (wie bei dockerd mit insecure-registries).
	skipVerify := insecure(host)
	tlsCfg := &tls.Config{RootCAs: regcerts.Pool(host), Certificates: regcerts.ClientCertificates(host), InsecureSkipVerify: skipVerify}
	client := &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsCfg}}
	tagsURL := "https://" + host + "/v2/" + repo + "/tags/list?n=1000"
	user, pass, hasCreds := config.RegistryCredentials(ref)
	// Zugangsdaten nur über geprüftes HTTPS: Bei abgeschalteter Prüfung oder HTTP
	// könnte sie jeder im Netz mitlesen oder mit einer gefälschten Antwort abfragen.
	if skipVerify {
		hasCreds = false
	}

	resp, err := client.Get(tagsURL)
	if err != nil && insecure(host) {
		tagsURL = "http://" + host + "/v2/" + repo + "/tags/list?n=1000"
		resp, err = client.Get(tagsURL)
	}
	if err != nil {
		var certErr *tls.CertificateVerificationError
		if errors.As(err, &certErr) {
			return nil, fmt.Errorf("Zertifikat von %s nicht vertrauenswürdig – unter Einstellungen → Zertifikate die CA hinterlegen", host)
		}
		return nil, fmt.Errorf("Registry nicht erreichbar: %w", err)
	}
	if resp.StatusCode == http.StatusUnauthorized {
		challenge := resp.Header.Get("WWW-Authenticate")
		resp.Body.Close()
		req, _ := http.NewRequest("GET", tagsURL, nil)
		switch {
		case strings.HasPrefix(challenge, "Bearer "):
			token, err := fetchToken(client, challenge, repo, user, pass, hasCreds)
			if err != nil {
				return nil, err
			}
			req.Header.Set("Authorization", "Bearer "+token)
		case hasCreds:
			req.SetBasicAuth(user, pass)
		}
		if resp, err = client.Do(req); err != nil {
			return nil, fmt.Errorf("Registry nicht erreichbar: %w", err)
		}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusUnauthorized && !hasCreds {
			return nil, fmt.Errorf("Registry %s verlangt Anmeldung – Zugangsdaten unter Einstellungen → Registries hinterlegen", host)
		}
		return nil, fmt.Errorf("Registry antwortet mit HTTP %d", resp.StatusCode)
	}
	var body struct {
		Tags []string `json:"tags"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&body); err != nil {
		return nil, fmt.Errorf("Tag-Liste unlesbar: %w", err)
	}
	return body.Tags, nil
}

var challengeRe = regexp.MustCompile(`(\w+)="([^"]*)"`)

// fetchToken holt ein Pull-Token beim Token-Dienst aus der Bearer-Challenge der Registry.
func fetchToken(client *http.Client, challenge, repo, user, pass string, hasCreds bool) (string, error) {
	params := map[string]string{}
	for _, m := range challengeRe.FindAllStringSubmatch(challenge, -1) {
		params[m[1]] = m[2]
	}
	if params["realm"] == "" {
		return "", errors.New("Registry liefert keinen Token-Dienst")
	}
	q := url.Values{}
	if params["service"] != "" {
		q.Set("service", params["service"])
	}
	q.Set("scope", "repository:"+repo+":pull")
	// Der Token-Dienst steht in der Antwort der Registry; Zugangsdaten nur an HTTPS-Adressen.
	if !strings.HasPrefix(params["realm"], "https://") {
		hasCreds = false
	}
	req, err := http.NewRequest("GET", params["realm"]+"?"+q.Encode(), nil)
	if err != nil {
		return "", err
	}
	if hasCreds {
		req.SetBasicAuth(user, pass)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("Token-Dienst %s nicht erreichbar (DNS/Netz im Container prüfen): %w", params["realm"], err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		if !hasCreds {
			return "", errors.New("Registry verlangt Anmeldung – Zugangsdaten unter Einstellungen → Registries hinterlegen")
		}
		return "", fmt.Errorf("Anmeldung an der Registry fehlgeschlagen (HTTP %d)", resp.StatusCode)
	}
	var tok struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&tok)
	if tok.Token == "" {
		tok.Token = tok.AccessToken
	}
	if tok.Token == "" {
		return "", errors.New("Token-Dienst liefert kein Token")
	}
	return tok.Token, nil
}
