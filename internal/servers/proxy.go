package servers

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"dockpilot/internal/config"
)

// AgentDo proxies a request from hub to an agent server.
func AgentDo(s *Server, method, path string, body interface{}, timeout time.Duration) ([]byte, int, error) {
	if s.URL == "" {
		return nil, 503, fmt.Errorf("agent URL nicht bekannt")
	}
	url := s.URL + path

	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, 500, err
		}
		bodyReader = bytes.NewReader(data)
	}

	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		return nil, 500, err
	}
	req.Header.Set("Authorization", "Bearer "+s.Token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	client := &http.Client{Timeout: timeout, Transport: agentTransport}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 502, fmt.Errorf("agent nicht erreichbar: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxAgentResponse+1))
	if err != nil {
		return nil, 502, fmt.Errorf("agent-antwort unvollständig: %w", err)
	}
	if len(data) > maxAgentResponse {
		return nil, 502, fmt.Errorf("agent-antwort zu groß")
	}
	return data, resp.StatusCode, nil
}

// maxAgentResponse schützt den Hub vor übergroßen Antworten eines Agents.
const maxAgentResponse = 32 << 20

var agentTransport = &http.Transport{
	Proxy:               http.ProxyFromEnvironment,
	TLSClientConfig:     AgentTLSConfig(),
	TLSHandshakeTimeout: 10 * time.Second,
	IdleConnTimeout:     90 * time.Second,
}

// AgentTLSConfig vertraut den System-CAs und zusätzlich AGENT_CA_FILE
// (für Hub bzw. Agents mit selbst signiertem HTTPS-Zertifikat).
func AgentTLSConfig() *tls.Config {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if config.AgentCAFile == "" {
		return cfg
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	pem, err := os.ReadFile(config.AgentCAFile)
	if err != nil || !pool.AppendCertsFromPEM(pem) {
		log.Printf("AGENT_CA_FILE %s nicht lesbar oder ohne Zertifikat – nur System-CAs", config.AgentCAFile)
		return cfg
	}
	cfg.RootCAs = pool
	return cfg
}

// AgentJSON proxies and decodes JSON response.
func AgentJSON(s *Server, method, path string, body interface{}, timeout time.Duration) (json.RawMessage, error) {
	data, code, err := AgentDo(s, method, path, body, timeout)
	if err != nil {
		return nil, err
	}
	if code >= 400 {
		var e struct{ Detail string }
		json.Unmarshal(data, &e)
		if e.Detail != "" {
			return nil, fmt.Errorf("agent: %s", e.Detail)
		}
		return nil, fmt.Errorf("agent HTTP %d", code)
	}
	return json.RawMessage(data), nil
}

func AgentGet(s *Server, path string) (json.RawMessage, error) {
	return AgentJSON(s, "GET", path, nil, 10*time.Second)
}

func AgentPost(s *Server, path string, body interface{}, timeout time.Duration) (json.RawMessage, error) {
	return AgentJSON(s, "POST", path, body, timeout)
}

func AgentPut(s *Server, path string, body interface{}) (json.RawMessage, error) {
	return AgentJSON(s, "PUT", path, body, 30*time.Second)
}

func AgentDelete(s *Server, path string) (json.RawMessage, error) {
	return AgentJSON(s, "DELETE", path, nil, 30*time.Second)
}
