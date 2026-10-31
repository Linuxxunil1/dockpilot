package servers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
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

	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 502, fmt.Errorf("agent nicht erreichbar: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return data, resp.StatusCode, nil
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
