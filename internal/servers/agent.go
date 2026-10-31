package servers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"dockpilot/internal/config"
)

func AgentURL() string {
	if v := os.Getenv("AGENT_URL"); v != "" {
		return strings.TrimRight(v, "/")
	}
	m := config.LoadMode()
	return strings.TrimRight(m.AgentURL, "/")
}

func StartAgentRegistrationLoop() {
	go func() {
		time.Sleep(5 * time.Second)
		for {
			if err := registerWithHub(); err != nil {
				log.Printf("Agent registration failed: %v", err)
			}
			time.Sleep(60 * time.Second)
		}
	}()
}

type RegisterResult struct {
	Online bool
	Error  string
}

// RegisterNow registers once with the hub and returns the result.
func RegisterNow() RegisterResult {
	if err := registerWithHub(); err != nil {
		return RegisterResult{Online: false, Error: err.Error()}
	}
	return RegisterResult{Online: true}
}

func registerWithHub() error {
	m := config.LoadMode()
	if m.Mode != "agent" {
		return nil
	}
	if m.HubURL == "" || m.AgentToken == "" {
		return fmt.Errorf("Hub-URL oder Agent-Token nicht konfiguriert")
	}
	agentURL := AgentURL()
	payload, _ := json.Marshal(map[string]string{
		"name": m.AgentName,
		"url":  agentURL,
	})
	req, err := http.NewRequest("POST", m.HubURL+"/api/agents/register", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+m.AgentToken)
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		var e struct{ Detail string }
		json.NewDecoder(resp.Body).Decode(&e)
		if e.Detail != "" {
			return fmt.Errorf("Hub HTTP %d: %s", resp.StatusCode, e.Detail)
		}
		return fmt.Errorf("Hub HTTP %d", resp.StatusCode)
	}
	return nil
}
