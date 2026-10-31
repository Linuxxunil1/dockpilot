package servers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
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

// StartAgentRegistrationLoop läuft immer. Im Agent-Modus meldet er sich alle 60 s beim Hub,
// sonst tut er nichts. So greift ein erst über die Oberfläche eingerichteter Agent ohne Neustart.
func StartAgentRegistrationLoop() {
	go func() {
		time.Sleep(5 * time.Second)
		for {
			if config.LoadMode().Mode == "agent" {
				if res := RegisterNow(); res.Error != "" {
					log.Printf("Agent registration failed: %s", res.Error)
				}
			}
			time.Sleep(60 * time.Second)
		}
	}()
}

type RegisterResult struct {
	Online bool
	Error  string
}

var (
	statusMu   sync.Mutex
	lastStatus RegisterResult
	lastCheck  time.Time
)

// RegisterNow registers once with the hub and returns the result.
func RegisterNow() RegisterResult {
	res := RegisterResult{Online: true}
	if err := registerWithHub(); err != nil {
		res = RegisterResult{Online: false, Error: err.Error()}
	}
	statusMu.Lock()
	lastStatus, lastCheck = res, time.Now()
	statusMu.Unlock()
	return res
}

// Status liefert das letzte Ergebnis. Ist es älter als 15 s, wird neu geprüft –
// so löst die (öffentliche) Statusseite höchstens alle 15 s eine Anfrage an den Hub aus.
func Status() RegisterResult {
	statusMu.Lock()
	fresh := time.Since(lastCheck) < 15*time.Second
	res := lastStatus
	if !fresh {
		lastCheck = time.Now() // parallele Aufrufe warten nicht, sondern sehen den alten Stand
	}
	statusMu.Unlock()
	if fresh {
		return res
	}
	return RegisterNow()
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
	client := &http.Client{Timeout: 10 * time.Second, Transport: agentTransport}
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
