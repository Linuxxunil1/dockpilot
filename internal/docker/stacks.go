package docker

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"dockpilot/internal/config"
)

type StackInfo struct {
	Name string `json:"name"`
	Dir  string `json:"dir"`
}

var safeStackName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$`)

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
	cf := filepath.Join(StackDir(name), "docker-compose.yaml")
	data, err := os.ReadFile(cf)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func WriteStackFile(name, content string) error {
	d := StackDir(name)
	os.MkdirAll(d, 0755)
	return os.WriteFile(filepath.Join(d, "docker-compose.yaml"), []byte(content), 0644)
}

func DeleteStack(name string) error {
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

// ImportStack downloads a docker-compose.yaml from rawURL and saves it as a new stack.
// token is an optional Bearer token value (not a name).
func ImportStack(name, rawURL, token string) error {
	if !safeStackName.MatchString(name) {
		return fmt.Errorf("invalid stack name")
	}
	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "dockpilot/2.0")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 5<<20))
	if err != nil {
		return err
	}
	return WriteStackFile(name, string(data))
}
