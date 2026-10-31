package main

import (
	"log"
	"os"
	"time"

	"dockpilot/internal/config"
	"dockpilot/internal/docker"
	"dockpilot/internal/release"
	"dockpilot/internal/servers"
	"dockpilot/internal/web"
)

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)

	// ── Docker client ────────────────────────────────────────────────
	if err := docker.Init(); err != nil {
		log.Fatalf("Docker-Client: %v", err)
	}

	// ── Mode-dependent behaviour ─────────────────────────────────────
	m := config.LoadMode()
	if m.Mode == "agent" {
		servers.StartAgentRegistrationLoop()
	}
	release.Start(time.Hour)

	// ── HTTP server ──────────────────────────────────────────────────
	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	web.Start(addr)
}
