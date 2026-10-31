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
	servers.StartAgentRegistrationLoop() // tut nur im Agent-Modus etwas
	release.Start(time.Hour)

	if config.NeedsSetup() {
		log.Printf("Ersteinrichtung: Setup-Code %s (im Browser unter /setup eingeben)", config.SetupToken())
	}

	// ── HTTP server ──────────────────────────────────────────────────
	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	web.Start(addr)
}
