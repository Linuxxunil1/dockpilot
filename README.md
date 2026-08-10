# dockpilot

Schlankes Docker-Management-Dashboard (FastAPI + Docker SDK) — Container-Übersicht,
Live-Stats, Start/Stop/Restart/Update, Compose-Stack-Verwaltung, Remote-Server per SSH
und ein integriertes Web-Terminal.

## Deployment

**1. `docker-compose.yaml` anlegen**

Inhalt kopieren und als `docker-compose.yaml` speichern:

```yaml
services:
  dockpilot:
    image: ghcr.io/linuxxunil1/dockpilot:latest
    container_name: dockpilot
    restart: unless-stopped
    security_opt:
      - no-new-privileges:true
    environment:
      # Zugangsdaten werden beim ersten Start im Setup-Wizard eingerichtet.
      - STACKS_DIR=/opt/dockpilot/stacks
    ports:
      - "8080:8080"   # ← Port anpassen oder eigenen Reverse Proxy vorschalten
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - /opt/dockpilot/stacks:/opt/dockpilot/stacks
      - /opt/dockpilot/data:/data

  dockpilot-updater:
    image: ghcr.io/linuxxunil1/dockpilot-updater:latest
    container_name: dockpilot-updater
    restart: unless-stopped
    environment:
      - DOCKPILOT_CONTAINER=dockpilot
      - CHECK_INTERVAL=28800
      - UPDATER_API_PORT=8081
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock

volumes: {}
```

**2. Starten**

```bash
docker compose up -d
```

Beim ersten Aufruf im Browser startet der Setup-Wizard — Benutzername, Passwort und
Secret werden dort eingerichtet und in `/data` gespeichert.

## Funktionen

| Tab | Funktionen |
|---|---|
| **Container** | Live-Stats (CPU %, RAM, Netz I/O), Start / Stop / Restart / Update |
| **Stacks** | Compose-Dateien im Browser anlegen, bearbeiten und deployen; Stack-Import via URL |
| **Wartung** | Image-Verwaltung (aufräumen / löschen), Self-Update mit automatischem 8h-Check |
| **Server** | Remote-Server per SSH oder DockPilot-Agent verwalten |
| **Konsole** | Web-Terminal (xterm.js) — Lokal oder auf jedem konfigurierten Remote-Server |

### Host-Übersicht
CPU, RAM, Festplatte, Uptime, Docker-Speichernutzung — live auf dem Container-Tab.

### Multi-Server-Modus
Im **Server**-Tab lassen sich SSH-Server und DockPilot-Agents hinzufügen.
Aus dem **Konsole**-Tab kann via Dropdown zwischen lokalem Shell und Remote-Servern
gewechselt werden.

### Installationsmodi

| Modus | Beschreibung |
|---|---|
| **Standalone** | Einzelserver — verwaltet nur den lokalen Docker-Host |
| **Hub** | Zentrales Dashboard — verwaltet mehrere Remote-Server |
| **Agent** | Wird vom Hub gesteuert — kein eigenes Dashboard |

### Self-Update
Der mitgelieferte `dockpilot-updater`-Container prüft alle 8 Stunden auf neue Images
und führt das Update durch — ohne dass dockpilot sich selbst beenden muss.

## Stacks-Verzeichnis

Compose-Stacks werden unter `/opt/dockpilot/stacks/<name>/docker-compose.yaml`
gespeichert und beim ersten Start automatisch angelegt.

## Verwaltung

```bash
# Logs anzeigen
docker compose logs -f

# Manuell updaten
docker compose pull && docker compose up -d

# Stoppen
docker compose down
```

## Optional: mTLS-Client-Zertifikatsauth

Zwingt den Browser, ein Client-Zertifikat vorzuweisen. Aktivieren:

1. Im Setup-Wizard Zertifikat generieren und `client.p12` im Browser importieren.
2. `ca.crt` in deinen Reverse Proxy (nginx, Caddy …) einbinden und Client-Auth aktivieren.
3. `docker compose up -d`

> Geheim halten: `docker-compose.yaml` (Passwörter), `certs/*.key`, `certs/*.p12`.
