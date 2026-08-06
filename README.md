# dockpilot

Schlankes Docker-Management-Dashboard (FastAPI + Docker SDK) — Container-Übersicht,
Live-Stats, Start/Stop/Restart/Update, Compose-Stack-Verwaltung, Remote-Server per SSH
und ein integriertes Web-Terminal.

Läuft hinter Traefik (Netzwerk `proxy`), HTTPS via Let's Encrypt.

## Deployment

Drei Schritte, eine Datei, kein Repo-Clone nötig.

**1. Compose-Datei herunterladen**

```bash
curl -o docker-compose.yaml \
  https://raw.githubusercontent.com/Linuxxunil1/dockpilot/main/docker-compose.example.yaml
```

**2. Pflichtfelder anpassen**

| Variable | Was ändern |
|---|---|
| `DASH_PASSWORD=changeme` | Sicheres Passwort wählen |
| `DASH_SECRET=changeme` | Zufallswert: `openssl rand -hex 32` |
| `dockpilot.example.com` | Eigene Domain |
| `letsencrypt` | Name des Cert-Resolvers in Traefik |
| `name: proxy` | Name des externen Traefik-Netzwerks |

**3. Starten**

```bash
docker compose up -d
```

Beide Container (`dockpilot` + `dockpilot-updater`) werden automatisch gestartet. Fertig.

## Funktionen

| Tab | Funktionen |
|---|---|
| **Container** | Live-Stats (CPU %, RAM, Netz I/O), Start / Stop / Restart / Update |
| **Stacks** | Compose-Dateien im Browser anlegen, bearbeiten und deployen; Stack-Import via URL |
| **Wartung** | Image-Verwaltung (aufräumen / löschen), Self-Update mit automatischem 8h-Check |
| **Server** | Remote-Server per SSH verwalten, Verbindungstest, Status-Anzeige (Online/Offline) |
| **Konsole** | Web-Terminal (xterm.js) — Lokal **oder** auf jedem konfigurierten Remote-Server |

### Host-Übersicht
CPU, RAM, Festplatte, Uptime, Docker-Speichernutzung — live auf dem Container-Tab.

### Remote-Server (Multi-Server-Modus)
Im **Server**-Tab lassen sich beliebig viele SSH-Server hinzufügen (SSH-Key oder Passwort).
Aus dem **Konsole**-Tab kann dann via Dropdown zwischen dem lokalen Shell und jedem
Remote-Server gewechselt werden — ohne separate SSH-Client-Software.

### Self-Update (Updater-Sidecar)
Der mitgelieferte `dockpilot-updater`-Container prüft alle 8 Stunden, ob ein neues Image
verfügbar ist, und führt das Update durch — außerhalb von dockpilot, damit der laufende
Container sich nicht selbst beenden muss.

## Stacks-Verzeichnis

Compose-Stacks werden unter `/opt/dockpilot/stacks/<name>/docker-compose.yaml`
gespeichert. Das Verzeichnis wird beim ersten Start automatisch angelegt.

## Verwaltung

```bash
# Logs anzeigen
docker compose logs -f

# Manuell updaten (ohne Self-Update-Sidecar)
docker compose pull && docker compose up -d

# Stoppen
docker compose down
```

## Optional: mTLS-Client-Zertifikatsauth

Zwingt den Browser, ein Client-Zertifikat vorzuweisen. Aktivieren:

1. Im Setup-Wizard Zertifikat generieren und `client.p12` im Browser importieren.
2. mTLS-Block in die Traefik-Dynamic-Config (`tls.yaml`) einfügen (siehe `examples/traefik.yml`).
3. In `docker-compose.yaml` die auskommentierte `tls.options`-Zeile einkommentieren.
4. `docker compose up -d`

> Geheim halten: `docker-compose.yaml` (enthält Passwörter), `certs/*.key`, `certs/*.p12`.
