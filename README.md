# dockpilot

Schlankes Docker-Management-Dashboard (FastAPI + Docker SDK) — Container-Übersicht,
Live-Stats, Start/Stop/Restart/Update und eine integrierte **Compose-Stack-Verwaltung**
zum Deployen neuer Dienste direkt aus dem Browser.

Läuft hinter Traefik (Netzwerk `proxy`), HTTPS via Let's Encrypt.

## Deployment

Drei Schritte, eine Datei, kein Repo-Clone nötig.

**1. Compose-Datei herunterladen**

```bash
curl -o docker-compose.yaml \
  https://raw.githubusercontent.com/Linuxxunil1/dockpilot/main/docker-compose.example.yaml
```

**2. Pflichtfelder anpassen**

| Zeile | Was ändern |
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

Das Image wird automatisch gepullt. Fertig.

## Funktionen

- **Host-Übersicht:** CPU, RAM, Festplatte, Uptime, Docker-Speicher
- **Container-Tab:** Live-Stats (CPU %, RAM, Netz I/O), Start / Stop / Restart / Update
- **Stacks-Tab:** Compose-Dateien direkt im Browser anlegen, bearbeiten und deployen
- Login mit signiertem Session-Cookie (7 Tage)

## Stacks-Verzeichnis

Compose-Stacks werden unter `/opt/dockpilot/stacks/<name>/docker-compose.yaml`
gespeichert. Das Verzeichnis wird beim ersten Start automatisch angelegt.

## Verwaltung

```bash
docker compose pull && docker compose up -d   # Update auf neue Version
docker compose logs -f
docker compose down
```

## Optional: mTLS-Client-Zertifikatsauth

Zwingt den Browser, ein Client-Zertifikat vorzuweisen. Aktivieren:

1. Client-Zertifikat im Browser importieren.
2. mTLS-Block in die Traefik-Dynamic-Config (`tls.yaml`) einfügen.
3. In `docker-compose.yaml` die auskommentierte `tls.options`-Zeile einkommentieren.
4. `docker compose up -d`

> Geheim halten: `docker-compose.yaml` (enthält Passwörter), `certs/*.key`, `certs/*.p12`.
