# Installation

DockPilot läuft als einzelner Container. Ein Clone des Repositorys ist nicht nötig, das Image
liegt fertig unter `ghcr.io/linuxxunil1/dockpilot`.

## Voraussetzungen

- Linux-Host mit Docker Engine und Docker Compose v2
- Zugriff auf `/var/run/docker.sock` (DockPilot steuert darüber den Docker-Daemon)
- Für den Betrieb im Netz: ein Reverse Proxy mit TLS oder ein eigenes Zertifikat (siehe [TLS und Reverse Proxy](TLS-und-Reverse-Proxy))

## docker-compose.yaml

```yaml
services:
  dockpilot:
    image: ghcr.io/linuxxunil1/dockpilot:latest
    container_name: dockpilot
    restart: unless-stopped
    security_opt:
      - no-new-privileges:true
    environment:
      - STACKS_DIR=/opt/dockpilot/stacks
      # - TRUSTED_PROXIES=172.18.0.0/16
    ports:
      - "127.0.0.1:8080:8080"       # nur lokal, davor ein Reverse Proxy mit TLS
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - dockpilot_stacks:/opt/dockpilot/stacks
      - dockpilot_data:/data
      # - /etc/docker:/etc/docker   # nur für HTTP-Registries und Registry-Zertifikate

volumes:
  dockpilot_stacks:
  dockpilot_data:
```

```bash
docker compose up -d
```

Danach `http://127.0.0.1:8080` (bzw. die Adresse des Reverse Proxys) öffnen und die
[Ersteinrichtung](Ersteinrichtung) durchführen.

## Image-Tags

| Tag | Bedeutung |
|---|---|
| `latest` | Letzter Stand von `main` |
| `0.6.0` | Exakte Version |
| `0.6` | Neueste Fehlerbehebung der Version 0.6 |

Für reproduzierbare Installationen eine feste Version (`:0.6`) statt `latest` verwenden.

## Volumes und Mounts

| Pfad im Container | Zweck | Pflicht |
|---|---|---|
| `/var/run/docker.sock` | Steuerung des Docker-Daemons | ja |
| `/data` | Benutzer, Gruppen, Server, Tokens, Schlüssel (siehe [Daten und Backup](Daten-und-Backup)) | ja |
| `/opt/dockpilot/stacks` | Compose-Stacks (`<name>/docker-compose.yaml`) | ja |
| `/etc/docker` | `daemon.json` (HTTP-Registries) und `certs.d` (Registry-Zertifikate) | optional |

> **Wichtig:** Wer Zugriff auf den Docker-Socket hat, hat faktisch Root auf dem Host.
> DockPilot deshalb nie ungeschützt ins Netz stellen.

### Stacks-Verzeichnis als Host-Pfad

Sollen die Compose-Dateien direkt auf dem Host liegen, statt im Volume, einen Bind-Mount mit
**gleichem Pfad** innen und außen verwenden. Relative Pfade in den Compose-Dateien
(z. B. `./config:/config`) wertet der Docker-Daemon auf dem Host aus:

```yaml
    volumes:
      - /opt/dockpilot/stacks:/opt/dockpilot/stacks
```

## Verwaltung

```bash
# Logs anzeigen
docker compose logs -f

# Aktualisieren
docker compose pull && docker compose up -d

# Stoppen
docker compose down
```

## Healthcheck

`GET /health` liefert `ok`. Beispiel für die Compose-Datei:

```yaml
    healthcheck:
      test: ["CMD", "wget", "-qO-", "http://127.0.0.1:8080/health"]
      interval: 30s
      timeout: 5s
      retries: 3
```

(Bei nativem TLS `https://` verwenden und `--no-check-certificate` ergänzen.)

## Aufbau des Images

- Build-Stage: `golang:1.26-alpine`, statisches Binary (`CGO_ENABLED=0`)
- Runtime-Stage: `alpine:3.23` mit `ca-certificates`, `docker-cli` und `docker-compose`
- Beide Basis-Images sind per Digest gepinnt
- Startbefehl: `/app/dockpilot`, Port `8080`
