# Konfiguration

DockPilot wird über Umgebungsvariablen konfiguriert. Alles Weitere (Benutzer, Server, Registries)
wird in der Oberfläche eingestellt und unter `/data` gespeichert.

## Umgebungsvariablen

| Variable | Standard | Zweck |
|---|---|---|
| `STACKS_DIR` | `/opt/dockpilot/stacks` | Verzeichnis der Compose-Stacks |
| `DATA_DIR` | `/data` | Benutzer, Gruppen, Server, Tokens, Schlüssel |
| `LISTEN_ADDR` | `:8080` | Adresse und Port im Container |
| `SETUP_TOKEN` | zufällig | Fester Setup-Code für die Ersteinrichtung |
| `TLS_CERT`, `TLS_KEY` | – | Pfade zu Zertifikat und Schlüssel (PEM). Sind beide gesetzt, spricht DockPilot selbst HTTPS |
| `COOKIE_SECURE` | `true` | Sitzungs-Cookie nur über HTTPS. Nur bei reinem HTTP auf `false` setzen |
| `TRUSTED_PROXIES` | – | Kommagetrennte IPs/CIDRs des Reverse Proxys, z. B. `172.18.0.0/16,10.0.0.5`. Nur von dort wird `X-Forwarded-For` für die Login-Drosselung ausgewertet |
| `AGENT_CA_FILE` | – | CA-Datei (PEM) für Hub bzw. Agents mit selbst signiertem HTTPS-Zertifikat, zusätzlich zu den System-CAs |
| `AGENT_URL` | – | Agent-Modus: URL, unter der der Hub diesen Agent erreicht (überschreibt den Wert aus dem Setup) |
| `DOCKPILOT_CONTAINER` | – | Name oder ID des eigenen Containers, falls der Selbstschutz ihn nicht findet |
| `DOCKPILOT_IMAGE` | eigenes Image | Image-Referenz für die Update-Prüfung |
| `DASH_SECRET` | zufällig, in `/data/secret_key` | Schlüssel zum Signieren der Sitzungen |
| `DOCKER_DAEMON_CONFIG` | `/etc/docker/daemon.json` | `daemon.json` für HTTP-Registries |
| `DOCKER_CERTS_DIR` | `/etc/docker/certs.d` | Ablage der Registry-Zertifikate |

## Hinweise

- **`COOKIE_SECURE=false`** nur im vertrauenswürdigen Netz verwenden: Passwort und Sitzung gehen
  dann unverschlüsselt über die Leitung.
- **`DASH_SECRET`**: Die Werte `changeme` und `insecure` werden ignoriert. Ohne Variable erzeugt
  DockPilot beim ersten Start einen zufälligen Schlüssel in `/data/secret_key`. Wird der Schlüssel
  geändert, werden alle Sitzungen ungültig.
- **`DASH_USER` / `DASH_PASSWORD`** werden nicht mehr ausgewertet. Einen Standardzugang gibt es nicht.
- **`TRUSTED_PROXIES`** hinter einem Reverse Proxy immer setzen, sonst zählt bei der
  Login-Drosselung die IP des Proxys für alle Clients gemeinsam.

## Beispiel: Betrieb hinter Traefik

```yaml
    environment:
      - STACKS_DIR=/opt/dockpilot/stacks
      - TRUSTED_PROXIES=172.18.0.0/16
```

## Beispiel: natives HTTPS

```yaml
    environment:
      - TLS_CERT=/certs/fullchain.pem
      - TLS_KEY=/certs/privkey.pem
    ports:
      - "8443:8080"
    volumes:
      - ./certs:/certs:ro
```
