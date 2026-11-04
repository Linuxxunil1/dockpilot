# Daten und Backup

## Dateien in `/data`

| Datei | Inhalt |
|---|---|
| `users.json` | Benutzer und Passwort-Hashes |
| `groups.json` | Gruppen, Rechte, Server-Freigaben |
| `mode.json` | Betriebsmodus, Hub-URL, Agent-Token, Agent-Name/-URL |
| `servers.json` | Agents und SSH-Server inklusive Zugangsdaten |
| `known_hosts.json` | SSH-Host-Keys (Trust on first use) |
| `tokens.json` | Import-Tokens für Stacks |
| `docker/` | Registry-Logins (Docker-Config-Format) |
| `insecure_registries.json` | Eingetragene HTTP-Registries |
| `certs/` | Registry-Zertifikate (Quelle für `certs.d`) |
| `secret_key` | Schlüssel zum Signieren der Sitzungen |
| `credentials.json` | Nur Altinstallationen, wird beim ersten Zugriff migriert |

Die Dateien werden atomar geschrieben, sensible Dateien mit Rechten `0600`.

> Das Volume enthält Passwörter, SSH-Schlüssel und Tokens im Klartext bzw. als Hash.
> Backups verschlüsselt ablegen.

## Stacks

Die Compose-Dateien liegen im Volume `dockpilot_stacks` (bzw. `STACKS_DIR`) unter
`<name>/docker-compose.yaml`. Daten der Stacks selbst (deren Volumes) sind darin **nicht**
enthalten und müssen separat gesichert werden.

## Backup

```bash
docker run --rm \
  -v dockpilot_dockpilot_data:/data:ro \
  -v dockpilot_dockpilot_stacks:/stacks:ro \
  -v "$PWD":/backup \
  alpine tar czf /backup/dockpilot-backup-$(date +%F).tar.gz /data /stacks
```

Die Volume-Namen haben das Präfix des Compose-Projekts (meist der Ordnername). Mit
`docker volume ls | grep dockpilot` nachsehen.

## Wiederherstellung

```bash
docker compose down
docker run --rm \
  -v dockpilot_dockpilot_data:/data \
  -v dockpilot_dockpilot_stacks:/stacks \
  -v "$PWD":/backup \
  alpine sh -c "cd / && tar xzf /backup/dockpilot-backup-YYYY-MM-DD.tar.gz"
docker compose up -d
```

Wird `secret_key` nicht mit wiederhergestellt (oder `DASH_SECRET` geändert), müssen sich alle
Benutzer neu anmelden; die übrigen Daten bleiben gültig.
