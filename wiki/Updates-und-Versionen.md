# Updates und Versionen

## DockPilot aktualisieren

```bash
docker compose pull && docker compose up -d
```

Die Daten in `/data` und die Stacks bleiben erhalten. Vor größeren Versionssprüngen ein
[Backup](Daten-und-Backup) anlegen.

## Update-Hinweis in der Oberfläche

DockPilot prüft stündlich (und nach Änderungen an Registry-Zugangsdaten), ob in der Registry des
eigenen Images ein höherer Versions-Tag liegt, und zeigt dann unten neben der Versionsnummer
einen Hinweis an, auch für Agents mit älterer Version.

- Unter **Einstellungen → Updates** stehen Ergebnis und Fehlergrund der letzten Prüfung; dort
  lässt sie sich auch sofort auslösen (`POST /api/release/check`).
- Das geprüfte Image wird automatisch erkannt oder per `DOCKPILOT_IMAGE` festgelegt.
- Für eine private Registry müssen Zugangsdaten unter **Einstellungen → Registries & Tokens**
  hinterlegt sein.
- Zugangsdaten werden nur über geprüftes HTTPS gesendet. Bei selbst signiertem Zertifikat die CA
  unter **Zertifikate** hinterlegen. Für HTTP-Registries werden keine Zugangsdaten gesendet.

## Container über DockPilot aktualisieren

„Update“ an einem Container zieht das aktuelle Image und erstellt den Container mit gleicher
Konfiguration neu (Recht `containers.update`). Für den DockPilot-Container selbst ist das
gesperrt, ihn per `docker compose pull && docker compose up -d` aktualisieren.

## Versionierung

Die Version steht in `internal/version/VERSION` und wird beim Build fest ins Programm
eingebettet (Anzeige unten in der Oberfläche, `GET /api/version`).

| Änderung | Beispiel |
|---|---|
| Fehlerbehebung | `0.6.0` → `0.6.1` |
| Neue Funktion | `0.6.0` → `0.7.0` |

Für ein neues Release nur diese Datei anpassen. Git-Tags sind nicht nötig.

## CI/CD

Der Workflow `.github/workflows/docker-publish.yml`:

1. **go-check** (bei Push und Pull Request): `go vet`, `go build`, `go test`, `govulncheck`
2. **build-and-push** (nur Push auf `main`): baut das Image und veröffentlicht es unter
   `ghcr.io/linuxxunil1/dockpilot` mit den Tags `latest`, `<version>` und `<major>.<minor>`,
   inklusive SBOM und Provenance

Der Workflow `.github/workflows/wiki.yml` überträgt den Ordner `wiki/` ins GitHub-Wiki.
