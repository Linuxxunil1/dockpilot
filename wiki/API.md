# API

DockPilot hat eine JSON-API, die auch die Weboberfläche nutzt.

## Authentifizierung

| Art | Verwendung |
|---|---|
| Sitzungs-Cookie `dockpilot_session` | Browser, nach `POST /login` |
| `Authorization: Bearer <agent-token>` | Nur Hub → Agent. Gilt ausschließlich auf einem Agent |

Rechte werden je Endpunkt geprüft (siehe [Benutzer und Rechte](Benutzer-und-Rechte)).
Endpunkte unter Einstellungen, Server, Benutzer und Gruppen erfordern Admin-Rechte.

Zustandsändernde Anfragen von fremden Seiten (Cross-Origin) werden abgelehnt (CSRF-Schutz).
Skripte und `curl` ohne `Origin`-Header sind davon nicht betroffen.

## Setup und Anmeldung

| Methode | Pfad | Beschreibung |
|---|---|---|
| GET | `/setup` | Setup-Wizard |
| POST | `/api/setup/credentials` | Ersten Admin anlegen (mit Setup-Code) |
| GET / POST | `/api/setup/mode` | Betriebsmodus lesen / setzen |
| GET / POST | `/login` | Anmeldeseite / Anmelden |
| POST | `/logout` | Alle Sitzungen des Benutzers beenden |
| GET | `/health` | Healthcheck, liefert `ok` |

## Konto, Benutzer, Gruppen

| Methode | Pfad | Beschreibung |
|---|---|---|
| GET | `/api/me` | Eigener Benutzer und Rechte |
| GET | `/api/version` | Programmversion |
| GET | `/api/release` | Ergebnis der letzten Update-Prüfung |
| POST | `/api/release/check` | Update-Prüfung sofort ausführen |
| POST | `/api/account/password` | Eigenes Passwort ändern |
| GET / POST | `/api/users` | Benutzer auflisten / anlegen |
| PUT / DELETE | `/api/users/{name}` | Benutzer ändern / löschen |
| GET / POST | `/api/groups` | Gruppen auflisten / anlegen |
| PUT / DELETE | `/api/groups/{id}` | Gruppe ändern / löschen |

## Container und Host (lokal)

| Methode | Pfad | Beschreibung |
|---|---|---|
| GET | `/api/containers` | Container mit Live-Stats |
| POST | `/api/containers/{cid}/{action}` | `start`, `stop`, `restart`, `update` |
| GET | `/api/host` | CPU, RAM, Festplatte, Uptime |
| GET | `/api/sizes` | Docker-Speichernutzung |

## Stacks (lokal)

| Methode | Pfad | Beschreibung |
|---|---|---|
| GET | `/api/stacks` | Stacks auflisten |
| POST | `/api/stacks/import` | Compose-Datei von URL importieren |
| GET / PUT | `/api/stacks/{name}/file` | Compose-Datei lesen / speichern |
| POST | `/api/stacks/{name}/up` | `docker compose up -d` |
| POST | `/api/stacks/{name}/down` | `docker compose down` |
| POST | `/api/stacks/{name}/pull` | `docker compose pull` |
| POST | `/api/stacks/{name}/logs` | Logs abrufen |
| DELETE | `/api/stacks/{name}` | Stack löschen |

## Images (lokal)

| Methode | Pfad | Beschreibung |
|---|---|---|
| GET | `/api/images` | Images auflisten |
| POST | `/api/images/prune` | Ungenutzte Images entfernen |
| DELETE | `/api/images/{id}` | Image löschen |

## Registries, Zertifikate, Tokens (Admin)

| Methode | Pfad | Beschreibung |
|---|---|---|
| GET / POST | `/api/registries` | Registry-Logins auflisten / anlegen |
| POST | `/api/registries/sync` | Logins an Agents übertragen |
| DELETE | `/api/registries/{registry}` | Login löschen |
| GET / POST | `/api/registry-certs` | Zertifikate auflisten / speichern |
| POST | `/api/registry-certs/fetch` | Zertifikat von der Registry abrufen |
| POST | `/api/registry-certs/sync` | Zertifikate an Agents übertragen |
| DELETE | `/api/registry-certs/{registry}` | Zertifikate löschen |
| GET / POST | `/api/insecure-registries` | HTTP-Registries auflisten / hinzufügen |
| POST | `/api/insecure-registries/sync` | An Agents übertragen |
| DELETE | `/api/insecure-registries/{registry}` | Entfernen |
| GET | `/api/tokens` | Namen der Import-Tokens |
| PUT / DELETE | `/api/tokens/{name}` | Import-Token speichern / löschen |

## Server und Agents (Hub)

| Methode | Pfad | Beschreibung |
|---|---|---|
| POST | `/api/servers/agent-invite` | Einladungs-Token für einen Agent erzeugen |
| POST | `/api/agents/register` | Registrierung eines Agents (Bearer) |
| GET / POST | `/api/servers` | Server auflisten / anlegen |
| PUT | `/api/servers/{id}` | Server ändern |
| PATCH | `/api/servers/{id}` | Neue Agent-URL bestätigen (`confirm_url`) oder verwerfen (`reject_url`) |
| DELETE | `/api/servers/{id}` | Server löschen |
| POST | `/api/servers/host-key` | SSH-Host-Key-Fingerprint abrufen |
| POST | `/api/servers/{id}/test` | Verbindung testen |
| DELETE | `/api/servers/{id}/known-host` | Gespeicherten SSH-Host-Key zurücksetzen |

### Weiterleitung an Agents

Diese Endpunkte entsprechen den lokalen, werden aber vom Hub an den Agent `{id}` weitergereicht:

| Methode | Pfad |
|---|---|
| GET | `/api/servers/{id}/containers` |
| POST | `/api/servers/{id}/containers/{cid}/{action}` |
| GET | `/api/servers/{id}/host` |
| GET | `/api/servers/{id}/version` |
| GET | `/api/servers/{id}/stacks` |
| POST | `/api/servers/{id}/stacks/import` |
| GET / PUT | `/api/servers/{id}/stacks/{name}/file` |
| POST | `/api/servers/{id}/stacks/{name}/{action}` |
| DELETE | `/api/servers/{id}/stacks/{name}` |
| GET | `/api/servers/{id}/images` |
| POST | `/api/servers/{id}/images/prune` |
| DELETE | `/api/servers/{id}/images/{iid}` |

## Agent-seitig

| Methode | Pfad | Beschreibung |
|---|---|---|
| GET | `/api/agent/hub-status` | Erreichbarkeit des Hubs („Online“/„Offline“) |

## WebSockets (Konsolen)

| Pfad | Beschreibung |
|---|---|
| `/ws/container/{cid}` | Shell in einem lokalen Container |
| `/ws/servers/{id}/container/{cid}` | Shell in einem Container auf einem Agent (über den Hub) |
| `/ws/ssh/{id}` | SSH-Konsole auf einem hinterlegten SSH-Server |

## Beispiel mit curl

```bash
# Anmelden und Cookie speichern
curl -c cookies.txt -X POST https://dockpilot.example.com/login \
  -d 'username=admin' -d 'password=…'

# Container auflisten
curl -b cookies.txt https://dockpilot.example.com/api/containers
```
