# Benutzer und Rechte

## Rollen

- **Admins** haben immer vollen Zugriff, auch auf Einstellungen, Server, Benutzer und Gruppen.
- **Benutzer** bekommen ihre Rechte ausschließlich über **Gruppen** (Tab **Benutzer**).

Ein Benutzer kann in mehreren Gruppen sein und bekommt dann alle Rechte zusammen.

## Berechtigungen

| ID | Bereich | Erlaubt |
|---|---|---|
| `containers.view` | Container | Container und Host-Auslastung ansehen |
| `containers.control` | Container | Container starten, stoppen, neu starten |
| `containers.update` | Container | Container-Image aktualisieren |
| `containers.exec` | Container | Konsole im Container öffnen (**kommt Root auf dem Host gleich**) |
| `stacks.view` | Stacks | Stacks, Compose-Dateien und Logs ansehen |
| `stacks.control` | Stacks | Stacks deployen und herunterfahren |
| `stacks.edit` | Stacks | Stacks anlegen, bearbeiten, importieren, pullen, löschen (**mit Deployen: Root auf dem Host**) |
| `images.manage` | System | Images ansehen, löschen und aufräumen |
| `ssh.console` | System | SSH-Konsole auf freigegebenen SSH-Servern |

## Server-Freigaben

Jede Gruppe legt zusätzlich fest, auf welchen Servern ihre Rechte gelten:

| Wert | Bedeutung |
|---|---|
| `local` | Der Server, auf dem DockPilot selbst läuft |
| `<server-id>` | Ein einzelner Agent oder SSH-Server |
| `*` | Alle Server |

## Gruppe „Standard“

Bestehende Benutzer landen beim Update auf das Gruppen-Modell automatisch in der Gruppe
**Standard** (Container und Stacks ansehen, starten, stoppen, deployen, auf allen Servern).

## Empfehlungen

- Nur so wenige Admins wie nötig.
- `containers.exec` und die Kombination `stacks.edit` + `stacks.control` nur an
  vertrauenswürdige Personen vergeben.
- Für reine Beobachter eine Gruppe nur mit `containers.view` und `stacks.view` anlegen.

## Passwort ändern

Jeder Benutzer kann sein Passwort selbst ändern (`POST /api/account/password`). Dabei werden
alle anderen Sitzungen dieses Benutzers beendet.

## Speicherung

Benutzer liegen in `/data/users.json`, Gruppen in `/data/groups.json`.
Passwörter werden nur als Hash gespeichert.
