# dockpilot

Schlankes Docker-Management-Dashboard (Go + Docker SDK) — Container-Übersicht,
Live-Stats, Start/Stop/Restart/Update, Compose-Stack-Verwaltung, Remote-Server per SSH
und ein integriertes Web-Terminal.

## Deployment

`docker-compose.yaml` anlegen und starten — kein Repo-Clone nötig.

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
    ports:
      - "8080:8080"                 # ← Port anpassen oder Reverse Proxy vorschalten
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - dockpilot_stacks:/opt/dockpilot/stacks
      - dockpilot_data:/data

volumes:
  dockpilot_stacks:
  dockpilot_data:
```

```bash
docker compose up -d
```

Beim ersten Aufruf führt ein Setup-Wizard durch die Konfiguration (Benutzername, Passwort, Betriebsmodus).

## Funktionen

| Tab | Funktionen |
|---|---|
| **Container** | Live-Stats (CPU %, RAM, Netz I/O), Start / Stop / Restart / Update, Konsole im Container (lokal und auf Agents) |
| **Stacks** | Compose-Dateien im Browser anlegen, bearbeiten und deployen; Stack-Import via URL |
| **Images** | Image-Verwaltung (aufräumen / löschen), lokal und auf Agents |
| **Server** | Remote-Server per SSH verwalten, Verbindungstest, Status-Anzeige (Online/Offline) |
| **SSH-Zugriff** | SSH-Zugänge hinterlegen (Schlüssel, optional mit Passphrase und OpenSSH-Zertifikat, oder Passwort) und daraus eine Web-Konsole (xterm.js) öffnen |
| **Benutzer** | Admins und Benutzer; Benutzer erhalten über Gruppen gezielt Rechte und Server-Freigaben |

### Host-Übersicht
CPU, RAM, Festplatte, Uptime, Docker-Speichernutzung — live auf dem Container-Tab.

### Remote-Server (Multi-Server-Modus)
Unter **SSH-Zugriff** lassen sich beliebig viele SSH-Server hinterlegen und per Klick eine
Konsole darauf öffnen — ohne separate SSH-Client-Software.

### Benutzer, Gruppen & Berechtigungen
Admins haben immer vollen Zugriff. Normale Benutzer bekommen ihre Rechte über **Gruppen**
(Tab **Benutzer**). Jede Gruppe legt fest,

- welche Funktionen erlaubt sind: Container ansehen / steuern / aktualisieren,
  Container-Konsole, Stacks ansehen / deployen / bearbeiten, Images verwalten,
  SSH-Konsole, und
- auf welchen Servern: lokal, einzelne Agents, einzelne SSH-Server oder alle Server.

Ein Benutzer kann in mehreren Gruppen sein und bekommt dann alle Rechte zusammen.
Bestehende Benutzer landen beim Update automatisch in der Gruppe **Standard**
(Container und Stacks ansehen, starten, stoppen, deployen – auf allen Servern).

### Registry-Zertifikate
Unter **Einstellungen → Registries & Tokens → Zertifikate** lassen sich je Registry eine eigene CA
(z. B. für selbst signierte Zertifikate) und optional ein Client-Zertifikat für mTLS hinterlegen.
Mit **Vom Server abrufen** holt DockPilot das Zertifikat direkt von der Registry und zeigt den
SHA-256-Fingerabdruck zum Vergleichen an. Die Dateien landen im Docker-Format unter
`/etc/docker/certs.d/<registry>/` (`ca.crt`, `client.cert`, `client.key`); der Docker-Daemon nutzt
sie ohne Neustart. Dafür muss `/etc/docker` in den Container eingebunden sein
(`- /etc/docker:/etc/docker`). Die Zertifikate werden wie die Registry-Logins an Agents übertragen,
und auch die Update-Prüfung vertraut ihnen – ein Eintrag als HTTP-Registry ist dann nicht nötig.

### Versionierung
Die Version steht in `internal/version/VERSION` und wird beim Build fest ins Programm eingebettet
(Anzeige unten in der Oberfläche). Für ein neues Release nur diese Datei anpassen:
Fehlerbehebung → `0.2.1`, neue Funktion → `0.3.0`. Die GitHub-Actions-CI baut auf `main` das Image `ghcr.io/linuxxunil1/dockpilot` und taggt es
zusätzlich mit der Version (`0.2.0` und `0.2`) – Git-Tags sind nicht nötig.

DockPilot prüft stündlich (und nach Änderungen an Registry-Zugangsdaten), ob in der Registry des eigenen Images ein höherer
Versions-Tag liegt, und zeigt dann unten neben der Versionsnummer einen Hinweis an
(auch für Agents mit älterer Version). Aktualisiert wird per
`docker compose pull && docker compose up -d`. Für eine private Registry müssen unter
**Einstellungen → Registries & Tokens** Zugangsdaten hinterlegt sein; bei selbst signiertem Zertifikat die Registry
zusätzlich als HTTP-Registry eintragen. Unter **Einstellungen → Updates** stehen Ergebnis
und Fehlergrund der letzten Prüfung; dort lässt sie sich auch sofort auslösen.

## Stacks-Verzeichnis

Compose-Stacks werden im Volume `dockpilot_stacks` unter `<name>/docker-compose.yaml`
gespeichert. Das Verzeichnis wird beim ersten Start automatisch angelegt.

## Verwaltung

```bash
# Logs anzeigen
docker compose logs -f

# Updaten
docker compose pull && docker compose up -d

# Stoppen
docker compose down
```

## Optional: mTLS-Client-Zertifikatsauth

Zwingt den Browser, ein Client-Zertifikat vorzuweisen. Aktivieren:

1. Im Setup-Wizard Zertifikat generieren und `client.p12` im Browser importieren.
2. `ca.crt` in den Reverse Proxy (nginx, Caddy, …) einbinden und Client-Auth aktivieren.
3. `docker compose up -d`

> Geheim halten: `certs/*.key`, `certs/*.p12`.
