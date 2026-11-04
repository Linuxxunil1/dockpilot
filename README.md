# dockpilot

Schlankes Docker-Management-Dashboard (Go + Docker SDK) — Container-Übersicht,
Live-Stats, Start/Stop/Restart/Update, Compose-Stack-Verwaltung, Remote-Server per SSH
und ein integriertes Web-Terminal.

Ausführliche Anleitungen und technische Details stehen im
[Wiki](https://github.com/Linuxxunil1/dockpilot/wiki) (Quelle: Ordner `wiki/`).

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
      - "127.0.0.1:8080:8080"       # ← nur lokal, davor ein Reverse Proxy mit TLS
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

Den Port nur lokal binden (`127.0.0.1:8080:8080`) und DockPilot über einen Reverse Proxy
mit TLS (nginx, Caddy, Traefik, …) veröffentlichen. Alternativ kann DockPilot selbst HTTPS
sprechen (`TLS_CERT`/`TLS_KEY`, siehe unten).

### Ersteinrichtung

Beim ersten Aufruf leitet DockPilot auf `/setup` weiter. Der Setup-Wizard legt den ersten
Admin (Benutzername, Passwort) und den Betriebsmodus fest (Standalone, Hub oder Agent).

- Die Einrichtung ist durch einen **Setup-Code** geschützt. Er steht beim Start im Container-Log:
  `docker logs dockpilot` → `Ersteinrichtung: Setup-Code … (im Browser unter /setup eingeben)`.
- Ohne `SETUP_TOKEN` wird der Code bei jedem Start neu erzeugt. Mit `SETUP_TOKEN` legt man ihn selbst fest.
- Einen Standardzugang gibt es nicht. `DASH_USER`/`DASH_PASSWORD` werden nicht mehr ausgewertet.

### Umgebungsvariablen

| Variable | Standard | Zweck |
|---|---|---|
| `STACKS_DIR` | `/opt/dockpilot/stacks` | Verzeichnis der Compose-Stacks |
| `DATA_DIR` | `/data` | Benutzer, Gruppen, Server, Tokens, Schlüssel |
| `LISTEN_ADDR` | `:8080` | Adresse und Port im Container |
| `SETUP_TOKEN` | zufällig | Fester Setup-Code für die Ersteinrichtung |
| `TLS_CERT`, `TLS_KEY` | – | Pfade zu Zertifikat und Schlüssel (PEM); beide gesetzt → DockPilot spricht selbst HTTPS |
| `COOKIE_SECURE` | `true` | Sitzungs-Cookie nur über HTTPS. Nur bei reinem HTTP auf `false` setzen |
| `TRUSTED_PROXIES` | – | Kommagetrennte IPs/CIDRs des Reverse Proxys, z. B. `172.18.0.0/16,10.0.0.5`. Nur von dort wird `X-Forwarded-For` für die Login-Drosselung ausgewertet |
| `AGENT_CA_FILE` | – | CA-Datei (PEM) für Hub bzw. Agents mit selbst signiertem HTTPS-Zertifikat, zusätzlich zu den System-CAs |
| `AGENT_URL` | – | Agent-Modus: URL, unter der der Hub diesen Agent erreicht (überschreibt den Wert aus dem Setup) |
| `DOCKPILOT_CONTAINER` | – | Name oder ID des eigenen Containers, falls der Selbstschutz ihn nicht findet (Log: `Selbstschutz: eigener Container nicht gefunden`) |
| `DOCKPILOT_IMAGE` | eigenes Image | Image-Referenz für die Update-Prüfung |
| `DASH_SECRET` | zufällig, in `/data/secret_key` | Schlüssel zum Signieren der Sitzungen |
| `DOCKER_DAEMON_CONFIG` | `/etc/docker/daemon.json` | `daemon.json` für HTTP-Registries |
| `DOCKER_CERTS_DIR` | `/etc/docker/certs.d` | Ablage der Registry-Zertifikate |

> `COOKIE_SECURE=false` nur im vertrauenswürdigen Netz verwenden: Passwort und Sitzung gehen
> dann unverschlüsselt über die Leitung.

## Funktionen

| Tab | Funktionen |
|---|---|
| **Container** | Live-Stats (CPU %, RAM, Netz I/O), Start / Stop / Restart / Update, Konsole im Container (lokal und auf Agents) |
| **Stacks** | Compose-Dateien im Browser anlegen, bearbeiten und deployen; Stack-Import via URL (lokal und auf Agents) |
| **Images** | Image-Verwaltung (aufräumen / löschen), lokal und auf Agents |
| **Server & Agents** | Agents einladen, Verbindungstest, Status-Anzeige (Online/Offline), neue Agent-URLs bestätigen |
| **SSH-Zugriff** | SSH-Zugänge hinterlegen (Schlüssel, optional mit Passphrase und OpenSSH-Zertifikat, oder Passwort) und daraus eine Web-Konsole (xterm.js) öffnen |
| **Benutzer** | Admins und Benutzer; Benutzer erhalten über Gruppen gezielt Rechte und Server-Freigaben |

### Host-Übersicht
CPU, RAM, Festplatte, Uptime, Docker-Speichernutzung — live auf dem Container-Tab.

### Hub und Agents
Ein DockPilot im Modus **Hub** verwaltet weitere Docker-Hosts, auf denen DockPilot im Modus
**Agent** läuft.

- Einladen: **Server & Agents → "Agent einladen"** (nur Admins) erzeugt einen Einladungs-Token.
  Diesen beim Setup des Agents eingeben (Agent-Modus → Hub-Verbindung).
- Der Agent meldet sich alle 60 s beim Hub und übermittelt dabei seine URL.
- Auf Agents gibt es keine Anmeldung. Die Seite des Agents zeigt ohne Token nur, ob der Hub
  erreichbar ist ("Online"/"Offline"). Anzeigen und Ändern der Konfiguration nur mit dem Agent-Token.
- Meldet ein bereits registrierter Agent eine **neue URL**, übernimmt der Hub sie nicht
  automatisch. In der Agent-Kachel erscheint "Agent meldet neue URL" mit "Übernehmen" und
  "Verwerfen"; bestätigen kann nur ein Admin (`PATCH /api/servers/{id}` mit `confirm_url` bzw. `reject_url`).
  Nur übernehmen, wenn der Agent bewusst umgezogen ist.
- Für Agents HTTPS verwenden. Bei `http://` steht ein Hinweis im Log des Hubs. Bei selbst
  signiertem Zertifikat die CA per `AGENT_CA_FILE` auf dem Hub (bzw. auf dem Agent für den Hub) einbinden.

### SSH-Zugriff
Unter **SSH-Zugriff** lassen sich beliebig viele SSH-Server hinterlegen und per Klick eine
Konsole darauf öffnen — ohne separate SSH-Client-Software.

- Beim Anlegen mit "Abrufen" den Host-Key-Fingerprint (`SHA256:…`) holen
  (`POST /api/servers/host-key`, nur Admins) und mit dem Server vergleichen. Der Fingerprint
  wird dann fest hinterlegt.
- Ohne Fingerprint gilt der Host-Key der ersten Verbindung (Trust on first use).

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

Vorsicht bei der Vergabe:

- **Container-Konsole** (`containers.exec`) kommt Root auf dem Host gleich.
- **Stacks bearbeiten** (`stacks.edit`) zusammen mit **Stacks deployen** (`stacks.control`) ebenfalls.

### Sicherheit
- **Selbstschutz:** Konsole, "Stop" und "Update" sind für den DockPilot-Container selbst gesperrt.
  Findet DockPilot den eigenen Container nicht, steht ein Hinweis im Log; dann `DOCKPILOT_CONTAINER` setzen.
- **Sitzungen:** "Abmelden" beendet alle Sitzungen des Benutzers auf allen Geräten. Ein
  Passwortwechsel beendet alle anderen Sitzungen. Sitzungen laufen nach 7 Tagen ab.
  Nach dem Update auf Version 0.6.0 muss man sich einmal neu anmelden.
- **Login-Drosselung:** Nach 5 Fehlversuchen für dieselbe Kombination aus Client-IP und
  Benutzername wächst die Wartezeit (2 s, 4 s, … bis 15 min). Hinter einem Reverse Proxy
  `TRUSTED_PROXIES` setzen, sonst zählt die IP des Proxys.
- **Stack-Import** (Stacks → "Importieren", lokal und auf Agents über
  `POST /api/servers/{id}/stacks/import`):
  - Ziele auf localhost, Link-Local (z. B. Cloud-Metadaten) und Multicast sind immer gesperrt.
  - Import aus internen Netzen (private Adressen, CGNAT) nur für Admins.
  - Gespeicherte Import-Tokens (Einstellungen → Registries & Tokens) nur für Admins und nur über `https://`.
  - Beim Import auf einen Agent lädt der Hub die Datei; Tokens verlassen den Hub nicht.

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
Fehlerbehebung → `0.6.1`, neue Funktion → `0.7.0`. Die GitHub-Actions-CI baut auf `main` das Image `ghcr.io/linuxxunil1/dockpilot` und taggt es
zusätzlich mit der Version (`0.6.0` und `0.6`) – Git-Tags sind nicht nötig.

DockPilot prüft stündlich (und nach Änderungen an Registry-Zugangsdaten), ob in der Registry des eigenen Images ein höherer
Versions-Tag liegt, und zeigt dann unten neben der Versionsnummer einen Hinweis an
(auch für Agents mit älterer Version). Aktualisiert wird per
`docker compose pull && docker compose up -d`. Für eine private Registry müssen unter
**Einstellungen → Registries & Tokens** Zugangsdaten hinterlegt sein. Die Zugangsdaten
sendet die Prüfung nur über geprüftes HTTPS: Bei selbst signiertem Zertifikat die CA unter
**Einstellungen → Registries & Tokens → Zertifikate** hinterlegen. Für eine als HTTP-Registry
eingetragene Registry werden keine Zugangsdaten gesendet. Unter **Einstellungen → Updates** stehen Ergebnis
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

## TLS

DockPilot sollte nur über HTTPS erreichbar sein (Passwörter, Sitzungs-Cookie, Konsolen).

- **Reverse Proxy (empfohlen):** Port nur lokal binden (`127.0.0.1:8080:8080`), TLS im Proxy
  terminieren und die Proxy-Adresse in `TRUSTED_PROXIES` eintragen. Der Proxy muss WebSockets
  (`/ws/…`) durchreichen, sonst funktionieren die Konsolen nicht.
- **Nativ:** `TLS_CERT` und `TLS_KEY` auf Zertifikat und Schlüssel (PEM, im Container eingebunden)
  setzen. DockPilot lauscht dann auf `LISTEN_ADDR` mit HTTPS und sendet HSTS.
- Ein Setup-Schritt für mTLS-Client-Zertifikate existiert nicht. Client-Zertifikate bei Bedarf im Reverse Proxy erzwingen.
