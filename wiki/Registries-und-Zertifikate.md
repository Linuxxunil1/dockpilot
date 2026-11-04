# Registries und Zertifikate

Alle Einstellungen liegen unter **Einstellungen → Registries & Tokens** (nur Admins).

## Registry-Logins

Zugangsdaten für private Registries (z. B. `ghcr.io`, eine eigene Harbor-Instanz). Sie werden
für Pulls, Container-Updates und die Update-Prüfung verwendet und im Docker-Config-Format unter
`/data/docker` gespeichert. Im Hub-Modus werden sie mit **Synchronisieren** an alle Agents
übertragen.

## Import-Tokens

Bearer-Tokens, um Compose-Dateien aus privaten Repositories zu importieren (siehe
[Stacks](Stacks)). Gespeichert in `/data/tokens.json`. Sie werden nie an Agents übertragen.

## HTTP-Registries (insecure registries)

Registries ohne TLS werden in die `daemon.json` des Docker-Daemons eingetragen
(`insecure-registries`). Voraussetzungen:

- `/etc/docker` ist in den Container eingebunden: `- /etc/docker:/etc/docker`
- DockPilot schreibt die Liste in `daemon.json` (alle übrigen Einstellungen bleiben erhalten) und
  versucht, den Daemon per `SIGHUP` neu zu laden. Steht im Log
  `PID-Datei von dockerd nicht gefunden — daemon.json manuell neu laden`, auf dem Host
  `sudo systemctl reload docker` ausführen (kein Neustart der Container nötig).
- Im Hub-Modus wird die Liste mit **Synchronisieren** auch in die `daemon.json` der Agents geschrieben.

Für HTTP-Registries sendet die Update-Prüfung keine Zugangsdaten. Besser ist meist ein
Zertifikat mit eigener CA (nächster Abschnitt).

## Registry-Zertifikate

Unter **Zertifikate** lässt sich je Registry hinterlegen:

- eine eigene **CA** (z. B. für selbst signierte Zertifikate)
- optional ein **Client-Zertifikat und Schlüssel** für mTLS

Mit **„Vom Server abrufen“** holt DockPilot das Zertifikat direkt von der Registry und zeigt den
SHA-256-Fingerabdruck zum Vergleichen an. Vor dem Speichern den Fingerabdruck auf anderem Weg
prüfen:

```bash
openssl s_client -connect registry.example.com:443 </dev/null 2>/dev/null \
  | openssl x509 -noout -fingerprint -sha256
```

Die Dateien landen im Docker-Format unter `/etc/docker/certs.d/<registry>/`:

| Datei | Inhalt |
|---|---|
| `ca.crt` | CA der Registry |
| `client.cert` | Client-Zertifikat (mTLS) |
| `client.key` | Client-Schlüssel (mTLS) |

Der Docker-Daemon nutzt sie ohne Neustart. Dafür muss `/etc/docker` eingebunden sein
(`DOCKER_CERTS_DIR` ändert den Pfad). Die Zertifikate werden wie die Logins an Agents
übertragen, und auch die Update-Prüfung vertraut ihnen; ein Eintrag als HTTP-Registry ist dann
nicht nötig.
