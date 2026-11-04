# Stacks

Im Tab **Stacks** werden Docker-Compose-Stacks im Browser angelegt, bearbeitet und deployt,
lokal und auf Agents.

## Ablage

Jeder Stack liegt unter `STACKS_DIR/<name>/docker-compose.yaml`
(Standard: `/opt/dockpilot/stacks`). Das Verzeichnis wird beim ersten Start automatisch
angelegt. Ausgeführt wird `docker compose` im Container von DockPilot gegen den Docker-Socket
des Hosts.

## Aktionen

| Aktion | Entspricht | Recht |
|---|---|---|
| Ansehen, Logs | `docker compose logs` | `stacks.view` |
| Deployen | `docker compose up -d` | `stacks.control` |
| Herunterfahren | `docker compose down` | `stacks.control` |
| Pull | `docker compose pull` | `stacks.edit` |
| Anlegen, Bearbeiten, Importieren, Löschen | – | `stacks.edit` |

## Import per URL

Unter **Stacks → „Importieren“** lässt sich eine Compose-Datei von einer URL laden, z. B. aus
einem Git-Repository (Raw-URL).

- Für private Repositories einen **Import-Token** unter
  **Einstellungen → Registries & Tokens** hinterlegen. Er wird als `Authorization: Bearer …`
  mitgesendet.
- Gespeicherte Tokens dürfen nur Admins verwenden, und nur über `https://`.
- Ziele auf localhost, Link-Local (z. B. Cloud-Metadaten `169.254.169.254`) und Multicast
  sind immer gesperrt.
- Import aus internen Netzen (private Adressen, CGNAT) ist nur für Admins erlaubt.
- Beim Import auf einen Agent lädt der Hub die Datei; Tokens verlassen den Hub nicht.

## Relative Pfade

Relative Bind-Mounts in Compose-Dateien (`./data:/data`) beziehen sich auf das
Stack-Verzeichnis. Da der Docker-Daemon die Pfade auf dem **Host** auflöst, funktionieren sie
nur, wenn `STACKS_DIR` als Bind-Mount mit gleichem Pfad innen und außen eingebunden ist
(siehe [Installation](Installation#stacks-verzeichnis-als-host-pfad)). Mit einem benannten
Volume besser absolute Host-Pfade oder benannte Volumes verwenden.

## Sicherheitshinweis

`stacks.edit` zusammen mit `stacks.control` kommt Root auf dem Host gleich (eine Compose-Datei
kann z. B. `/` des Hosts einbinden oder `privileged: true` setzen). Diese Kombination nur
vertrauenswürdigen Benutzern geben.
