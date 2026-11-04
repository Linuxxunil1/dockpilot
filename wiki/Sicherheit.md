# Sicherheit

## Grundsätzliches

DockPilot hat über den Docker-Socket volle Kontrolle über den Host. Deshalb:

- nur über HTTPS veröffentlichen ([TLS und Reverse Proxy](TLS-und-Reverse-Proxy)),
- den Port nicht ungeschützt ins Internet stellen (am besten VPN oder IP-Beschränkung im Proxy),
- `no-new-privileges:true` gesetzt lassen,
- das Daten-Volume sichern und schützen ([Daten und Backup](Daten-und-Backup)).

## Selbstschutz

Konsole, „Stop“ und „Update“ sind für den DockPilot-Container selbst gesperrt, damit man sich
nicht aussperrt. DockPilot erkennt den eigenen Container über `DOCKPILOT_CONTAINER`, die
cgroup, `/proc/self/mountinfo` oder den Hostnamen. Findet es ihn nicht, steht im Log:

```
Selbstschutz: eigener Container nicht gefunden (…) – ggf. DOCKPILOT_CONTAINER=<name> setzen
```

Dann `DOCKPILOT_CONTAINER=dockpilot` (Containername) setzen.

## Sitzungen

- Sitzungen laufen nach **7 Tagen** ab (Cookie `dockpilot_session`, signiert mit `DASH_SECRET`).
- „Abmelden“ beendet **alle** Sitzungen des Benutzers auf allen Geräten.
- Ein Passwortwechsel beendet alle anderen Sitzungen.
- Nach dem Update auf Version 0.6.0 muss man sich einmal neu anmelden.

## Login-Drosselung

Nach 5 Fehlversuchen für dieselbe Kombination aus Client-IP und Benutzername wächst die
Wartezeit (2 s, 4 s, … bis 15 min). Hinter einem Reverse Proxy `TRUSTED_PROXIES` setzen, sonst
zählt die IP des Proxys.

## Agents

- Agents haben keine Benutzeranmeldung; der Hub authentifiziert sich per Bearer-Token.
- Den Agent-Token wie ein Root-Passwort behandeln.
- Neue Agent-URLs muss ein Admin bestätigen (siehe [Hub und Agents](Hub-und-Agents)).

## Stack-Import

- Ziele auf localhost, Link-Local und Multicast sind immer gesperrt.
- Interne Netze (private Adressen, CGNAT) nur für Admins.
- Gespeicherte Import-Tokens nur für Admins und nur über `https://`.

## Kritische Rechte

| Recht | Risiko |
|---|---|
| `containers.exec` | Shell in beliebigen Containern, kommt Root auf dem Host gleich |
| `stacks.edit` + `stacks.control` | Beliebige Compose-Dateien deployen, kommt Root auf dem Host gleich |
| Admin | Voller Zugriff inklusive Benutzer, Server und Zugangsdaten |

## Lieferkette

- Basis-Images im Dockerfile per Digest gepinnt
- GitHub Actions per Commit-SHA gepinnt, Workflows mit minimalen Rechten
- `govulncheck` in der CI bricht bei aufgerufenen Schwachstellen ab
- Images werden mit SBOM und Provenance-Attestierung veröffentlicht
