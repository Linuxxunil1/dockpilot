# Fehlerbehebung

Erster Schritt ist immer das Log:

```bash
docker logs -f dockpilot
```

## Setup-Code unbekannt

Der Code steht beim Start im Log (`Ersteinrichtung: Setup-Code …`). Ohne `SETUP_TOKEN` ändert
er sich bei jedem Neustart, also den aktuellen Log-Eintrag verwenden.

## Anmeldung klappt nicht, Seite lädt nur neu

Das Sitzungs-Cookie wird nur über HTTPS gesetzt. Entweder über HTTPS zugreifen oder (nur im
vertrauenswürdigen Netz) `COOKIE_SECURE=false` setzen.

## „Zu viele Versuche“ / lange Wartezeit beim Login

Login-Drosselung nach 5 Fehlversuchen (bis 15 min). Wartezeit abwarten oder den Container neu
starten. Sind alle Benutzer gleichzeitig betroffen, fehlt hinter dem Reverse Proxy
`TRUSTED_PROXIES`.

## Konsole öffnet sich nicht / bricht sofort ab

Der Reverse Proxy reicht keine WebSockets durch. `Upgrade`- und `Connection`-Header weitergeben
(siehe [TLS und Reverse Proxy](TLS-und-Reverse-Proxy)). Bei nginx zusätzlich
`proxy_read_timeout` erhöhen, sonst brechen untätige Konsolen nach 60 s ab.

## „Selbstschutz: eigener Container nicht gefunden“

`DOCKPILOT_CONTAINER=<containername>` setzen (siehe [Sicherheit](Sicherheit#selbstschutz)).

## Agent bleibt „Offline“

- Erreicht der Agent den Hub? Auf dem Agent: `docker logs dockpilot` auf Fehler bei der
  Registrierung prüfen.
- Erreicht der Hub den Agent unter der gemeldeten URL? Ggf. `AGENT_URL` setzen.
- Bei selbst signierten Zertifikaten `AGENT_CA_FILE` auf beiden Seiten einbinden.
- Hat der Agent eine neue URL gemeldet, muss ein Admin sie im Hub bestätigen.

## Fehlermeldung „x509: certificate signed by unknown authority“

- Zwischen Hub und Agent: `AGENT_CA_FILE` setzen.
- Bei einer Registry: CA unter **Einstellungen → Registries & Tokens → Zertifikate** hinterlegen.

## HTTP-Registry funktioniert nicht

- `/etc/docker` muss eingebunden sein.
- Im Log nach `PID-Datei von dockerd nicht gefunden` suchen und dann auf dem Host
  `sudo systemctl reload docker` ausführen.
- `docker info | grep -A5 "Insecure Registries"` zeigt, ob der Daemon die Registry kennt.

## Relative Pfade in Stacks zeigen ins Leere

Der Docker-Daemon löst Pfade auf dem Host auf. `STACKS_DIR` als Bind-Mount mit gleichem Pfad
einbinden (siehe [Stacks](Stacks#relative-pfade)).

## Kein Update-Hinweis

Unter **Einstellungen → Updates** steht der Fehlergrund der letzten Prüfung. Häufig fehlen
Zugangsdaten für eine private Registry, oder das eigene Image wurde nicht erkannt
(`DOCKPILOT_IMAGE` setzen).

## Nach Update alle abgemeldet

Normal beim Update auf 0.6.0 oder wenn `DASH_SECRET` bzw. `/data/secret_key` geändert wurde.
Einfach neu anmelden.
