# DockPilot Wiki

DockPilot ist ein schlankes Docker-Management-Dashboard (Go + Docker SDK). Es bietet eine
Container-Übersicht mit Live-Stats, Start/Stop/Restart/Update, Verwaltung von Compose-Stacks,
Remote-Server per Agent oder SSH und ein integriertes Web-Terminal.

Dieses Wiki enthält alle technischen Details und Anleitungen zum Betrieb der Container.

## Schnellstart

1. [Installation](Installation): `docker-compose.yaml` anlegen und `docker compose up -d`
2. [Ersteinrichtung](Ersteinrichtung): Setup-Code aus `docker logs dockpilot` holen und unter `/setup` eingeben
3. [TLS und Reverse Proxy](TLS-und-Reverse-Proxy): DockPilot nur über HTTPS veröffentlichen

## Seiten

| Thema | Inhalt |
|---|---|
| [Installation](Installation) | Compose-Datei, Volumes, Ports, Verwaltung |
| [Konfiguration](Konfiguration) | Alle Umgebungsvariablen |
| [Ersteinrichtung](Ersteinrichtung) | Setup-Wizard, Setup-Code, Betriebsmodi |
| [Hub und Agents](Hub-und-Agents) | Mehrere Docker-Hosts zentral verwalten |
| [Stacks](Stacks) | Compose-Stacks anlegen, deployen, importieren |
| [SSH-Zugriff](SSH-Zugriff) | SSH-Server hinterlegen, Web-Konsole |
| [Benutzer und Rechte](Benutzer-und-Rechte) | Admins, Benutzer, Gruppen, Berechtigungen |
| [Registries und Zertifikate](Registries-und-Zertifikate) | Private Registries, HTTP-Registries, eigene CAs, mTLS |
| [TLS und Reverse Proxy](TLS-und-Reverse-Proxy) | HTTPS nativ oder per nginx/Caddy/Traefik |
| [Sicherheit](Sicherheit) | Selbstschutz, Sitzungen, Login-Drosselung, Import-Regeln |
| [Updates und Versionen](Updates-und-Versionen) | Update-Prüfung, Versionierung, CI |
| [Daten und Backup](Daten-und-Backup) | Dateien in `/data`, Sicherung, Wiederherstellung |
| [API](API) | Alle HTTP- und WebSocket-Endpunkte |
| [Fehlerbehebung](Fehlerbehebung) | Häufige Probleme und Lösungen |
