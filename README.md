# dockpilot — eigenes Docker-Management-Dashboard

Schlankes, selbst geschriebenes Web-Dashboard (FastAPI + Docker SDK) zum
Verwalten der Container auf diesem Host. Kein Portainer, keine externe
Abhängigkeit — der komplette Code liegt in `app/main.py`.

- **URL:** https://dockpilot.linus-hub.de
- **Login:** `admin` + Passwort aus `.env` (`DASH_PASSWORD`)
- **Reverse-Proxy:** vorhandener Traefik (Netzwerk `proxy`), HTTPS via Let's Encrypt
- **Container-Name:** `dockpilot`

## Schnellstart

`.env` und `certs/` sind aus dem Repo ausgeschlossen (enthalten Geheimnisse) und
müssen lokal erzeugt werden:

```bash
# 1. Zugangsdaten anlegen
cp .env.example .env
sed -i "s|^DASH_PASSWORD=.*|DASH_PASSWORD=$(openssl rand -base64 12)|" .env
sed -i "s|^DASH_SECRET=.*|DASH_SECRET=$(openssl rand -hex 32)|" .env

# 2. Starten (hinter einem Traefik im Netzwerk 'proxy')
docker compose up -d --build
```

Den Host (`dockpilot.linus-hub.de`) und den Cert-Resolver in
`docker-compose.yaml` ggf. an die eigene Umgebung anpassen. Die optionalen
mTLS-Zertifikate erzeugt man wie im Abschnitt unten beschrieben.

## Funktionen

- **Host-Übersicht** oben: CPU-Last (+ Load/Kerne), RAM, Festplatte (Root-FS),
  Uptime und Docker-Speicherverbrauch (Images/Container/Volumes/Build-Cache)
- Container-Übersicht (laufend/gestoppt) mit Image und Compose-Projekt-Tag
- Live-Stats pro Container: CPU %, RAM % + absolut, **Speicher** (Writable-Layer
  + gesamt inkl. Image), Netz I/O (Auto-Refresh 5 s, Größen alle 30 s)
- **Start / Stop / Restart** per Button
- **Update**: zieht das Image neu und erstellt den Container mit identischer
  Config neu (Volumes, Env, Ports, Netzwerke, Restart-Policy bleiben erhalten —
  Watchtower-Prinzip). Named Volumes bleiben bestehen, es gehen keine Daten verloren.
- Login mit signiertem Session-Cookie (HMAC, 7 Tage gültig)

## Aufbau

```
dockpilot/
├── app/
│   ├── main.py            # Backend + eingebettetes Frontend
│   ├── requirements.txt
│   └── Dockerfile
├── docker-compose.yaml
├── .env                   # DASH_USER / DASH_PASSWORD / DASH_SECRET  (geheim!)
├── certs/                 # mTLS-Material (optional, siehe unten)
└── mtls.snippet.yaml
```

## Verwaltung

```bash
cd /root/docker-compose/dockpilot
docker compose up -d --build      # nach Code-Änderung neu bauen + starten
docker compose logs -f
docker compose down               # stoppen
```

Passwort ändern: Wert in `.env` (`DASH_PASSWORD`) anpassen, dann
`docker compose up -d`. Ein geändertes `DASH_SECRET` invalidiert alle Sessions.

## Sicherheitshinweis zu „Update"

Die meisten Container hier sind Compose-verwaltet (matrix, ticket, …). Der
Update-Button erstellt den Container am Docker-Layer neu und erhält dabei die
Compose-Labels, d.h. `docker compose` erkennt ihn weiterhin. Für Dienste, deren
Image lokal **gebaut** wird (z.B. `ticket-backend-web`), zieht „Update" nur ein
ggf. vorhandenes Remote-Image — neu bauen aus Quellcode macht weiterhin
`docker compose build`. Bei Datenbank-Containern (postgres) wie immer vorher ein
Backup, bevor das Image-Tag wechselt.

## Optional: mTLS-Client-Zertifikatsauth (zusätzliche Schicht)

Zwingt den Browser, ein Client-Zertifikat vorzuweisen, bevor überhaupt die
Loginseite erscheint. Material liegt in `certs/` bereit:

- `client.p12` — in Browser/OS importieren (Passwort: `certs/p12-password.txt`)
- `ca.crt` — schon nach `traefik/dynamic/dockpilot-ca.crt` kopiert

**Aktivieren (Reihenfolge wichtig, sonst sperrst du dich aus):**

1. `certs/client.p12` im Browser importieren.
2. Den `mtls`-Block aus `mtls.snippet.yaml` in
   `/root/docker-compose/traefik/dynamic/tls.yaml` einfügen (Hot-Reload).
3. In `docker-compose.yaml` die Zeile entkommentieren:
   `- "traefik.http.routers.dockpilot.tls.options=mtls@file"`
4. `docker compose up -d`

**Deaktivieren:** Schritt 3 rückgängig + `up -d`.

> Geheim halten: `.env`, `certs/*.key`, `certs/*.p12`, `certs/p12-password.txt`.
