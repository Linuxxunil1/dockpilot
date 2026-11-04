# TLS und Reverse Proxy

DockPilot sollte nur über HTTPS erreichbar sein: Passwörter, Sitzungs-Cookie und Konsolen
laufen darüber.

## Variante 1: Reverse Proxy (empfohlen)

1. Port nur lokal binden: `127.0.0.1:8080:8080` (oder nur im Docker-Netz des Proxys).
2. TLS im Proxy terminieren.
3. Die Adresse des Proxys in `TRUSTED_PROXIES` eintragen.
4. **WebSockets** (`/ws/…`) durchreichen, sonst funktionieren die Konsolen nicht.

### Caddy

```caddy
dockpilot.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

Caddy reicht WebSockets automatisch durch. `TRUSTED_PROXIES=127.0.0.1` bzw. die IP des
Caddy-Containers setzen.

### nginx

```nginx
server {
    listen 443 ssl http2;
    server_name dockpilot.example.com;

    ssl_certificate     /etc/letsencrypt/live/dockpilot.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/dockpilot.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 1h;   # lange Konsolen-Sitzungen
    }
}
```

### Traefik (Labels)

```yaml
    labels:
      - traefik.enable=true
      - traefik.http.routers.dockpilot.rule=Host(`dockpilot.example.com`)
      - traefik.http.routers.dockpilot.entrypoints=websecure
      - traefik.http.routers.dockpilot.tls.certresolver=letsencrypt
      - traefik.http.services.dockpilot.loadbalancer.server.port=8080
    environment:
      - TRUSTED_PROXIES=172.18.0.0/16   # Subnetz des Traefik-Netzes
```

Ports dann ganz weglassen und DockPilot ins Netz von Traefik hängen. Traefik reicht WebSockets
automatisch durch.

## Variante 2: Natives HTTPS

`TLS_CERT` und `TLS_KEY` auf Zertifikat und Schlüssel (PEM, im Container eingebunden) setzen.
DockPilot lauscht dann auf `LISTEN_ADDR` mit HTTPS und sendet HSTS.

```yaml
    environment:
      - TLS_CERT=/certs/fullchain.pem
      - TLS_KEY=/certs/privkey.pem
    ports:
      - "8443:8080"
    volumes:
      - ./certs:/certs:ro
```

Diese Variante bietet sich vor allem für [Agents](Hub-und-Agents) an.

## Reines HTTP

Nur im vertrauenswürdigen Netz und mit `COOKIE_SECURE=false`, sonst setzt der Browser das
Sitzungs-Cookie nicht und die Anmeldung schlägt fehl.

## mTLS für Benutzer

Einen Setup-Schritt für Client-Zertifikate gibt es nicht. Client-Zertifikate bei Bedarf im
Reverse Proxy erzwingen.
