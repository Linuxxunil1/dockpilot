# SSH-Zugriff

Unter **SSH-Zugriff** (Hub-Modus) lassen sich beliebig viele SSH-Server hinterlegen und per Klick
eine Web-Konsole (xterm.js) darauf öffnen, ohne separate SSH-Client-Software.

## Anmeldearten

- **Schlüssel**: privater Schlüssel, optional mit Passphrase
- **Schlüssel + OpenSSH-Zertifikat**: zusätzlich das signierte Zertifikat (`id_ed25519-cert.pub`)
- **Passwort**

Die Zugangsdaten werden in `/data/servers.json` gespeichert (Dateirechte `0600`).
Das Daten-Volume deshalb wie ein Schlüsselbund behandeln.

## Host-Key prüfen

1. Beim Anlegen mit **„Abrufen“** den Host-Key-Fingerprint (`SHA256:…`) holen
   (`POST /api/servers/host-key`, nur Admins).
2. Mit dem Fingerprint auf dem Server vergleichen:

   ```bash
   ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
   ```

3. Speichern. Der Fingerprint ist dann fest hinterlegt, abweichende Host-Keys werden abgelehnt.

Ohne Fingerprint gilt der Host-Key der ersten Verbindung (Trust on first use). Er wird in
`/data/known_hosts.json` gespeichert. Ändert sich der Host-Key bewusst (z. B. Neuinstallation),
lässt er sich zurücksetzen (`DELETE /api/servers/{id}/known-host`).

## Rechte

Für Benutzer ist das Recht `ssh.console` nötig, und der SSH-Server muss in einer ihrer Gruppen
freigegeben sein (siehe [Benutzer und Rechte](Benutzer-und-Rechte)).

## Reverse Proxy

Die Konsole läuft über einen WebSocket (`/ws/ssh/{id}`). Der Reverse Proxy muss WebSockets
durchreichen (siehe [TLS und Reverse Proxy](TLS-und-Reverse-Proxy)).
