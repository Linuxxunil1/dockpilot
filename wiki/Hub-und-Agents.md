# Hub und Agents

Ein DockPilot im Modus **Hub** verwaltet weitere Docker-Hosts, auf denen DockPilot im Modus
**Agent** läuft. Container, Stacks, Images und Konsolen der Agents werden dann zentral im Hub
bedient.

## Funktionsweise

```
Browser ──HTTPS──▶ Hub ──HTTPS + Bearer-Token──▶ Agent ──▶ Docker-Socket
                    ▲                               │
                    └─────── Registrierung (60 s) ──┘
```

- Der Hub ruft die API des Agents auf und authentifiziert sich mit dem **Agent-Token**
  (`Authorization: Bearer …`).
- Der Agent meldet sich alle 60 s beim Hub (`POST /api/agents/register`) und übermittelt dabei
  seine URL.
- Konsolen in Containern auf Agents laufen als WebSocket über den Hub
  (`/ws/servers/{id}/container/{cid}`).
- Auf Agents gibt es **keine Benutzeranmeldung**. Rechte werden ausschließlich im Hub geprüft.

## Agent einrichten

1. Im Hub: **Server & Agents → „Agent einladen“** (nur Admins). Es wird ein Einladungs-Token erzeugt.
2. Auf dem Zielhost DockPilot wie unter [Installation](Installation) starten. Der Port muss für
   den Hub erreichbar sein, am besten mit nativem TLS:

   ```yaml
   services:
     dockpilot-agent:
       image: ghcr.io/linuxxunil1/dockpilot:latest
       container_name: dockpilot
       restart: unless-stopped
       security_opt:
         - no-new-privileges:true
       environment:
         - TLS_CERT=/certs/fullchain.pem
         - TLS_KEY=/certs/privkey.pem
         - AGENT_URL=https://agent1.example.com:8443
       ports:
         - "8443:8080"
       volumes:
         - /var/run/docker.sock:/var/run/docker.sock
         - dockpilot_stacks:/opt/dockpilot/stacks
         - dockpilot_data:/data
         - ./certs:/certs:ro
   volumes:
     dockpilot_stacks:
     dockpilot_data:
   ```

3. `/setup` auf dem Agent öffnen, Setup-Code eingeben, Modus **Agent** wählen und
   Hub-URL, Einladungs-Token und Namen eintragen.
4. Nach spätestens 60 s erscheint der Agent im Hub unter **Server & Agents** als „Online“.

Am besten den Port des Agents per Firewall nur für den Hub freigeben.

## Agent-Seite ohne Token

Ruft man die Adresse eines Agents im Browser auf, zeigt die Seite ohne Token nur, ob der Hub
erreichbar ist („Online“/„Offline“). Die Konfiguration lässt sich nur mit dem Agent-Token
anzeigen und ändern.

## Neue Agent-URL bestätigen

Meldet ein bereits registrierter Agent eine **neue URL**, übernimmt der Hub sie nicht
automatisch. In der Agent-Kachel erscheint „Agent meldet neue URL“ mit **Übernehmen** und
**Verwerfen**. Bestätigen kann nur ein Admin (`PATCH /api/servers/{id}` mit `confirm_url`
bzw. `reject_url`).

Nur übernehmen, wenn der Agent bewusst umgezogen ist. Eine unerwartete URL-Änderung kann auf
einen gestohlenen Agent-Token hindeuten.

## HTTPS zwischen Hub und Agent

- Für Agents immer HTTPS verwenden. Bei `http://` steht ein Hinweis im Log des Hubs.
- Bei selbst signierten Zertifikaten die CA per `AGENT_CA_FILE` einbinden:
  - auf dem **Hub**, damit er dem Agent vertraut,
  - auf dem **Agent**, damit er dem Hub bei der Registrierung vertraut.

```yaml
    environment:
      - AGENT_CA_FILE=/certs/ca.pem
    volumes:
      - ./certs/ca.pem:/certs/ca.pem:ro
```

## Registry-Daten auf Agents

Registry-Logins und Registry-Zertifikate werden vom Hub an die Agents übertragen
(siehe [Registries und Zertifikate](Registries-und-Zertifikate)). Beim Stack-Import auf einen Agent
lädt der Hub die Datei selbst herunter, gespeicherte Import-Tokens verlassen den Hub nicht.
