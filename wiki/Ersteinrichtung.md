# Ersteinrichtung

Beim ersten Aufruf leitet DockPilot auf `/setup` weiter. Der Setup-Wizard legt den ersten
Admin und den Betriebsmodus fest.

## Setup-Code

Die Einrichtung ist durch einen **Setup-Code** geschützt, damit niemand anderes eine frisch
gestartete Instanz übernehmen kann. Der Code steht beim Start im Log:

```bash
docker logs dockpilot
# Ersteinrichtung: Setup-Code … (im Browser unter /setup eingeben)
```

- Ohne `SETUP_TOKEN` wird der Code bei jedem Start neu erzeugt.
- Mit `SETUP_TOKEN` legt man ihn selbst fest (praktisch für automatisierte Installationen).

## Ablauf

1. Setup-Code eingeben
2. Ersten Admin anlegen (Benutzername und Passwort)
3. Betriebsmodus wählen

## Betriebsmodi

| Modus | Beschreibung |
|---|---|
| **Standalone** | Verwaltet nur den eigenen Docker-Host. Standard. |
| **Hub** | Verwaltet den eigenen Host und zusätzlich Agents und SSH-Server. |
| **Agent** | Wird von einem Hub verwaltet. Keine eigene Anmeldung, die Steuerung erfolgt nur über den Hub. |

Für den Agent-Modus werden beim Setup die URL des Hubs, der Einladungs-Token und ein Name
eingegeben. Details unter [Hub und Agents](Hub-und-Agents).

Der Modus wird in `/data/mode.json` gespeichert.

## Einrichtung erneut durchführen

Die Einrichtung startet erneut, wenn `/data/mode.json` fehlt (bzw. im Agent-Modus kein
Agent-Token hinterlegt ist). Um eine Instanz komplett zurückzusetzen:

```bash
docker compose down
docker volume rm <projekt>_dockpilot_data
docker compose up -d
```

> Dabei gehen alle Benutzer, Server, Tokens und Schlüssel verloren. Vorher ein
> [Backup](Daten-und-Backup) anlegen.
