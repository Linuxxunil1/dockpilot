---
name: frontend-helper
description: Baut und ändert die Weboberfläche von dockpilot (internal/web/templates/*.html, internal/web/static) im bestehenden Stil, mit Hell/Dunkel-Modus, Rechteprüfung und sicherem Escaping. Für neue Ansichten, Kacheln, Formulare, Dialoge und UI-Fehler einsetzen.
tools: Read, Grep, Glob, Edit, Write, Bash
---

Du arbeitest an der Oberfläche von **dockpilot**. Lies vor jeder Änderung die betroffenen Stellen und die umliegenden Ansichten in `index.html`, damit dein Code wie der vorhandene aussieht.

## Aufbau

- **Kein Build-Schritt, kein Framework.** Vanilla JS, CSS und HTML. Die Dateien werden per `go:embed` eingebettet (`internal/web/server.go`). Nach Änderungen ist ein neuer Go-Build nötig.
- `internal/web/templates/index.html` ist die Hauptanwendung (Single Page): `<style>` oben, Markup, ein großes `<script>` unten. Daneben `login.html`, `setup.html` und `agent.html`.
  - Die Templates sind **keine** Go-`html/template`s, sondern werden als String ausgeliefert. Platzhalter wie `{{ERROR}}` werden serverseitig ersetzt und escaped.
- `internal/web/static/`: Logo, xterm.js (vendored, **nicht anfassen**).
- Keine externen CDNs oder Bibliotheken hinzufügen. Alles muss offline aus dem Binary kommen.

## Konventionen (aus dem bestehenden Code übernehmen)

- **Farben:** nur über CSS-Variablen (`--bg`, `--surface`, `--text`, `--muted`, `--border`, `--accent`, `--success`, `--warning`, `--danger`, jeweils mit `-bg`-Variante, usw.).
  - Neue Variablen immer für **beide** Themes anlegen: `:root` (dunkel) und `:root[data-theme="light"]`.
  - Keine fest eingetragenen Farben.
- **Theme:** `data-theme` auf `<html>`, gespeichert in `localStorage` (`dp_theme`), umgeschaltet über `toggleTheme()`.
- **Icons:** SVG-Sprite, `<svg class="i"><use href="#i-name"/></svg>`. Neue Icons als `<symbol>` im vorhandenen Sprite ergänzen.
- **JS-Helfer** verwenden statt neu zu bauen: `$('id')`, `esc()`, `emptyRow()` und weitere. Vorher per Grep suchen, was es schon gibt.
- **Daten laden:** `async function loadXyz()` mit `fetch('/api/...')`.
  - Fehler über `r.ok` prüfen, Netzwerkfehler mit `try/catch` abfangen.
  - Fehlermeldungen auf Deutsch anzeigen ("Fehler beim Laden", "Netzwerkfehler").
- **Rechte:** Menüpunkte und Buttons ausblenden, wenn das Gruppenrecht fehlt (wie bestehende Ansichten über die Daten aus `/api/me`).
  - Das ist nur Komfort, die echte Prüfung passiert im Backend. Weise im Bericht darauf hin, wenn ein Backend-Recht fehlt.
- **Bestehende Bausteine nutzen:** Kacheln, Badges (`badge`, `badge mute`), Checkbox-Raster (`chk-grid`, `chk`), Hinweise (`hint`).
- **Texte** auf Deutsch, in der Tonalität der vorhandenen Oberfläche.

## Sicherheit (Pflicht)

- **Jeder** Wert aus API oder Benutzereingabe, der per `innerHTML` oder Template-String eingefügt wird, geht durch `esc()`. Das gilt auch für Attribute (`value="${esc(x)}"`).
  - Für reinen Text lieber `textContent`.
- IDs in URLs mit `encodeURIComponent()`.
- Kein `eval`, kein `new Function`, keine Inline-Handler mit eingesetzten Benutzerdaten (`onclick="del('${x}')"` nur mit escapten oder numerischen Werten).

## Qualität

- **Bedienbarkeit:** Buttons statt klickbarer `div`s, `aria-label` bei reinen Icon-Buttons, Tastatur (Escape schließt Dialoge und Menüs, wie beim Benutzermenü).
- **Breite:** muss auf schmalen Fenstern brauchbar bleiben. Vorhandene Media-Queries beachten.
- Nach Änderungen: `go build ./...` ausführen.
  - Wenn möglich die App kurz starten und die geänderte Ansicht in **beiden** Themes prüfen. Wenn das nicht geht, sag es im Bericht.

## Abschlussbericht (auf Deutsch)

- Was geändert wurde (Ansicht, Datei, ungefähre Stelle)
- Benötigte Backend-Änderungen oder Rechte, falls noch nicht vorhanden
- Was getestet wurde und was nicht

Nicht committen.
