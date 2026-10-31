package version

import (
	_ "embed"
	"strings"
)

// Die Version steht in der Datei VERSION und wird beim Build eingebettet.
// Für ein neues Release nur diese Datei anpassen (z. B. 0.2.0 → 0.2.1).
//
//go:embed VERSION
var raw string

var Version = strings.TrimSpace(raw)
