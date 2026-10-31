package config

import (
	"crypto/hmac"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// WriteFileAtomic schreibt erst in eine temporäre Datei im selben Verzeichnis und
// benennt sie dann um. Bei Absturz oder parallelem Lesen bleibt so nie eine halbe Datei stehen.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp) // nach erfolgreichem Rename ein No-op
	if err := f.Chmod(perm); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// setupToken schützt die Ersteinrichtung: Nur wer das Log des Containers lesen kann
// (oder SETUP_TOKEN gesetzt hat), darf den ersten Admin bzw. den Modus festlegen.
var setupToken = func() string {
	if v := strings.TrimSpace(os.Getenv("SETUP_TOKEN")); v != "" {
		return v
	}
	return randomHex(12)
}()

func SetupToken() string { return setupToken }

// ValidSetupToken vergleicht in konstanter Zeit.
func ValidSetupToken(t string) bool {
	return t != "" && hmac.Equal([]byte(strings.TrimSpace(t)), []byte(setupToken))
}

var registryHostRe = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9.-]{0,252})(:[0-9]{1,5})?$`)

// ValidRegistryHost prüft einen Eintrag wie "registry.local:5000" (ohne Schema und Pfad).
// Ungültige Einträge in daemon.json verhindern sonst den Start von dockerd.
func ValidRegistryHost(s string) bool {
	return registryHostRe.MatchString(s)
}
