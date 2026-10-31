package users

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"

	"golang.org/x/crypto/bcrypt"

	"dockpilot/internal/config"
)

const (
	RoleAdmin = "admin"
	RoleUser  = "user"
)

type User struct {
	Username     string `json:"username"`
	PasswordHash string `json:"password_hash"`
	Role         string `json:"role"`
	// Groups enthält Gruppen-IDs. nil heißt: Daten von vor den Gruppen, siehe load.
	Groups []string `json:"groups"`
	// SessionNonce steckt signiert im Session-Cookie. Ein neuer Wert macht alle Sitzungen
	// ungültig – zufällig statt Zähler, damit ein gleichnamig neu angelegter Benutzer
	// keine alten Cookies erbt.
	SessionNonce string `json:"session_nonce,omitempty"`
}

func (u User) IsAdmin() bool { return u.Role == RoleAdmin }

var (
	mu        sync.Mutex
	dummyOnce sync.Once
	dummyHash []byte

	ErrNotFound   = errors.New("Benutzer nicht gefunden")
	ErrExists     = errors.New("Benutzer existiert bereits")
	ErrLastAdmin  = errors.New("Der letzte Admin kann nicht entfernt oder herabgestuft werden")
	ErrBadName    = errors.New("Benutzername ungültig (1–64 Zeichen, keine Leerzeichen)")
	ErrBadRole    = errors.New("Ungültige Rolle")
	ErrShortPass  = errors.New("Passwort muss mindestens 8 Zeichen haben")
	ErrCorrupt    = errors.New("Benutzerdatei unlesbar – bitte users.json prüfen")
	errNoMigrated = errors.New("keine Altdaten")
)

// load liest users.json. Fehlt die Datei, werden die alten Einzel-Zugangsdaten
// aus credentials.json als Admin übernommen. Ist die Datei unlesbar, gibt es ErrCorrupt,
// damit sie weder überschrieben wird noch die Ersteinrichtung wieder aufgeht. Aufrufer muss mu halten.
func load() ([]User, error) {
	data, err := os.ReadFile(config.UsersFile)
	if err != nil && !os.IsNotExist(err) {
		return nil, ErrCorrupt
	}
	if err == nil {
		var list []User
		if json.Unmarshal(data, &list) != nil {
			return nil, ErrCorrupt
		}
		// Bestehende Benutzer behalten über die Gruppe "Standard" ihre bisherigen Rechte.
		for i := range list {
			if list[i].Groups == nil {
				list[i].Groups = []string{}
				if !list[i].IsAdmin() {
					list[i].Groups = []string{DefaultGroupID}
				}
			}
		}
		return list, nil
	}
	if list, err := migrateLegacy(); err == nil {
		return list, nil
	}
	return nil, nil
}

func migrateLegacy() ([]User, error) {
	if _, err := os.Stat(config.CredsFile); err != nil {
		return nil, errNoMigrated
	}
	creds, err := config.LoadCreds()
	if err != nil || creds.User == "" || creds.Password == "" {
		return nil, errNoMigrated
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(creds.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	list := []User{{Username: creds.User, PasswordHash: string(hash), Role: RoleAdmin}}
	if err := save(list); err != nil {
		return nil, err
	}
	// Klartext-Passwort entfernen, Secret für Session-Signaturen behalten.
	creds.User, creds.Password = "", ""
	config.SaveCreds(creds)
	return list, nil
}

func save(list []User) error {
	data, _ := json.MarshalIndent(list, "", "  ")
	return config.WriteFileAtomic(config.UsersFile, data, 0600)
}

func adminCount(list []User) int {
	n := 0
	for _, u := range list {
		if u.IsAdmin() {
			n++
		}
	}
	return n
}

func validName(name string) bool {
	return name != "" && len(name) <= 64 && !strings.ContainsAny(name, " \t\r\n")
}

func validRole(role string) bool { return role == RoleAdmin || role == RoleUser }

// List gibt alle Benutzer zurück (inkl. Hash – nicht direkt an Clients ausgeben).
func List() []User {
	mu.Lock()
	defer mu.Unlock()
	list, _ := load()
	return list
}

// Any meldet, ob mindestens ein Benutzer existiert. Eine vorhandene, aber
// unlesbare users.json zählt als "ja", damit die Ersteinrichtung zu bleibt.
func Any() bool {
	if _, err := os.Stat(config.UsersFile); err == nil {
		return true
	}
	return len(List()) > 0
}

func Get(name string) *User {
	for _, u := range List() {
		if u.Username == name {
			cp := u
			return &cp
		}
	}
	return nil
}

// Authenticate prüft Benutzername und Passwort.
func Authenticate(name, password string) *User {
	u := Get(name)
	if u == nil {
		// Gleiche Laufzeit wie bei existierendem Benutzer.
		dummyOnce.Do(func() { dummyHash, _ = bcrypt.GenerateFromPassword([]byte("dummy-password"), bcrypt.DefaultCost) })
		bcrypt.CompareHashAndPassword(dummyHash, []byte(password))
		return nil
	}
	if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)) != nil {
		return nil
	}
	return u
}

func Create(name, password, role string, groups []string) error {
	name = strings.TrimSpace(name)
	if !validName(name) {
		return ErrBadName
	}
	if !validRole(role) {
		return ErrBadRole
	}
	if len(password) < 8 {
		return ErrShortPass
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	mu.Lock()
	defer mu.Unlock()
	list, err := load()
	if err != nil {
		return err
	}
	for _, u := range list {
		if u.Username == name {
			return ErrExists
		}
	}
	if groups == nil {
		groups = []string{}
	}
	return save(append(list, User{Username: name, PasswordHash: string(hash), Role: role, Groups: groups, SessionNonce: newNonce()}))
}

func SetPassword(name, password string) error {
	if len(password) < 8 {
		return ErrShortPass
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	mu.Lock()
	defer mu.Unlock()
	list, err := load()
	if err != nil {
		return err
	}
	for i := range list {
		if list[i].Username == name {
			list[i].PasswordHash = string(hash)
			// Neues Passwort beendet alle bestehenden Sitzungen.
			list[i].SessionNonce = newNonce()
			return save(list)
		}
	}
	return ErrNotFound
}

func newNonce() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func SetRole(name, role string) error {
	if !validRole(role) {
		return ErrBadRole
	}
	mu.Lock()
	defer mu.Unlock()
	list, err := load()
	if err != nil {
		return err
	}
	for i := range list {
		if list[i].Username == name {
			if list[i].IsAdmin() && role != RoleAdmin && adminCount(list) == 1 {
				return ErrLastAdmin
			}
			list[i].Role = role
			return save(list)
		}
	}
	return ErrNotFound
}

func Delete(name string) error {
	mu.Lock()
	defer mu.Unlock()
	list, err := load()
	if err != nil {
		return err
	}
	for i, u := range list {
		if u.Username == name {
			if u.IsAdmin() && adminCount(list) == 1 {
				return ErrLastAdmin
			}
			return save(append(list[:i], list[i+1:]...))
		}
	}
	return ErrNotFound
}

// SetGroups ersetzt die Gruppen eines Benutzers. Unbekannte Gruppen-IDs werden verworfen.
func SetGroups(name string, groups []string) error {
	mu.Lock()
	defer mu.Unlock()
	known := map[string]bool{}
	for _, g := range loadGroups() {
		known[g.ID] = true
	}
	clean := []string{}
	for _, id := range groups {
		if known[id] {
			clean = append(clean, id)
		}
	}
	list, err := load()
	if err != nil {
		return err
	}
	for i := range list {
		if list[i].Username == name {
			list[i].Groups = clean
			return save(list)
		}
	}
	return ErrNotFound
}

// EndSessions macht alle Sitzungen des Benutzers ungültig (Abmelden auf allen Geräten).
func EndSessions(name string) error {
	mu.Lock()
	defer mu.Unlock()
	list, err := load()
	if err != nil {
		return err
	}
	for i := range list {
		if list[i].Username == name {
			list[i].SessionNonce = newNonce()
			return save(list)
		}
	}
	return ErrNotFound
}
