package users

import (
	"encoding/json"
	"errors"
	"os"
	"strings"

	"github.com/google/uuid"

	"dockpilot/internal/config"
)

// Berechtigungen, die Gruppen vergeben können. Admins haben immer alle.
const (
	PermContainersView    = "containers.view"
	PermContainersControl = "containers.control"
	PermContainersUpdate  = "containers.update"
	PermContainersExec    = "containers.exec"
	PermStacksView        = "stacks.view"
	PermStacksControl     = "stacks.control"
	PermStacksEdit        = "stacks.edit"
	PermImagesManage      = "images.manage"
	PermSSHConsole        = "ssh.console"
)

type Permission struct {
	ID    string `json:"id"`
	Area  string `json:"area"`
	Label string `json:"label"`
}

var Permissions = []Permission{
	{PermContainersView, "Container", "Container und Host-Auslastung ansehen"},
	{PermContainersControl, "Container", "Container starten, stoppen, neu starten"},
	{PermContainersUpdate, "Container", "Container-Image aktualisieren"},
	{PermContainersExec, "Container", "Konsole im Container öffnen (volle Shell – kommt Root auf dem Host gleich)"},
	{PermStacksView, "Stacks", "Stacks, Compose-Dateien und Logs ansehen"},
	{PermStacksControl, "Stacks", "Stacks deployen und herunterfahren"},
	{PermStacksEdit, "Stacks", "Stacks anlegen, bearbeiten, importieren, pullen, löschen (mit Deployen: Root auf dem Host)"},
	{PermImagesManage, "System", "Images ansehen, löschen und aufräumen"},
	{PermSSHConsole, "System", "SSH-Konsole auf freigegebenen SSH-Servern"},
}

// ServerLocal steht für den Server, auf dem DockPilot selbst läuft; ServerAll für alle Server.
const (
	ServerLocal = "local"
	ServerAll   = "*"
	// DefaultGroupID bekommen bestehende Benutzer bei der Umstellung auf Gruppen.
	DefaultGroupID = "standard"
)

type Group struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Permissions []string `json:"permissions"`
	Servers     []string `json:"servers"`
}

var (
	ErrGroupNotFound = errors.New("Gruppe nicht gefunden")
	ErrGroupExists   = errors.New("Gruppe existiert bereits")
	ErrGroupName     = errors.New("Gruppenname ungültig (1–64 Zeichen)")
	ErrBadPerm       = errors.New("Unbekannte Berechtigung")
)

// loadGroups liest groups.json. Fehlt die Datei, wird die Gruppe "Standard" mit den
// bisherigen Benutzerrechten auf allen Servern angelegt. Aufrufer muss mu halten.
func loadGroups() []Group {
	data, err := os.ReadFile(config.GroupsFile)
	if err == nil {
		var list []Group
		if json.Unmarshal(data, &list) != nil {
			groupsCorrupt = true
			return nil
		}
		groupsCorrupt = false
		return list
	}
	if !os.IsNotExist(err) {
		groupsCorrupt = true
		return nil
	}
	list := []Group{{
		ID:          DefaultGroupID,
		Name:        "Standard",
		Permissions: []string{PermContainersView, PermContainersControl, PermStacksView, PermStacksControl},
		Servers:     []string{ServerAll},
	}}
	saveGroups(list)
	return list
}

// groupsCorrupt verhindert, dass eine unlesbare groups.json beim Speichern überschrieben wird.
var groupsCorrupt bool

func saveGroups(list []Group) error {
	if groupsCorrupt {
		return errors.New("Gruppendatei unlesbar – bitte groups.json prüfen")
	}
	data, _ := json.MarshalIndent(list, "", "  ")
	return config.WriteFileAtomic(config.GroupsFile, data, 0600)
}

func validPerms(perms []string) bool {
	for _, p := range perms {
		ok := false
		for _, k := range Permissions {
			if k.ID == p {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

func cleanGroup(g *Group) error {
	g.Name = strings.TrimSpace(g.Name)
	if g.Name == "" || len(g.Name) > 64 {
		return ErrGroupName
	}
	if !validPerms(g.Permissions) {
		return ErrBadPerm
	}
	if g.Permissions == nil {
		g.Permissions = []string{}
	}
	if g.Servers == nil {
		g.Servers = []string{}
	}
	return nil
}

func Groups() []Group {
	mu.Lock()
	defer mu.Unlock()
	return loadGroups()
}

func CreateGroup(g Group) (Group, error) {
	if err := cleanGroup(&g); err != nil {
		return g, err
	}
	mu.Lock()
	defer mu.Unlock()
	list := loadGroups()
	for _, x := range list {
		if strings.EqualFold(x.Name, g.Name) {
			return g, ErrGroupExists
		}
	}
	g.ID = uuid.New().String()
	return g, saveGroups(append(list, g))
}

func UpdateGroup(id string, g Group) error {
	if err := cleanGroup(&g); err != nil {
		return err
	}
	mu.Lock()
	defer mu.Unlock()
	list := loadGroups()
	idx := -1
	for i, x := range list {
		if x.ID == id {
			idx = i
		} else if strings.EqualFold(x.Name, g.Name) {
			return ErrGroupExists
		}
	}
	if idx < 0 {
		return ErrGroupNotFound
	}
	g.ID = id
	list[idx] = g
	return saveGroups(list)
}

// DeleteGroup entfernt die Gruppe und ihre Zuordnung bei allen Benutzern.
func DeleteGroup(id string) error {
	mu.Lock()
	defer mu.Unlock()
	list := loadGroups()
	out := list[:0]
	for _, g := range list {
		if g.ID != id {
			out = append(out, g)
		}
	}
	if len(out) == len(list) {
		return ErrGroupNotFound
	}
	if err := saveGroups(out); err != nil {
		return err
	}
	ul, err := load()
	if err != nil {
		return err
	}
	for i := range ul {
		ul[i].Groups = without(ul[i].Groups, id)
	}
	return save(ul)
}

func without(list []string, v string) []string {
	out := []string{}
	for _, x := range list {
		if x != v {
			out = append(out, x)
		}
	}
	return out
}

// Access fasst die effektiven Rechte eines Benutzers aus allen seinen Gruppen zusammen.
type Access struct {
	Permissions []string `json:"permissions"`
	Servers     []string `json:"servers"`
}

func (u User) Access() Access {
	a := Access{Permissions: []string{}, Servers: []string{}}
	if u.IsAdmin() {
		for _, p := range Permissions {
			a.Permissions = append(a.Permissions, p.ID)
		}
		a.Servers = []string{ServerAll}
		return a
	}
	seenP, seenS := map[string]bool{}, map[string]bool{}
	for _, g := range Groups() {
		member := false
		for _, id := range u.Groups {
			if id == g.ID {
				member = true
				break
			}
		}
		if !member {
			continue
		}
		for _, p := range g.Permissions {
			if !seenP[p] {
				seenP[p] = true
				a.Permissions = append(a.Permissions, p)
			}
		}
		for _, s := range g.Servers {
			if !seenS[s] {
				seenS[s] = true
				a.Servers = append(a.Servers, s)
			}
		}
	}
	return a
}

func (a Access) Can(perm string) bool {
	for _, p := range a.Permissions {
		if p == perm {
			return true
		}
	}
	return false
}

func (a Access) CanServer(id string) bool {
	for _, s := range a.Servers {
		if s == ServerAll || s == id {
			return true
		}
	}
	return false
}
