package web

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gorilla/mux"

	"dockpilot/internal/auth"
	"dockpilot/internal/users"
)

func userErrStatus(err error) int {
	switch {
	case errors.Is(err, users.ErrNotFound):
		return http.StatusNotFound
	case errors.Is(err, users.ErrExists):
		return http.StatusConflict
	case errors.Is(err, users.ErrLastAdmin):
		return http.StatusConflict
	case errors.Is(err, users.ErrGroupNotFound):
		return http.StatusNotFound
	case errors.Is(err, users.ErrGroupExists):
		return http.StatusConflict
	case errors.Is(err, users.ErrBadName), errors.Is(err, users.ErrBadRole), errors.Is(err, users.ErrShortPass),
		errors.Is(err, users.ErrGroupName), errors.Is(err, users.ErrBadPerm):
		return http.StatusBadRequest
	}
	return http.StatusInternalServerError
}

func handleUsersList(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}
	list := users.List()
	out := make([]map[string]interface{}, 0, len(list))
	for _, u := range list {
		out = append(out, map[string]interface{}{"username": u.Username, "role": u.Role, "groups": u.Groups})
	}
	jsonOK(w, out)
}

func handleUserCreate(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}
	var body struct {
		Username string   `json:"username"`
		Password string   `json:"password"`
		Role     string   `json:"role"`
		Groups   []string `json:"groups"`
	}
	if err := parseJSON(r, &body); err != nil {
		jsonErr(w, http.StatusBadRequest, "Ungültige Anfrage")
		return
	}
	if err := users.Create(body.Username, body.Password, body.Role, nil); err != nil {
		jsonErr(w, userErrStatus(err), err.Error())
		return
	}
	if body.Groups != nil {
		users.SetGroups(strings.TrimSpace(body.Username), body.Groups)
	}
	jsonOK(w, map[string]bool{"ok": true})
}

// handleUserUpdate ändert Rolle, Gruppen und/oder setzt das Passwort neu.
func handleUserUpdate(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}
	name := mux.Vars(r)["name"]
	var body struct {
		Password string    `json:"password"`
		Role     string    `json:"role"`
		Groups   *[]string `json:"groups"`
	}
	if err := parseJSON(r, &body); err != nil {
		jsonErr(w, http.StatusBadRequest, "Ungültige Anfrage")
		return
	}
	if users.Get(name) == nil {
		jsonErr(w, http.StatusNotFound, users.ErrNotFound.Error())
		return
	}
	if body.Role != "" {
		if err := users.SetRole(name, body.Role); err != nil {
			jsonErr(w, userErrStatus(err), err.Error())
			return
		}
	}
	if body.Groups != nil {
		if err := users.SetGroups(name, *body.Groups); err != nil {
			jsonErr(w, userErrStatus(err), err.Error())
			return
		}
	}
	if body.Password != "" {
		if err := users.SetPassword(name, body.Password); err != nil {
			jsonErr(w, userErrStatus(err), err.Error())
			return
		}
	}
	jsonOK(w, map[string]bool{"ok": true})
}

// ── Gruppen ───────────────────────────────────────────────────────────────────

func handleGroupsList(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}
	jsonOK(w, map[string]interface{}{"groups": users.Groups(), "permissions": users.Permissions})
}

func handleGroupSave(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}
	var g users.Group
	if err := parseJSON(r, &g); err != nil {
		jsonErr(w, http.StatusBadRequest, "Ungültige Anfrage")
		return
	}
	id := mux.Vars(r)["id"]
	var err error
	if id == "" {
		g, err = users.CreateGroup(g)
		id = g.ID
	} else {
		err = users.UpdateGroup(id, g)
	}
	if err != nil {
		jsonErr(w, userErrStatus(err), err.Error())
		return
	}
	jsonOK(w, map[string]interface{}{"ok": true, "id": id})
}

func handleGroupDelete(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}
	if err := users.DeleteGroup(mux.Vars(r)["id"]); err != nil {
		jsonErr(w, userErrStatus(err), err.Error())
		return
	}
	jsonOK(w, map[string]bool{"ok": true})
}

func handleUserDelete(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}
	name := mux.Vars(r)["name"]
	if me := auth.SessionUser(r); me != nil && me.Username == name {
		jsonErr(w, http.StatusConflict, "Du kannst dich nicht selbst löschen")
		return
	}
	if err := users.Delete(name); err != nil {
		jsonErr(w, userErrStatus(err), err.Error())
		return
	}
	jsonOK(w, map[string]bool{"ok": true})
}
