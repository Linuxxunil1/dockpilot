package web

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/gorilla/mux"

	"dockpilot/internal/docker"
	"dockpilot/internal/users"
)

// readCtx: Lesende Docker-Aufrufe enden mit der Anfrage, spätestens nach 2 min (Größen dauern lange).
func readCtx(r *http.Request) (context.Context, context.CancelFunc) {
	return context.WithTimeout(r.Context(), 2*time.Minute)
}

// actionCtx: Ändernde Aufrufe laufen zu Ende, auch wenn der Browser abbricht.
// Sonst bliebe z. B. ein Container-Update halb ausgeführt stehen.
func actionCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 10*time.Minute)
}

func handleContainers(w http.ResponseWriter, r *http.Request) {
	if !requireLocalPerm(w, r, users.PermContainersView) {
		return
	}
	ctx, cancel := readCtx(r)
	defer cancel()
	list, err := docker.ListContainers(ctx)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	jsonOK(w, list)
}

func handleHost(w http.ResponseWriter, r *http.Request) {
	if !requireLocalPerm(w, r, users.PermContainersView) {
		return
	}
	jsonOK(w, docker.GetHostStats())
}

func handleSizes(w http.ResponseWriter, r *http.Request) {
	if !requireLocalPerm(w, r, users.PermContainersView) {
		return
	}
	ctx, cancel := readCtx(r)
	defer cancel()
	sizes, err := docker.ContainerSizes(ctx)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	jsonOK(w, sizes)
}

func handleContainerAction(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	cid := vars["cid"]
	action := vars["action"]
	if !requireLocalPerm(w, r, containerActionPerm(action)) {
		return
	}
	ctx, cancel := actionCtx()
	defer cancel()
	if err := docker.ContainerAction(ctx, cid, action); err != nil {
		if errors.Is(err, docker.ErrSelf) {
			jsonErr(w, http.StatusForbidden, err.Error())
			return
		}
		jsonErr(w, http.StatusBadRequest, err.Error())
		return
	}
	jsonOK(w, map[string]bool{"ok": true})
}

func handleImages(w http.ResponseWriter, r *http.Request) {
	if !requireLocalPerm(w, r, users.PermImagesManage) {
		return
	}
	ctx, cancel := readCtx(r)
	defer cancel()
	list, err := docker.ListImages(ctx)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	jsonOK(w, list)
}

func handleImageDelete(w http.ResponseWriter, r *http.Request) {
	if !requireLocalPerm(w, r, users.PermImagesManage) {
		return
	}
	ctx, cancel := actionCtx()
	defer cancel()
	id := mux.Vars(r)["id"]
	if err := docker.DeleteImage(ctx, id); err != nil {
		jsonErr(w, http.StatusConflict, err.Error())
		return
	}
	jsonOK(w, map[string]bool{"ok": true})
}

func handleImagesPrune(w http.ResponseWriter, r *http.Request) {
	if !requireLocalPerm(w, r, users.PermImagesManage) {
		return
	}
	ctx, cancel := actionCtx()
	defer cancel()
	deleted, freed, err := docker.PruneImages(ctx)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	jsonOK(w, map[string]interface{}{"deleted": deleted, "freed": freed})
}
