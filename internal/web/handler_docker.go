package web

import (
	"context"
	"net/http"

	"github.com/gorilla/mux"

	"dockpilot/internal/docker"
	"dockpilot/internal/users"
)

func handleContainers(w http.ResponseWriter, r *http.Request) {
	if !requireLocalPerm(w, r, users.PermContainersView) {
		return
	}
	list, err := docker.ListContainers(context.Background())
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
	sizes, err := docker.ContainerSizes(context.Background())
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
	if err := docker.ContainerAction(context.Background(), cid, action); err != nil {
		jsonErr(w, http.StatusBadRequest, err.Error())
		return
	}
	jsonOK(w, map[string]bool{"ok": true})
}

func handleImages(w http.ResponseWriter, r *http.Request) {
	if !requireLocalPerm(w, r, users.PermImagesManage) {
		return
	}
	list, err := docker.ListImages(context.Background())
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
	id := mux.Vars(r)["id"]
	if err := docker.DeleteImage(context.Background(), id); err != nil {
		jsonErr(w, http.StatusConflict, err.Error())
		return
	}
	jsonOK(w, map[string]bool{"ok": true})
}

func handleImagesPrune(w http.ResponseWriter, r *http.Request) {
	if !requireLocalPerm(w, r, users.PermImagesManage) {
		return
	}
	deleted, freed, err := docker.PruneImages(context.Background())
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	jsonOK(w, map[string]interface{}{"deleted": deleted, "freed": freed})
}
