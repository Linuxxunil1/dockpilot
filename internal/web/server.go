package web

import (
	"embed"
	"io/fs"
	"log"
	"net/http"

	"github.com/gorilla/mux"
)

//go:embed templates
var templateFS embed.FS

//go:embed static
var staticFS embed.FS

func NewRouter() http.Handler {
	r := mux.NewRouter()
	registerRoutes(r)

	// Static files
	staticSub, err := fs.Sub(staticFS, "static")
	if err == nil {
		r.PathPrefix("/static/").Handler(
			http.StripPrefix("/static/", http.FileServer(http.FS(staticSub))),
		)
	}

	return r
}

func Start(addr string) {
	h := NewRouter()
	log.Printf("DockPilot läuft auf %s", addr)
	if err := http.ListenAndServe(addr, h); err != nil {
		log.Fatalf("Server-Fehler: %v", err)
	}
}

func templateContent(name string) string {
	data, err := templateFS.ReadFile("templates/" + name)
	if err != nil {
		log.Printf("Template %q nicht gefunden: %v", name, err)
		return ""
	}
	return string(data)
}
