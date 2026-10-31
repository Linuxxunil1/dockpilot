package web

import (
	"embed"
	"io/fs"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/mux"

	"dockpilot/internal/config"
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

	// CrossOriginProtection lehnt zustandsändernde Anfragen anderer Seiten ab (CSRF),
	// auch von Nachbar-Subdomains. Hub → Agent (ohne Browser-Header) ist nicht betroffen.
	return securityHeaders(limitBody(http.NewCrossOriginProtection().Handler(r)))
}

// maxBodyBytes reicht für Compose-Dateien und Zertifikate.
const maxBodyBytes = 8 << 20

func limitBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
		}
		next.ServeHTTP(w, r)
	})
}

// Die Oberfläche nutzt Inline-Skripte und -Handler, deshalb 'unsafe-inline'.
// Alles andere kommt nur vom eigenen Server; Einbetten in fremde Seiten ist verboten.
const contentSecurityPolicy = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; " +
	"img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", contentSecurityPolicy)
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "same-origin")
		if r.TLS != nil {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		next.ServeHTTP(w, r)
	})
}

// Start startet den Server. Keine Read-/WriteTimeouts: Compose-Aktionen dauern bis zu
// 5 Minuten und Konsolen laufen beliebig lange. ReadHeaderTimeout reicht gegen Slowloris.
func Start(addr string) {
	srv := &http.Server{
		Addr:              addr,
		Handler:           NewRouter(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
	var err error
	if config.TLSCert != "" && config.TLSKey != "" {
		log.Printf("DockPilot läuft auf %s (HTTPS)", addr)
		err = srv.ListenAndServeTLS(config.TLSCert, config.TLSKey)
	} else {
		log.Printf("DockPilot läuft auf %s", addr)
		err = srv.ListenAndServe()
	}
	if err != nil {
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
