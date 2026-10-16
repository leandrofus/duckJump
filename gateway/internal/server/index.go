package server

import (
	_ "embed"
	"io/fs"
	"net/http"
	"strings"

	"github.com/leandrofus/palta/gateway/internal/server/ui"
)

//go:embed web/index.html
var pocHTML []byte

// The built UI loads nothing from other origins; inline styles are used by
// React components and the recording player.
// 'wasm-unsafe-eval' lets the recording player compile its WebAssembly
// terminal parser; it does not allow eval().
const uiCSP = "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; " +
	"font-src 'self' data:; connect-src 'self'; worker-src 'self' blob:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"

// static serves the React UI (or the PoC viewer when the UI was not built).
func (s *Server) static() http.Handler {
	return getOnly(s.files())
}

func getOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) files() http.Handler {
	dist := ui.FS()
	if dist == nil {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/" {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write(pocHTML)
		})
	}
	files := http.FileServerFS(dist)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", uiCSP)
		p := strings.TrimPrefix(r.URL.Path, "/")
		if p == "" || p == "index.html" {
			w.Header().Set("Cache-Control", "no-cache")
			http.ServeFileFS(w, r, dist, "index.html")
			return
		}
		if _, err := fs.Stat(dist, p); err != nil {
			http.NotFound(w, r)
			return
		}
		if strings.HasPrefix(p, "assets/") {
			// Vite fingerprints these file names.
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		}
		files.ServeHTTP(w, r)
	})
}
