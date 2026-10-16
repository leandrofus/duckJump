package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// SSOResult contains credentials or tokens obtained from an SSO login flow.
type SSOResult struct {
	Token    string
	Username string
	Email    string
}

// OpenBrowser opens the specified URL in the user's default browser.
func OpenBrowser(targetURL string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("cmd", "/c", "start", strings.ReplaceAll(targetURL, "&", "^&"))
	case "darwin":
		cmd = exec.Command("open", targetURL)
	default:
		cmd = exec.Command("xdg-open", targetURL)
	}
	return cmd.Start()
}

// LaunchSSO orchestrates an interactive Single Sign-On flow with the gateway.
func LaunchSSO(ctx context.Context, serverURL, loginURL string) (*SSOResult, error) {
	if loginURL == "" {
		loginURL = "/api/v1/auth/oidc/login"
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("no se pudo abrir puerto local para SSO: %w", err)
	}
	defer listener.Close()

	port := listener.Addr().(*net.TCPAddr).Port
	callbackURL := fmt.Sprintf("http://127.0.0.1:%d/callback", port)

	stateBytes := make([]byte, 16)
	_, _ = rand.Read(stateBytes)
	state := hex.EncodeToString(stateBytes)

	fullLoginURL := fmt.Sprintf("%s%s?redirect_uri=%s&state=%s",
		strings.TrimRight(serverURL, "/"),
		loginURL,
		url.QueryEscape(callbackURL),
		state,
	)

	resultChan := make(chan *SSOResult, 1)
	errChan := make(chan error, 1)

	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get("token")
		user := r.URL.Query().Get("user")
		email := r.URL.Query().Get("email")

		// If returned via session cookie
		if token == "" {
			for _, cookie := range r.Cookies() {
				if cookie.Name == "duckjump_session" || cookie.Name == "duckjump_oidc" {
					token = cookie.Value
				}
			}
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>duckJump Assist — SSO</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background: #0f172a; color: #f8fafc; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
    .card { background: #1e293b; padding: 32px 48px; border-radius: 12px; box-shadow: 0 10px 25px rgba(0,0,0,0.5); text-align: center; border: 1px solid #334155; }
    h2 { color: #38bdf8; margin-top: 0; }
    p { color: #94a3b8; font-size: 15px; }
  </style>
</head>
<body>
  <div class="card">
    <h2>🦆 Autenticación Exitosa</h2>
    <p>Su sesión ha sido confirmada correctamente.</p>
    <p>Ya puede cerrar esta pestaña del navegador y volver a <strong>duckJump Assist</strong>.</p>
  </div>
</body>
</html>`)

		resultChan <- &SSOResult{
			Token:    token,
			Username: user,
			Email:    email,
		}
	})

	srv := &http.Server{Handler: mux}
	go func() {
		_ = srv.Serve(listener)
	}()

	if err := OpenBrowser(fullLoginURL); err != nil {
		return nil, fmt.Errorf("error al abrir el navegador: %w", err)
	}

	select {
	case res := <-resultChan:
		_ = srv.Shutdown(context.Background())
		return res, nil
	case err := <-errChan:
		_ = srv.Shutdown(context.Background())
		return nil, err
	case <-time.After(3 * time.Minute):
		_ = srv.Shutdown(context.Background())
		return nil, fmt.Errorf("tiempo de espera agotado para el inicio de sesión SSO")
	case <-ctx.Done():
		_ = srv.Shutdown(context.Background())
		return nil, ctx.Err()
	}
}
