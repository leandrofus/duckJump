package server

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// DownloadAgent serves the duckjump-agent binary.
func (s *Server) DownloadAgent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	path, err := s.findAgentBinary()
	if err != nil {
		writeErr(w, &apiError{http.StatusNotFound, "not_found", err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="duckjump-agent"`)
	http.ServeFile(w, r, path)
}

// ServeAgentInstallScript serves a bash installer script for the duckjump-agent systemd service.
func (s *Server) ServeAgentInstallScript(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	dl, srv, _, _ := s.siteURLs(r)
	token := r.URL.Query().Get("token")
	server := r.URL.Query().Get("server")
	if server == "" {
		server = srv
	}
	allow := r.URL.Query().Get("allow")
	if allow == "" {
		allow = "0.0.0.0/0:22,3389,5900"
	}
	// Always this gateway's binary: the script runs as root, and a link to
	// it must not be able to fetch one from elsewhere.
	binURL := dl

	script := generateInstallScript(token, server, allow, binURL)

	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write([]byte(script))
}

func shQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func generateInstallScript(token, server, allow, binURL string) string {
	return fmt.Sprintf(`#!/bin/sh
set -e

# DuckJump edge agent installer
# Installs duckjump-agent as a systemd service.

DEFAULT_TOKEN=%s
DEFAULT_SERVER=%s
DEFAULT_ALLOW=%s
DEFAULT_BIN_URL=%s

TOKEN="${DUCKJUMP_AGENT_TOKEN:-$DEFAULT_TOKEN}"
SERVER="${DUCKJUMP_AGENT_SERVER:-$DEFAULT_SERVER}"
ALLOW="${DUCKJUMP_AGENT_ALLOW:-$DEFAULT_ALLOW}"
BIN_URL="${DUCKJUMP_AGENT_BIN_URL:-$DEFAULT_BIN_URL}"

# Parse optional arguments
while [ $# -gt 0 ]; do
  case "$1" in
    --token|-token) TOKEN="$2"; shift 2 ;;
    --server|-server) SERVER="$2"; shift 2 ;;
    --allow|-allow) ALLOW="$2"; shift 2 ;;
    --bin-url|-bin-url) BIN_URL="$2"; shift 2 ;;
    *) shift ;;
  esac
done

if [ "$(id -u)" -ne 0 ]; then
  echo "Error: this installer must be run as root (e.g. sudo bash)" >&2
  exit 1
fi

if [ -z "$TOKEN" ]; then
  echo "Error: agent token is required (pass via ?token=, DUCKJUMP_AGENT_TOKEN, or --token)" >&2
  exit 1
fi

if [ -z "$SERVER" ]; then
  echo "Error: agent server URL is required" >&2
  exit 1
fi

if [ -z "$ALLOW" ]; then
  ALLOW="0.0.0.0/0:22,3389,5900"
fi

echo "==> Installing DuckJump Edge Agent..."

mkdir -p /usr/local/bin
TMP_BIN="/usr/local/bin/duckjump-agent.tmp.$$"

if command -v curl >/dev/null 2>&1; then
  curl -fsSL "$BIN_URL" -o "$TMP_BIN"
elif command -v wget >/dev/null 2>&1; then
  wget -qO "$TMP_BIN" "$BIN_URL"
else
  echo "Error: neither curl nor wget is installed." >&2
  exit 1
fi

chmod 755 "$TMP_BIN"
mv "$TMP_BIN" /usr/local/bin/duckjump-agent

# Symlink to /usr/bin if /usr/bin exists and duckjump-agent is not already there
if [ -d /usr/bin ] && [ ! -e /usr/bin/duckjump-agent ]; then
  ln -sf /usr/local/bin/duckjump-agent /usr/bin/duckjump-agent || true
fi

# Create agent config directory
mkdir -p /etc/duckjump-agent
chmod 750 /etc/duckjump-agent

# Save token (systemd LoadCredential reads this as root)
echo "$TOKEN" > /etc/duckjump-agent/token
chmod 600 /etc/duckjump-agent/token

# Write environment file
cat <<EOF > /etc/duckjump-agent/agent.env
# DuckJump edge agent configuration
DUCKJUMP_AGENT_SERVER="$SERVER"
DUCKJUMP_AGENT_ALLOW="$ALLOW"
EOF
chmod 600 /etc/duckjump-agent/agent.env

# Install and configure systemd service if systemd is available
if [ -d /run/systemd/system ] || command -v systemctl >/dev/null 2>&1; then
  cat <<'EOF' > /etc/systemd/system/duckjump-agent.service
[Unit]
Description=DuckJump edge agent (outbound tunnel to the gateway)
Documentation=https://github.com/leandrofus/duckJump
After=network-online.target
Wants=network-online.target
ConditionFileNotEmpty=/etc/duckjump-agent/token

[Service]
Type=simple
DynamicUser=yes
EnvironmentFile=-/etc/duckjump-agent/agent.env
LoadCredential=agent-token:/etc/duckjump-agent/token
ExecStart=/usr/local/bin/duckjump-agent
Restart=always
RestartSec=5
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes
CapabilityBoundingSet=

[Install]
WantedBy=multi-user.target
EOF

  chmod 644 /etc/systemd/system/duckjump-agent.service
  systemctl daemon-reload
  systemctl enable duckjump-agent.service
  systemctl restart duckjump-agent.service

  echo "==> DuckJump agent installed and running as systemd service!"
  echo "    Status: systemctl status duckjump-agent"
  echo "    Logs:   journalctl -u duckjump-agent -f"
else
  echo "==> DuckJump agent installed to /usr/local/bin/duckjump-agent."
  echo "    Notice: systemd not active on this system."
  echo "    To run manually:"
  echo "      DUCKJUMP_AGENT_TOKEN='$TOKEN' /usr/local/bin/duckjump-agent -server '$SERVER' -allow '$ALLOW'"
fi
`,
		shQuote(token),
		shQuote(server),
		shQuote(allow),
		shQuote(binURL),
	)
}

func (s *Server) findAgentBinary() (string, error) {
	if s.AgentBinPath != "" {
		if isFile(s.AgentBinPath) {
			return s.AgentBinPath, nil
		}
		return "", fmt.Errorf("configured agent binary not found at %s", s.AgentBinPath)
	}

	// 1. Next to the running executable
	if exe, err := os.Executable(); err == nil {
		p := filepath.Join(filepath.Dir(exe), "duckjump-agent")
		if isFile(p) {
			return p, nil
		}
	}

	// 2. Relative to current working directory
	candidates := []string{
		"bin/duckjump-agent",
		"gateway/bin/duckjump-agent",
		"../gateway/bin/duckjump-agent",
		"dist/bin/duckjump-agent",
		"../dist/bin/duckjump-agent",
		"/usr/bin/duckjump-agent",
		"/usr/local/bin/duckjump-agent",
	}
	for _, c := range candidates {
		if isFile(c) {
			return c, nil
		}
	}

	// 3. In system PATH
	if p, err := exec.LookPath("duckjump-agent"); err == nil {
		return p, nil
	}

	return "", errors.New("duckjump-agent binary not found on server")
}

func isFile(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && !fi.IsDir()
}
