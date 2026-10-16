package server

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestServeAgentInstallScript(t *testing.T) {
	s := &Server{
		FrontendURL: "https://bastion.example.com:8090",
	}

	req := httptest.NewRequest(http.MethodGet, "/agent/install.sh?token=pat_testtok&allow=10.0.0.0/8:22,3389", nil)
	w := httptest.NewRecorder()

	s.ServeAgentInstallScript(w, req)
	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", resp.StatusCode)
	}

	body := w.Body.String()
	if !strings.Contains(body, "DEFAULT_TOKEN='pat_testtok'") {
		t.Errorf("script should contain DEFAULT_TOKEN='pat_testtok', got:\n%s", body)
	}
	if !strings.Contains(body, "DEFAULT_ALLOW='10.0.0.0/8:22,3389'") {
		t.Errorf("script should contain DEFAULT_ALLOW='10.0.0.0/8:22,3389', got:\n%s", body)
	}
	if !strings.Contains(body, "DEFAULT_SERVER='wss://bastion.example.com:8090/agent/connect'") {
		t.Errorf("script should contain DEFAULT_SERVER, got:\n%s", body)
	}
	if !strings.Contains(body, "DEFAULT_BIN_URL='https://bastion.example.com:8090/agent/duckjump-agent'") {
		t.Errorf("script should contain DEFAULT_BIN_URL, got:\n%s", body)
	}
	if !strings.Contains(body, "systemctl enable duckjump-agent.service") {
		t.Errorf("script should enable systemd service, got:\n%s", body)
	}
}

func TestDownloadAgent(t *testing.T) {
	tmpDir := t.TempDir()
	binPath := filepath.Join(tmpDir, "duckjump-agent")
	if err := os.WriteFile(binPath, []byte("fake-agent-binary"), 0755); err != nil {
		t.Fatal(err)
	}

	s := &Server{
		AgentBinPath: binPath,
	}

	req := httptest.NewRequest(http.MethodGet, "/agent/duckjump-agent", nil)
	w := httptest.NewRecorder()

	s.DownloadAgent(w, req)
	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", resp.StatusCode)
	}
	if w.Body.String() != "fake-agent-binary" {
		t.Fatalf("expected binary content, got %s", w.Body.String())
	}
}
