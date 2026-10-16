package agent

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
)

var codeRegex = regexp.MustCompile(`\[\s*(\d{3}\s*\d{3})\s*\]`)

// Runner manages the lifecycle of the duckjump-assist background process.
type Runner struct {
	mu      sync.Mutex
	cmd     *exec.Cmd
	cancel  context.CancelFunc
	running bool

	OnCode      func(code string)
	OnConnected func()
	OnExit      func(err error)
	OnLog       func(line string)
}

// NewRunner creates an agent runner instance.
func NewRunner() *Runner {
	return &Runner{}
}

// LocateOrDownloadBinary finds the duckjump-assist executable or downloads it from the server.
func (r *Runner) LocateOrDownloadBinary(serverURL string) (string, error) {
	binName := "duckjump-assist"
	if runtime.GOOS == "windows" {
		binName = "duckjump-assist.exe"
	}

	candidates := []string{
		binName,
		filepath.Join(".", binName),
		filepath.Join("..", "dist", "bin", binName),
		filepath.Join("..", "gateway", "bin", binName),
		filepath.Join("dist", "bin", binName),
	}

	execPath, err := os.Executable()
	if err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(execPath), binName))
	}

	for _, c := range candidates {
		if info, err := os.Stat(c); err == nil && !info.IsDir() {
			return filepath.Abs(c)
		}
	}

	// Try PATH
	if p, err := exec.LookPath(binName); err == nil {
		return p, nil
	}

	// Download from server if not found locally
	tempDir := filepath.Join(os.TempDir(), "duckjump-assist")
	_ = os.MkdirAll(tempDir, 0o755)
	destPath := filepath.Join(tempDir, binName)

	downloadURL := fmt.Sprintf("%s/support/duckjump-assist?os=%s", strings.TrimRight(serverURL, "/"), runtime.GOOS)
	resp, err := http.Get(downloadURL)
	if err != nil {
		return "", fmt.Errorf("no se pudo descargar el agente de soporte: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("servidor retornó código %d al descargar binario", resp.StatusCode)
	}

	out, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return "", err
	}
	defer out.Close()

	if _, err := io.Copy(out, resp.Body); err != nil {
		return "", err
	}

	return destPath, nil
}

// Start launches duckjump-assist and streams stdout events.
func (r *Runner) Start(ctx context.Context, serverURL, token string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.running {
		return fmt.Errorf("el agente ya se encuentra en ejecución")
	}

	binPath, err := r.LocateOrDownloadBinary(serverURL)
	if err != nil {
		return err
	}

	cmdCtx, cancel := context.WithCancel(ctx)
	r.cancel = cancel
	r.cmd = exec.CommandContext(cmdCtx, binPath, "--server", serverURL, "--token", token)

	stdout, err := r.cmd.StdoutPipe()
	if err != nil {
		cancel()
		return err
	}
	r.cmd.Stderr = r.cmd.Stdout // merge stderr into stdout stream

	if err := r.cmd.Start(); err != nil {
		cancel()
		return fmt.Errorf("error al iniciar el agente: %w", err)
	}
	r.running = true

	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Text()
			if r.OnLog != nil {
				r.OnLog(line)
			}

			if m := codeRegex.FindStringSubmatch(line); len(m) > 1 {
				cleanCode := strings.TrimSpace(m[1])
				if r.OnCode != nil {
					r.OnCode(cleanCode)
				}
			}

			if strings.Contains(line, "Frame #") || strings.Contains(line, "ACK recibido") {
				if r.OnConnected != nil {
					r.OnConnected()
				}
			}
		}

		exitErr := r.cmd.Wait()
		r.mu.Lock()
		r.running = false
		r.mu.Unlock()

		if r.OnExit != nil {
			r.OnExit(exitErr)
		}
	}()

	return nil
}

// Stop cleanly terminates the running agent.
func (r *Runner) Stop() {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.cancel != nil {
		r.cancel()
		r.cancel = nil
	}
	if r.cmd != nil && r.cmd.Process != nil {
		_ = r.cmd.Process.Kill()
	}
	r.running = false
}

// IsRunning reports if the agent process is currently active.
func (r *Runner) IsRunning() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.running
}
