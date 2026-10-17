package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strconv"
	"strings"

	"github.com/leandrofus/duckjump/gateway/internal/vault"
)

const systemdUnit = `[Unit]
Description=DuckJump access gateway (web UI, API, vault, audit)
Documentation=https://github.com/leandrofus/duckJump
After=network-online.target duckjumpd.service
Wants=network-online.target duckjumpd.service

[Service]
Type=simple
User=duckjump
Group=duckjump
Environment=DUCKJUMP_LISTEN=0.0.0.0:8443
Environment=DUCKJUMP_DB=/var/lib/duckjump/duckjump.db
Environment=DUCKJUMP_RECORDINGS=/var/lib/duckjump/recordings
Environment=DUCKJUMP_FILES=/var/lib/duckjump/files
Environment=DUCKJUMP_TLS_CERT=/var/lib/duckjump/tls/cert.pem
Environment=DUCKJUMP_TLS_KEY=/var/lib/duckjump/tls/key.pem
Environment=DUCKJUMPD_ADDR=127.0.0.1:4823
EnvironmentFile=-/etc/duckjump/duckjump.env
LoadCredential=duckjump-master-key:/etc/duckjump/master.key
LoadCredential=duckjumpd-token:/etc/duckjump/duckjumpd.token
ExecStart=/usr/local/bin/duckjump-gw serve -listen ${DUCKJUMP_LISTEN} $DUCKJUMP_OPTS
Restart=on-failure
RestartSec=3
StateDirectory=duckjump duckjump/recordings duckjump/files
StateDirectoryMode=0750
UMask=0027
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
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

[Install]
WantedBy=multi-user.target
`

func installService(args []string) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("install-service is only available on Linux (systemd)")
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("run as root: sudo duckjump install-service [serve flags]")
	}

	self, err := os.Executable()
	if err != nil {
		return err
	}
	bin := "/usr/local/bin/duckjump-gw"
	if self != bin {
		data, err := os.ReadFile(self)
		if err != nil {
			return err
		}
		os.MkdirAll("/usr/local/bin", 0o755)
		if err := os.WriteFile(bin+".new", data, 0o755); err != nil {
			return err
		}
		if err := os.Rename(bin+".new", bin); err != nil {
			return err
		}
	}

	// Symlink /usr/local/bin/duckjump -> /usr/local/bin/duckjump-gw
	cliLink := "/usr/local/bin/duckjump"
	if _, err := os.Lstat(cliLink); err == nil {
		_ = os.Remove(cliLink)
	}
	_ = os.Symlink(bin, cliLink)

	// Ensure system user 'duckjump' exists
	u, err := user.Lookup("duckjump")
	if err != nil {
		_ = exec.Command("useradd", "-r", "-s", "/sbin/nologin", "-d", "/var/lib/duckjump", "-M", "duckjump").Run()
		u, _ = user.Lookup("duckjump")
	}

	// Directories
	dirs := []string{
		"/etc/duckjump",
		"/var/lib/duckjump",
		"/var/lib/duckjump/recordings",
		"/var/lib/duckjump/files",
		"/var/lib/duckjump/tls",
	}
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0o750); err != nil {
			return err
		}
		if u != nil && strings.HasPrefix(d, "/var/lib/duckjump") {
			uid, _ := strconv.Atoi(u.Uid)
			gid, _ := strconv.Atoi(u.Gid)
			_ = os.Chown(d, uid, gid)
		}
	}

	// Generate master key if missing
	masterKeyFile := "/etc/duckjump/master.key"
	if _, err := os.Stat(masterKeyFile); os.IsNotExist(err) {
		k := vault.GenerateKey()
		if err := os.WriteFile(masterKeyFile, []byte(k+"\n"), 0o600); err != nil {
			return fmt.Errorf("writing master key: %w", err)
		}
		fmt.Println("generated /etc/duckjump/master.key")
	}

	// Generate duckjumpd token if missing
	tokenFile := "/etc/duckjump/duckjumpd.token"
	if _, err := os.Stat(tokenFile); os.IsNotExist(err) {
		t := vault.GenerateKey()
		if err := os.WriteFile(tokenFile, []byte(t+"\n"), 0o600); err != nil {
			return fmt.Errorf("writing duckjumpd token: %w", err)
		}
		fmt.Println("generated /etc/duckjump/duckjumpd.token")
	}

	// Environment file
	envFile := "/etc/duckjump/duckjump.env"
	if _, err := os.Stat(envFile); os.IsNotExist(err) {
		opts := strings.Join(args, " ")
		envContent := fmt.Sprintf("# DuckJump options\nDUCKJUMP_LISTEN=0.0.0.0:8443\nDUCKJUMP_OPTS=%q\n", opts)
		if err := os.WriteFile(envFile, []byte(envContent), 0o644); err != nil {
			return err
		}
	}

	// Write unit file
	unitPath := "/etc/systemd/system/duckjump.service"
	if err := os.WriteFile(unitPath, []byte(systemdUnit), 0o644); err != nil {
		return fmt.Errorf("writing systemd unit: %w", err)
	}

	// Reload & enable service
	_ = exec.Command("systemctl", "daemon-reload").Run()
	if err := exec.Command("systemctl", "enable", "--now", "duckjump.service").Run(); err != nil {
		return fmt.Errorf("enabling duckjump.service: %w", err)
	}

	fmt.Printf("\n  duckJump service installed and running\n\n")
	fmt.Printf("  Binary:  %s (symlink %s)\n", bin, cliLink)
	fmt.Printf("  Status:  systemctl status duckjump\n")
	fmt.Printf("  Logs:    journalctl -u duckjump -f\n")
	fmt.Printf("  Config:  /etc/duckjump/duckjump.env\n\n")
	return nil
}
