// duckjump-gw: web gateway. Serves the API and the session tunnel, holds the
// credential vault and the audit trail, and hosts edge agents.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/leandrofus/duckjump/gateway/internal/access"
	"github.com/leandrofus/duckjump/gateway/internal/auth"
	"github.com/leandrofus/duckjump/gateway/internal/edge"
	"github.com/leandrofus/duckjump/gateway/internal/envcompat"
	"github.com/leandrofus/duckjump/gateway/internal/objstore"
	"github.com/leandrofus/duckjump/gateway/internal/server"
	"github.com/leandrofus/duckjump/gateway/internal/services"
	"github.com/leandrofus/duckjump/gateway/internal/store"
	"github.com/leandrofus/duckjump/gateway/internal/store/db"
	"github.com/leandrofus/duckjump/gateway/internal/vault"
)

var version = "0.1.0"

const usage = `duckJump — clientless web-based access bastion for SSH, RDP and VNC

Usage:
  duckjump serve             [--listen 0.0.0.0:8080] [--allow IP,CIDR,host] ...
                               Web UI + API + session tunnel
  duckjump ui                Opens the UI locally (127.0.0.1:8080) and launches the browser
  duckjump agent             --server wss://... --token ... [--allow <CIDR>]
                               Connects this edge node outbound to the central gateway
  duckjump install-service   [serve flags] Install systemd service (root)

  duckjump conn ls | add <name> --host <h> [--protocol ssh|rdp|vnc] [--secret s] | rm <name>
  duckjump conn tag ls <name> | add <name> <tag>... | clear <name>
  duckjump user ls | add <name> --password <p> [--role superadmin|admin|auditor|user] | rm <name> | passwd <name> | enable <name> | disable <name>
  duckjump group ls | add <name> [--desc "..."] | rm <name> | member ls|add|rm <group> <user>
  duckjump folder ls | add <name> [--parent <folder>] | rm <name>
  duckjump secret ls | add <name> --user <u> [--password x | --key-file f] | rm <name>
  duckjump site ls | add <name> [--direct] | rm <name> | token <name>
  duckjump grant ls | add --user <u> --conn <c> [--ttl 2h] [--upload] [--download] | rm <id>
  duckjump request ls [--status pending|approved|rejected] | approve <id> [--comment "..."] | deny <id>
  duckjump allow ls | add <IP|CIDR|host>... | rm <entry>...
  duckjump forward <name> <local-port>[:<remote-port>] [--server URL] [--token TOKEN]

  duckjump session ls | kill <session-id> [--reason "..."]
  duckjump recording ls
  duckjump audit ls [--limit 50] [--action "..."] | verify | seal
  duckjump hostkey --conn <c> [--fingerprint SHA256:...]
  duckjump keygen
  duckjump migrate-to-postgres --to postgres://...
  duckjump version

Environment:
  DUCKJUMP_DB (default duckjump.db), DUCKJUMP_MASTER_KEY, DUCKJUMPD_ADDR, DUCKJUMPD_TOKEN,
  DUCKJUMPD_TLS=1 with DUCKJUMPD_TLS_FINGERPRINT or DUCKJUMPD_CA,
  DUCKJUMP_S3_ENDPOINT, _BUCKET, _REGION, _PREFIX, _ACCESS_KEY, _SECRET_KEY[_FILE], _PATH_STYLE.
`

var cli = store.Actor{Name: "cli"}

func main() {
	envcompat.Apply()
	var cmd string
	var args []string
	if len(os.Args) < 2 {
		if strings.HasSuffix(filepath.Base(os.Args[0]), "agent") {
			cmd = "agent"
			args = nil
		} else {
			fmt.Fprint(os.Stderr, usage)
			os.Exit(2)
		}
	} else {
		cmd, args = os.Args[1], os.Args[2:]
		if strings.HasSuffix(filepath.Base(os.Args[0]), "agent") && strings.HasPrefix(cmd, "-") {
			cmd = "agent"
			args = os.Args[1:]
		}
	}

	switch cmd {
	case "version", "--version", "-v":
		fmt.Println("duckjump", version)
		return
	case "help", "--help", "-h":
		fmt.Print(usage)
		return
	case "keygen":
		fmt.Println(vault.GenerateKey())
		return
	case "agent":
		if err := agentCmd(args); err != nil {
			fatal(err)
		}
		return
	case "install-service":
		if err := installService(args); err != nil {
			fatal(err)
		}
		return
	case "forward":
		var st *store.Store
		if v, err := openVault(); err == nil {
			store.SetAuditKey(v.Derive("audit-mac"))
			dbPath := env("DUCKJUMP_DB", defaultDB())
			if s, err := store.Open(dbPath); err == nil {
				st = s
				defer st.Close()
			}
		}
		if err := forwardCmd(context.Background(), st, args); err != nil {
			fatal(err)
		}
		return
	}

	cmds := map[string]func(context.Context, *store.Store, []string) error{
		"serve":               func(ctx context.Context, st *store.Store, a []string) error { return serve(ctx, st, a, false) },
		"ui":                  func(ctx context.Context, st *store.Store, a []string) error { return serve(ctx, st, a, true) },
		"user":                userCmd,
		"group":               groupCmd,
		"folder":              folderCmd,
		"secret":              secretCmd,
		"site":                siteCmd,
		"conn":                connCmd,
		"grant":               grantCmd,
		"request":             requestCmd,
		"requests":            requestCmd,
		"allow":               allowCmd,
		"forward":             forwardCmd,
		"session":             sessionCmd,
		"sessions":            listSessions,
		"recording":           recordingCmd,
		"recordings":          recordingCmd,
		"audit":               auditCmd,
		"kill":                killSession,
		"hostkey":             approveKey,
		"audit-seal":          auditSeal,
		"migrate-to-postgres": migrateToPostgres,
	}
	run, ok := cmds[cmd]
	if !ok {
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", cmd)
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}

	// Every command writes audit events, and the chain carries MACs keyed
	// from the master key.
	v, err := openVault()
	if err != nil {
		fatal(err)
	}
	store.SetAuditKey(v.Derive("audit-mac"))
	dbPath := env("DUCKJUMP_DB", defaultDB())
	st, err := store.Open(dbPath)
	if err != nil {
		fatal(err)
	}
	defer func() {
		st.Close()
		fixDbPermissions(dbPath)
	}()
	if err := run(context.Background(), st, args); err != nil {
		fatal(err)
	}
}

func serve(ctx context.Context, st *store.Store, args []string, openBrowser bool) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	listen := fs.String("listen", "127.0.0.1:8080", "HTTP listen address")
	allowFlag := fs.String("allow", "", "allowed client IPs, CIDRs or hostnames (comma-separated). Loopback is always allowed")
	dev := fs.Bool("dev", false, "disable user authentication (PoC only, never expose)")
	agentListen := fs.String("agent-listen", "", "listen address for edge agents (only /agent/connect), e.g. 0.0.0.0:18443")
	relayListen := fs.String("relay-listen", "127.0.0.1:4824", "listen address duckjumpd uses to reach edge sites")
	recordings := fs.String("recordings", env("DUCKJUMP_RECORDINGS", ""), "directory where duckjumpd writes recordings (for downloads)")
	tlsCert := fs.String("tls-cert", env("DUCKJUMP_TLS_CERT", ""), "serve HTTPS (and the agent endpoint) with this certificate; created self-signed if it and -tls-key do not exist")
	tlsKey := fs.String("tls-key", env("DUCKJUMP_TLS_KEY", ""), "private key for -tls-cert")
	relayTLS := fs.Bool("relay-tls", env("DUCKJUMP_RELAY_TLS", "") != "", "serve the edge relay over TLS (with -tls-cert; duckjumpd pins it), for a duckjumpd on another host")
	proxies := fs.String("trusted-proxies", env("DUCKJUMP_TRUSTED_PROXIES", ""), "comma-separated addresses/CIDRs of reverse proxies whose X-Forwarded-For / X-Forwarded-Proto are believed")
	secureCookies := fs.Bool("secure-cookies", env("DUCKJUMP_SECURE_COOKIES", "") != "", "always mark the session cookie Secure (TLS terminated in front of the gateway)")
	tofu := fs.Bool("trust-on-first-use", env("DUCKJUMP_TRUST_ON_FIRST_USE", "") != "", "pin the key a server shows on its first session instead of waiting for an admin to approve it")
	auditExport := fs.String("audit-export", env("DUCKJUMP_AUDIT_EXPORT", ""), "comma-separated audit log copies: file:///path.jsonl, syslog:, syslog+udp://host:514, syslog+tcp://host:514")
	oidcIssuer := fs.String("oidc-issuer", env("DUCKJUMP_OIDC_ISSUER", ""), "OpenID Connect issuer URL for single sign-on, e.g. https://keycloak.example.com/realms/corp")
	oidcClient := fs.String("oidc-client-id", env("DUCKJUMP_OIDC_CLIENT_ID", ""), "OIDC client id (secret: DUCKJUMP_OIDC_CLIENT_SECRET[_FILE] or the oidc-client-secret credential)")
	oidcRedirect := fs.String("oidc-redirect-url", env("DUCKJUMP_OIDC_REDIRECT_URL", ""), "public URL of /api/v1/auth/oidc/callback, as registered with the provider")
	oidcName := fs.String("oidc-name", env("DUCKJUMP_OIDC_NAME", ""), "label of the sign-in button (default: Single sign-on)")
	oidcRoles := fs.String("oidc-roles-claim", env("DUCKJUMP_OIDC_ROLES_CLAIM", ""), "claim with the user's roles (dotted path, e.g. realm_access.roles); empty: roles are set by admins")
	oidcRoleMap := fs.String("oidc-role-map", env("DUCKJUMP_OIDC_ROLE_MAP", "duckjump-superadmin=superadmin,duckjump-admin=admin,duckjump-auditor=auditor"), "provider role=gateway role, comma-separated")
	oidcGroups := fs.String("oidc-groups-claim", env("DUCKJUMP_OIDC_GROUPS_CLAIM", "groups"), "claim listing the user's groups (synced as groups of source oidc)")
	oidcUser := fs.String("oidc-username-claim", env("DUCKJUMP_OIDC_USERNAME_CLAIM", "preferred_username"), "claim used as username")
	filesDir := fs.String("files", env("DUCKJUMP_FILES", ""), "directory for the file tray (file transfer); with S3 configured the tray goes to the bucket instead")
	fileMax := fs.Int64("file-max-size", 1<<30, "largest file that may be transferred, in bytes")
	fileTTL := fs.Duration("file-ttl", server.DefaultFileTTL, "how long files stay in the tray")
	frontendURL := fs.String("frontend-url", firstEnv("", "DUCKJUMP_FRONTEND_URL", "FRONTEND_URL", "FRONTENDURL"), "public frontend/gateway URL (e.g. https://bastion.example.com)")
	agentBin := fs.String("agent-bin", env("DUCKJUMP_AGENT_BIN", ""), "path to duckjump-agent binary to serve (default: alongside duckjump-gw)")
	agentServerURL := fs.String("agent-server-url", env("DUCKJUMP_AGENT_SERVER_URL", ""), "public WebSocket URL where edge agents connect (default: derived from -frontend-url and -agent-listen)")
	fs.Parse(args)

	trusted, err := server.ParseProxies(*proxies)
	if err != nil {
		return err
	}

	var tlsConf *tls.Config
	if *tlsCert != "" || *tlsKey != "" {
		if *tlsCert == "" || *tlsKey == "" {
			return fmt.Errorf("-tls-cert and -tls-key go together")
		}
		if tlsConf, err = loadTLS(*tlsCert, *tlsKey); err != nil {
			return err
		}
	}
	if *relayTLS && tlsConf == nil {
		return fmt.Errorf("-relay-tls needs -tls-cert and -tls-key")
	}
	daemonAddr := env("DUCKJUMPD_ADDR", "127.0.0.1:4823")
	var daemonConf *tls.Config
	if os.Getenv("DUCKJUMPD_TLS") != "" {
		if daemonConf, err = daemonTLS(daemonAddr, os.Getenv("DUCKJUMPD_CA"), os.Getenv("DUCKJUMPD_TLS_FINGERPRINT")); err != nil {
			return err
		}
	} else if h, _, _ := net.SplitHostPort(daemonAddr); !isLoopback(h) {
		slog.Warn("the link to duckjumpd is not encrypted and duckjumpd is not on this host: set DUCKJUMPD_TLS", "duckjumpd", daemonAddr)
	}

	var sinks []io.Writer
	for _, target := range strings.Split(*auditExport, ",") {
		if target = strings.TrimSpace(target); target == "" {
			continue
		}
		w, err := store.OpenAuditSink(target)
		if err != nil {
			return err
		}
		defer w.Close()
		sinks = append(sinks, w)
	}

	v, err := openVault()
	if err != nil {
		return err
	}
	if res, err := st.VerifyAudit(ctx); err != nil {
		return fmt.Errorf("verifying the audit log: %w", err)
	} else if !res.OK {
		slog.Error("AUDIT LOG DOES NOT VERIFY", "broken_at", res.BrokenAt, "reason", res.Reason)
	}
	token, err := secretEnv("DUCKJUMPD_TOKEN", "duckjumpd-token")
	if err != nil {
		return err
	}
	if token == "" {
		return fmt.Errorf("DUCKJUMPD_TOKEN is required")
	}
	if n, err := st.Q.CountUsers(ctx); err == nil && n == 0 && !*dev {
		slog.Warn("no users yet: create one with `duckjump user add admin --password ... --role superadmin`")
	}

	hub := edge.NewHub(st.AgentSiteLookup)
	rl, err := net.Listen("tcp", *relayListen)
	if err != nil {
		return fmt.Errorf("relay listener: %w", err)
	}
	relayFP := ""
	if *relayTLS {
		rl = tls.NewListener(rl, tlsConf)
		relayFP = certFingerprint(tlsConf.Certificates[0].Certificate[0])
	} else if h, _, _ := net.SplitHostPort(*relayListen); !isLoopback(h) {
		slog.Warn("the edge relay listens beyond this host without TLS: add -relay-tls", "addr", *relayListen)
	}
	go hub.ServeRelay(rl)

	authSvc := &auth.Service{Store: st, Vault: v}
	var sso *auth.OIDC
	if *oidcIssuer != "" {
		secret, err := secretEnv("DUCKJUMP_OIDC_CLIENT_SECRET", "oidc-client-secret")
		if err != nil {
			return err
		}
		if *oidcClient == "" || *oidcRedirect == "" {
			return fmt.Errorf("-oidc-issuer needs -oidc-client-id and -oidc-redirect-url")
		}
		roleMap, err := auth.ParseRoleMap(*oidcRoleMap)
		if err != nil {
			return err
		}
		sso = &auth.OIDC{Issuer: *oidcIssuer, ClientID: *oidcClient, ClientSecret: secret, RedirectURL: *oidcRedirect,
			Name: *oidcName, RolesClaim: *oidcRoles, RoleMap: roleMap, GroupsClaim: *oidcGroups, UsernameClaim: *oidcUser, Vault: v}
		slog.Info("single sign-on enabled", "issuer", *oidcIssuer, "client", *oidcClient, "roles_claim", *oidcRoles)
	}
	go func() {
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			if n, err := authSvc.PurgeExpired(context.Background()); err != nil {
				slog.Error("purging web sessions", "err", err)
			} else if n > 0 {
				slog.Info("purged expired web sessions", "count", n)
			}
		}
	}()

	s3secret, err := secretEnv("DUCKJUMP_S3_SECRET_KEY", "s3-secret-key")
	if err != nil {
		return err
	}
	objects, err := objstore.FromEnv(os.Getenv, s3secret)
	if err != nil {
		return err
	}
	if objects != nil {
		if err := objects.Check(ctx); err != nil {
			slog.Error("recordings bucket not reachable (downloads of finished recordings will fail until it is)", "err", err)
		} else {
			slog.Info("recordings read from S3", "endpoint", os.Getenv("DUCKJUMP_S3_ENDPOINT"), "bucket", os.Getenv("DUCKJUMP_S3_BUCKET"))
		}
	}

	var files server.FileStore
	switch {
	case objects != nil:
		prefix := env("DUCKJUMP_S3_FILES_PREFIX", "files/")
		files = server.S3FileStore{S3: objects.WithPrefix(prefix)}
		slog.Info("file tray in S3", "prefix", prefix)
	case *filesDir != "":
		if err := os.MkdirAll(*filesDir, 0o700); err != nil {
			return err
		}
		files = server.DirFileStore{Dir: *filesDir}
		slog.Info("file tray on disk", "dir", *filesDir)
	default:
		slog.Info("file transfer off (no -files directory or S3)")
	}

	srv := &server.Server{
		Store: st, Vault: v, Auth: authSvc, Hub: hub,
		DaemonAddr: daemonAddr, DaemonToken: token, DaemonTLS: daemonConf,
		RelayAddr: env("DUCKJUMP_RELAY_ADDR", *relayListen), RelayFingerprint: relayFP, RecordingsDir: *recordings, Objects: objects,
		Files: files, FileMaxSize: *fileMax, FileTTL: *fileTTL,
		TrustedProxies: trusted, SecureCookies: *secureCookies, TrustOnFirstUse: *tofu, OIDC: sso,
		FrontendURL: *frontendURL, AgentBinPath: *agentBin, AgentListen: *agentListen, AgentServerURL: *agentServerURL,
		Dev: *dev, StaticSinks: sinks,
	}

	if *agentListen != "" {
		al, err := net.Listen("tcp", *agentListen)
		if err != nil {
			return fmt.Errorf("agent listener: %w", err)
		}
		amux := http.NewServeMux()
		amux.HandleFunc("GET /agent/connect", hub.ServeAgent)
		amux.HandleFunc("GET /agent/duckjump-agent", srv.DownloadAgent)
		as := &http.Server{Handler: amux, ReadHeaderTimeout: 10 * time.Second}
		if tlsConf != nil {
			al = tls.NewListener(al, tlsConf)
		}
		slog.Info("edge agent endpoint listening", "addr", *agentListen, "tls", tlsConf != nil)
		go func() { slog.Error("agent listener stopped", "err", as.Serve(al)) }()
	}
	if *dev {
		slog.Warn("DEV MODE: authentication disabled")
	}
	if *tofu {
		slog.Warn("trust on first use: host keys are pinned without approval")
	}
	// Sessions left open by a gateway that stopped (this one, before a
	// restart, or another sharing the database).
	if err := srv.SweepStale(ctx); err != nil {
		return err
	}
	go srv.RetentionLoop(ctx)
	go srv.Supervise(ctx)
	go srv.SIEMLoop(ctx)
	if len(sinks) > 0 {
		slog.Info("exporting the audit log (static sinks)", "to", *auditExport)
	}

	// Build allowlist
	dbAllow, _ := loadAllowlist(ctx, st)
	var allowEntries []string
	allowEntries = append(allowEntries, dbAllow...)
	if *allowFlag != "" {
		for _, e := range strings.Split(*allowFlag, ",") {
			if e = strings.TrimSpace(e); e != "" {
				if !containsStr(allowEntries, e) {
					allowEntries = append(allowEntries, e)
				}
			}
		}
	}
	var acl *access.List
	if len(allowEntries) > 0 {
		var err error
		acl, err = access.New(allowEntries)
		if err != nil {
			return fmt.Errorf("allowlist: %w", err)
		}
	}

	addrs := strings.Split(*listen, ",")
	var listeners []net.Listener
	for _, a := range addrs {
		addr := strings.TrimSpace(a)
		if addr == "" {
			continue
		}
		if !strings.Contains(addr, ":") {
			addr = addr + ":8080"
		}
		l, err := net.Listen("tcp", addr)
		if err != nil {
			for _, prev := range listeners {
				prev.Close()
			}
			return fmt.Errorf("listen %s: %w", addr, err)
		}
		if tlsConf != nil {
			l = tls.NewListener(l, tlsConf)
		}
		if acl != nil {
			l = acl.Listener(l)
		}
		listeners = append(listeners, l)
		slog.Info("duckjump-gw listening", "addr", addr, "tls", tlsConf != nil, "duckjumpd", srv.DaemonAddr)
	}
	if len(listeners) == 0 {
		return errors.New("no listen addresses specified")
	}

	primaryAddr := addrs[0]
	if !strings.Contains(primaryAddr, ":") {
		primaryAddr += ":8080"
	}
	proto := "http"
	if tlsConf != nil {
		proto = "https"
	}
	host, port, _ := net.SplitHostPort(primaryAddr)
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	uiURL := fmt.Sprintf("%s://%s", proto, net.JoinHostPort(host, port))
	if *frontendURL != "" {
		uiURL = *frontendURL
	}

	printBanner(uiURL, st, srv.DaemonAddr, allowEntries)

	if openBrowser {
		go func() {
			time.Sleep(400 * time.Millisecond)
			for _, b := range []string{"xdg-open", "open"} {
				if exec.Command(b, uiURL).Start() == nil {
					return
				}
			}
		}()
	}

	hs := &http.Server{Handler: srv.Handler(), ReadHeaderTimeout: 10 * time.Second, TLSConfig: tlsConf}
	errCh := make(chan error, len(listeners))
	for _, l := range listeners {
		go func(lis net.Listener) {
			errCh <- hs.Serve(lis)
		}(l)
	}
	return <-errCh
}

func printBanner(uiURL string, st *store.Store, daemonAddr string, allowEntries []string) {
	fmt.Printf("\n  duckJump %s\n\n", version)
	fmt.Printf("  UI         %s\n", uiURL)
	fmt.Printf("  Vault      active (audit chain verified)\n")
	if len(allowEntries) > 0 {
		fmt.Printf("  Allowlist  loopback %s\n", strings.Join(allowEntries, " "))
	} else {
		fmt.Printf("  Allowlist  loopback (open to all networks)\n")
	}
	dbInfo := "sqlite"
	if st.Postgres {
		dbInfo = "postgresql"
	}
	fmt.Printf("  Database   %s\n", dbInfo)
	if daemonAddr != "" {
		fmt.Printf("  Daemon     %s\n", daemonAddr)
	}
	fmt.Printf("\n")
}

// defaultDB returns the target database. It looks first in the current
// directory for duckjump.db (or palta.db), then in /etc/duckjump/duckjump.env,
// then /var/lib/duckjump/duckjump.db for installed packages.
func defaultDB() string {
	if _, err := os.Stat("duckjump.db"); err == nil {
		return "duckjump.db"
	}
	if _, err := os.Stat("palta.db"); err == nil {
		slog.Warn("using palta.db from before the rename; rename it to duckjump.db (with its -wal/-shm files)")
		return "palta.db"
	}
	if envBytes, err := os.ReadFile("/etc/duckjump/duckjump.env"); err == nil {
		for _, line := range strings.Split(string(envBytes), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "DUCKJUMP_DB=") {
				val := strings.TrimPrefix(line, "DUCKJUMP_DB=")
				val = strings.Trim(val, `"'`)
				if val != "" {
					return val
				}
			}
		}
	}
	if _, err := os.Stat("/var/lib/duckjump/duckjump.db"); err == nil {
		return "/var/lib/duckjump/duckjump.db"
	}
	return "duckjump.db"
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func approveKey(ctx context.Context, st *store.Store, args []string) error {
	fs := flag.NewFlagSet("hostkey", flag.ExitOnError)
	conn := fs.String("conn", "", "connection name")
	fp := fs.String("fingerprint", "", "fingerprint to pin (default: the one waiting for approval)")
	fs.Parse(args)
	return st.Tx(ctx, func(q *db.Queries) error {
		c, err := q.GetConnectionByName(ctx, *conn)
		if err != nil {
			return fmt.Errorf("connection %q: %w", *conn, store.Classify(err))
		}
		key := *fp
		if key == "" {
			if !c.HostKeyPending.Valid {
				return fmt.Errorf("connection %s has no key waiting for approval; pass -fingerprint", c.Name)
			}
			key = c.HostKeyPending.String
		}
		if !strings.HasPrefix(key, "SHA256:") {
			return fmt.Errorf("fingerprint must look like SHA256:...")
		}
		if _, err := q.ApproveHostKey(ctx, db.ApproveHostKeyParams{ID: c.ID, HostKey: store.NullString(key), Now: store.Now()}); err != nil {
			return err
		}
		fmt.Printf("pinned %s for %s\n", key, c.Name)
		return store.Audit(ctx, q, store.Event{Actor: cli, Action: "connection.host_key_approved", ObjectType: "connection", ObjectID: c.ID,
			Details: map[string]any{"name": c.Name, "fingerprint": key, "previous": c.HostKey.String, "was_pending": c.HostKeyPending.String == key}})
	})
}

func listSessions(ctx context.Context, st *store.Store, args []string) error {
	sessionSvc := services.NewSessionService(st)
	rows, err := sessionSvc.List(ctx, services.ListSessionsParams{ActiveOnly: true, Limit: 500})
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		fmt.Println("no open sessions")
		return nil
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "SESSION\tUSER\tCONNECTION\tFROM\tSTARTED")
	for _, x := range rows {
		var c struct{ Name string }
		json.Unmarshal([]byte(x.ConnectionSnapshot), &c)
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", x.ID, x.Username, c.Name, x.ClientIP, x.StartedAt.Local().Format(time.DateTime))
	}
	return tw.Flush()
}

func killSession(ctx context.Context, st *store.Store, args []string) error {
	fs := flag.NewFlagSet("kill", flag.ExitOnError)
	id := fs.String("session", "", "session id (see `duckjump session ls`)")
	reason := fs.String("reason", "", "shown to the user and audited")
	fs.Parse(args)
	sessionSvc := services.NewSessionService(st)
	x, err := sessionSvc.RequestKill(ctx, cli, *id, *reason)
	if err != nil {
		return err
	}
	fmt.Printf("termination of %s (%s) requested; the gateway ends it within %s\n", x.ID, x.Username, server.SuperviseInterval)
	return nil
}

func auditSeal(ctx context.Context, st *store.Store, args []string) error {
	auditSvc := services.NewAuditService(st)
	res, err := auditSvc.Verify(ctx)
	if err != nil {
		return err
	}
	if res.Sealed || res.Events == 0 {
		fmt.Println("the audit chain is already sealed (events carry MACs)")
		return nil
	}
	if res.BrokenAt != 0 {
		return fmt.Errorf("the hash chain is broken at event %d (%s): refusing to seal it", res.BrokenAt, res.Reason)
	}
	n, err := auditSvc.Seal(ctx, cli)
	if err != nil {
		return err
	}
	fmt.Printf("sealed: %d earlier events are now covered by the MAC chain\n", n)
	return nil
}

func migrateToPostgres(ctx context.Context, st *store.Store, args []string) error {
	fs := flag.NewFlagSet("migrate-to-postgres", flag.ExitOnError)
	to := fs.String("to", "", "PostgreSQL URL of an empty database, e.g. postgres://duckjump:secret@db:5432/duckjump")
	fs.Parse(args)
	if st.Postgres {
		return fmt.Errorf("DUCKJUMP_DB is already PostgreSQL")
	}
	if !store.IsPostgres(*to) {
		return fmt.Errorf("-to must be a postgres:// URL")
	}
	res, err := st.VerifyAudit(ctx)
	if err != nil {
		return err
	}
	if res.BrokenAt != 0 {
		return fmt.Errorf("the audit chain does not verify at event %d (%s): fix or investigate before moving it", res.BrokenAt, res.Reason)
	}
	dst, err := store.Open(*to)
	if err != nil {
		return fmt.Errorf("opening PostgreSQL: %w", err)
	}
	defer dst.Close()
	fmt.Println("copying (stop the gateway first: changes made meanwhile would be lost)…")
	counts, err := st.CopyTo(ctx, dst)
	if err != nil {
		return err
	}
	var total int64
	for _, n := range counts {
		total += n
	}
	after, err := dst.VerifyAudit(ctx)
	if err != nil {
		return err
	}
	if !after.OK && res.OK {
		return fmt.Errorf("copied, but the audit chain does not verify in PostgreSQL (%s): keep using SQLite and report it", after.Reason)
	}
	if err := dst.AuditTx(ctx, store.Event{Actor: cli, Action: "database.migrated", ObjectType: "database",
		Details: map[string]any{"from": "sqlite", "rows": counts}}); err != nil {
		return err
	}
	fmt.Printf("copied %d rows (%d audit events, chain verified). Now set DUCKJUMP_DB to the PostgreSQL URL and start the gateway.\n"+
		"The SQLite file is unchanged; keep it until you are satisfied.\n", total, counts["audit_events"])
	return nil
}

func openVault() (*vault.Vault, error) {
	k, err := secretEnv("DUCKJUMP_MASTER_KEY", "duckjump-master-key")
	if err != nil {
		return nil, err
	}
	if k == "" {
		return nil, fmt.Errorf("DUCKJUMP_MASTER_KEY is required (generate one with: duckjump keygen)")
	}
	return vault.New(k)
}

// secretEnv reads a secret from the environment variable k, from the file
// named by k_FILE, or from the systemd credential cred (LoadCredential=).
// Files keep secrets out of the process environment and unit files.
func secretEnv(k, cred string) (string, error) {
	if v := os.Getenv(k); v != "" {
		return v, nil
	}
	f := os.Getenv(k + "_FILE")
	if f == "" {
		if dir := os.Getenv("CREDENTIALS_DIRECTORY"); dir != "" {
			f = envcompat.Credential(dir, cred)
		}
	}
	if f == "" && k == "DUCKJUMP_MASTER_KEY" {
		if _, err := os.Stat("/etc/duckjump/master.key"); err == nil {
			f = "/etc/duckjump/master.key"
		} else if _, err := os.Stat("master.key"); err == nil {
			f = "master.key"
		}
	}
	if f == "" && k == "DUCKJUMPD_TOKEN" {
		if _, err := os.Stat("/etc/duckjump/duckjumpd.token"); err == nil {
			f = "/etc/duckjump/duckjumpd.token"
		}
	}
	if f == "" {
		return "", nil
	}
	b, err := os.ReadFile(f)
	if err != nil {
		return "", fmt.Errorf("reading %s: %w", k, err)
	}
	return strings.TrimSpace(string(b)), nil
}

func fixDbPermissions(dbPath string) {
	if os.Geteuid() != 0 || strings.HasPrefix(dbPath, "postgres://") || strings.HasPrefix(dbPath, "postgresql://") {
		return
	}
	dir := filepath.Dir(dbPath)
	fi, err := os.Stat(dir)
	if err != nil {
		return
	}
	stat, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return
	}
	uid, gid := int(stat.Uid), int(stat.Gid)
	if uid == 0 && gid == 0 {
		return
	}
	for _, p := range []string{dbPath, dbPath + "-wal", dbPath + "-shm"} {
		if _, err := os.Stat(p); err == nil {
			_ = os.Chown(p, uid, gid)
		}
	}
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func firstEnv(def string, names ...string) string {
	for _, n := range names {
		if v := os.Getenv(n); v != "" {
			return v
		}
	}
	return def
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}
