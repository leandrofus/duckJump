// palta-gw: web gateway. Serves the API and the session tunnel, holds the
// credential vault and the audit trail, and hosts edge agents.
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/leandrofus/palta/gateway/internal/auth"
	"github.com/leandrofus/palta/gateway/internal/edge"
	"github.com/leandrofus/palta/gateway/internal/server"
	"github.com/leandrofus/palta/gateway/internal/store"
	"github.com/leandrofus/palta/gateway/internal/store/db"
	"github.com/leandrofus/palta/gateway/internal/vault"
)

const usage = `usage: palta-gw <command> [flags]

commands:
  serve     run the gateway
  keygen    print a new master key for PALTA_MASTER_KEY
  user      create a local user   (user -name admin -password ... [-role superadmin])

  Quick-start helpers (the same as the API, audited as "cli"):
  secret    vault a credential    (secret -name s -user root [-password x | -key-file id_ed25519])
  site      add a site            (site -name edge1 [-direct]; prints the agent token)
  conn      add a connection      (conn -name web1 -host 10.0.0.5 [-port 22] -secret s [-site edge1])
  grant     grant access          (grant -user ana -conn web1 [-ttl 2h])

environment: PALTA_DB (default palta.db), PALTA_MASTER_KEY, PALTAD_ADDR, PALTAD_TOKEN
  Secrets can also come from a file: PALTA_MASTER_KEY_FILE, PALTAD_TOKEN_FILE, or the
  systemd credentials palta-master-key and paltad-token (LoadCredential=).
`

var cli = store.Actor{Name: "cli"}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	if cmd == "keygen" {
		fmt.Println(vault.GenerateKey())
		return
	}
	cmds := map[string]func(context.Context, *store.Store, []string) error{
		"serve": serve, "user": addUser, "secret": addSecret, "site": addSite, "conn": addConn, "grant": grant,
	}
	run, ok := cmds[cmd]
	if !ok {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	st, err := store.Open(env("PALTA_DB", "palta.db"))
	if err != nil {
		fatal(err)
	}
	defer st.Close()
	if err := run(context.Background(), st, args); err != nil {
		fatal(err)
	}
}

func serve(ctx context.Context, st *store.Store, args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	listen := fs.String("listen", "127.0.0.1:8080", "HTTP listen address")
	dev := fs.Bool("dev", false, "disable user authentication (PoC only, never expose)")
	agentListen := fs.String("agent-listen", "", "listen address for edge agents (only /agent/connect), e.g. 0.0.0.0:18443")
	relayListen := fs.String("relay-listen", "127.0.0.1:4824", "listen address paltad uses to reach edge sites")
	recordings := fs.String("recordings", env("PALTA_RECORDINGS", ""), "directory where paltad writes recordings (for downloads)")
	tlsCert := fs.String("tls-cert", env("PALTA_TLS_CERT", ""), "serve HTTPS (and the agent endpoint) with this certificate; created self-signed if it and -tls-key do not exist")
	tlsKey := fs.String("tls-key", env("PALTA_TLS_KEY", ""), "private key for -tls-cert")
	fs.Parse(args)

	var tlsConf *tls.Config
	if *tlsCert != "" || *tlsKey != "" {
		if *tlsCert == "" || *tlsKey == "" {
			return fmt.Errorf("-tls-cert and -tls-key go together")
		}
		var err error
		if tlsConf, err = loadTLS(*tlsCert, *tlsKey); err != nil {
			return err
		}
	}

	v, err := openVault()
	if err != nil {
		return err
	}
	token, err := secretEnv("PALTAD_TOKEN", "paltad-token")
	if err != nil {
		return err
	}
	if token == "" {
		return fmt.Errorf("PALTAD_TOKEN is required")
	}
	if n, err := st.Q.CountUsers(ctx); err == nil && n == 0 && !*dev {
		slog.Warn("no users yet: create one with `palta-gw user -name admin -password ... -role superadmin`")
	}

	hub := edge.NewHub(st.AgentSiteLookup)
	rl, err := net.Listen("tcp", *relayListen)
	if err != nil {
		return fmt.Errorf("relay listener: %w", err)
	}
	go hub.ServeRelay(rl)
	if *agentListen != "" {
		al, err := net.Listen("tcp", *agentListen)
		if err != nil {
			return fmt.Errorf("agent listener: %w", err)
		}
		amux := http.NewServeMux()
		amux.HandleFunc("GET /agent/connect", hub.ServeAgent)
		as := &http.Server{Handler: amux, ReadHeaderTimeout: 10 * time.Second}
		if tlsConf != nil {
			al = tls.NewListener(al, tlsConf)
		}
		slog.Info("edge agent endpoint listening", "addr", *agentListen, "tls", tlsConf != nil)
		go func() { slog.Error("agent listener stopped", "err", as.Serve(al)) }()
	}

	authSvc := &auth.Service{Store: st, Vault: v}
	go func() {
		for range time.Tick(10 * time.Minute) {
			if n, err := authSvc.PurgeExpired(context.Background()); err != nil {
				slog.Error("purging web sessions", "err", err)
			} else if n > 0 {
				slog.Info("purged expired web sessions", "count", n)
			}
		}
	}()

	srv := &server.Server{
		Store: st, Vault: v, Auth: authSvc, Hub: hub,
		PaltadAddr: env("PALTAD_ADDR", "127.0.0.1:4823"), PaltadToken: token,
		RelayAddr: env("PALTA_RELAY_ADDR", *relayListen), RecordingsDir: *recordings,
		Dev: *dev,
	}
	if *dev {
		slog.Warn("DEV MODE: authentication disabled")
	}
	go srv.RetentionLoop(ctx)
	slog.Info("palta-gw listening", "addr", *listen, "tls", tlsConf != nil, "paltad", srv.PaltadAddr)
	hs := &http.Server{Addr: *listen, Handler: srv.Handler(), ReadHeaderTimeout: 10 * time.Second, TLSConfig: tlsConf}
	if tlsConf != nil {
		return hs.ListenAndServeTLS("", "")
	}
	return hs.ListenAndServe()
}

func addUser(ctx context.Context, st *store.Store, args []string) error {
	fs := flag.NewFlagSet("user", flag.ExitOnError)
	name := fs.String("name", "", "username")
	password := fs.String("password", "", "password (at least 10 characters)")
	role := fs.String("role", "user", "superadmin | admin | auditor | user")
	fs.Parse(args)
	if *name == "" {
		return fmt.Errorf("need -name")
	}
	if err := auth.CheckPasswordPolicy(*password); err != nil {
		return err
	}
	h, err := auth.HashPassword(*password)
	if err != nil {
		return err
	}
	id := store.NewID()
	return st.Tx(ctx, func(q *db.Queries) error {
		if err := q.CreateUser(ctx, db.CreateUserParams{ID: id, Username: strings.ToLower(*name), PasswordHash: store.NullString(h),
			Source: "local", Role: *role, Now: store.Now()}); err != nil {
			return store.Classify(err)
		}
		fmt.Printf("user %s created (%s)\n", *name, *role)
		return store.Audit(ctx, q, store.Event{Actor: cli, Action: "user.create", ObjectType: "user", ObjectID: id,
			Details: map[string]any{"username": *name, "role": *role}})
	})
}

func addSecret(ctx context.Context, st *store.Store, args []string) error {
	fs := flag.NewFlagSet("secret", flag.ExitOnError)
	name := fs.String("name", "", "secret name")
	user := fs.String("user", "", "remote username")
	password := fs.String("password", "", "remote password")
	keyFile := fs.String("key-file", "", "private key file (OpenSSH/PEM)")
	fs.Parse(args)
	if *name == "" || *user == "" || (*password == "") == (*keyFile == "") {
		return fmt.Errorf("need -name, -user and exactly one of -password or -key-file")
	}
	v, err := openVault()
	if err != nil {
		return err
	}
	kind, plain := "password", []byte(*password)
	if *keyFile != "" {
		if plain, err = os.ReadFile(*keyFile); err != nil {
			return err
		}
		kind = "private_key"
	}
	id := store.NewID()
	return st.Tx(ctx, func(q *db.Queries) error {
		if err := q.CreateSecret(ctx, db.CreateSecretParams{ID: id, Name: *name, Kind: kind, Username: *user,
			Sealed: v.Seal(plain, []byte(id)), Now: store.Now()}); err != nil {
			return store.Classify(err)
		}
		fmt.Printf("secret %s stored (%s)\n", *name, kind)
		return store.Audit(ctx, q, store.Event{Actor: cli, Action: "secret.create", ObjectType: "secret", ObjectID: id,
			Details: map[string]any{"name": *name, "kind": kind, "username": *user}})
	})
}

func addSite(ctx context.Context, st *store.Store, args []string) error {
	fs := flag.NewFlagSet("site", flag.ExitOnError)
	name := fs.String("name", "", "site name")
	direct := fs.Bool("direct", false, "hosts are reachable directly from paltad (no agent)")
	fs.Parse(args)
	if *name == "" {
		return fmt.Errorf("need -name")
	}
	kind, tok, hash := "agent", edge.NewToken(), ""
	if *direct {
		kind, tok = "direct", ""
	} else {
		hash = edge.HashToken(tok)
	}
	id := store.NewID()
	return st.Tx(ctx, func(q *db.Queries) error {
		if err := q.CreateSite(ctx, db.CreateSiteParams{ID: id, Name: *name, Kind: kind, AgentTokenHash: store.NullString(hash), Now: store.Now()}); err != nil {
			return store.Classify(err)
		}
		if tok != "" {
			fmt.Printf("site %s created (agent). Agent token, shown only once:\n%s\n", *name, tok)
		} else {
			fmt.Printf("site %s created (direct)\n", *name)
		}
		return store.Audit(ctx, q, store.Event{Actor: cli, Action: "site.create", ObjectType: "site", ObjectID: id,
			Details: map[string]any{"name": *name, "kind": kind}})
	})
}

func addConn(ctx context.Context, st *store.Store, args []string) error {
	fs := flag.NewFlagSet("conn", flag.ExitOnError)
	name := fs.String("name", "", "connection name")
	protocol := fs.String("protocol", "ssh", "ssh | rdp | vnc")
	host := fs.String("host", "", "target host")
	port := fs.Int("port", 22, "target port")
	secret := fs.String("secret", "", "vaulted credential name")
	site := fs.String("site", "", "site the host belongs to (default: reachable directly)")
	noRecord := fs.Bool("no-record", false, "do not record sessions")
	recInput := fs.Bool("record-input", false, "also record keystrokes")
	fs.Parse(args)
	if *name == "" || *host == "" {
		return fmt.Errorf("need -name and -host")
	}
	p := db.CreateConnectionParams{ID: store.NewID(), Name: *name, Protocol: *protocol, Host: *host, Port: int64(*port),
		Backend: "paltad", CredentialMode: "vault", Params: "{}", Record: !*noRecord, RecordInput: *recInput, Now: store.Now()}
	return st.Tx(ctx, func(q *db.Queries) error {
		if *secret != "" {
			sec, err := q.GetSecretByName(ctx, *secret)
			if err != nil {
				return fmt.Errorf("secret %q: %w", *secret, store.Classify(err))
			}
			p.SecretID = store.NullString(sec.ID)
		}
		if *site != "" {
			s, err := q.GetSiteByName(ctx, *site)
			if err != nil {
				return fmt.Errorf("site %q: %w", *site, store.Classify(err))
			}
			p.SiteID = store.NullString(s.ID)
		}
		if err := q.CreateConnection(ctx, p); err != nil {
			return store.Classify(err)
		}
		fmt.Printf("connection %s created (%s)\n", *name, p.ID)
		return store.Audit(ctx, q, store.Event{Actor: cli, Action: "connection.create", ObjectType: "connection", ObjectID: p.ID,
			Details: map[string]any{"name": *name, "protocol": *protocol, "host": *host, "port": *port}})
	})
}

func grant(ctx context.Context, st *store.Store, args []string) error {
	fs := flag.NewFlagSet("grant", flag.ExitOnError)
	user := fs.String("user", "", "username")
	conn := fs.String("conn", "", "connection name")
	ttl := fs.Duration("ttl", 0, "access duration for just-in-time grants (0 = permanent)")
	fs.Parse(args)
	id := store.NewID()
	return st.Tx(ctx, func(q *db.Queries) error {
		u, err := q.GetUserByUsername(ctx, *user)
		if err != nil {
			return fmt.Errorf("user %q: %w", *user, store.Classify(err))
		}
		c, err := q.GetConnectionByName(ctx, *conn)
		if err != nil {
			return fmt.Errorf("connection %q: %w", *conn, store.Classify(err))
		}
		var exp time.Time
		if *ttl > 0 {
			exp = store.Now().Add(*ttl)
		}
		if err := q.CreatePolicy(ctx, db.CreatePolicyParams{ID: id, SubjectType: "user", SubjectID: u.ID, ObjectType: "connection",
			ObjectRef: c.ID, CanConnect: true, ExpiresAt: store.NullTime(exp), Now: store.Now()}); err != nil {
			return err
		}
		fmt.Printf("granted %s -> %s\n", *user, *conn)
		return store.Audit(ctx, q, store.Event{Actor: cli, Action: "policy.create", ObjectType: "policy", ObjectID: id,
			Details: map[string]any{"subject": "user:" + u.ID, "object": "connection:" + c.ID, "can_connect": true}})
	})
}

func openVault() (*vault.Vault, error) {
	k, err := secretEnv("PALTA_MASTER_KEY", "palta-master-key")
	if err != nil {
		return nil, err
	}
	if k == "" {
		return nil, fmt.Errorf("PALTA_MASTER_KEY is required (generate one with: palta-gw keygen)")
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
			if _, err := os.Stat(dir + "/" + cred); err == nil {
				f = dir + "/" + cred
			}
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

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}
