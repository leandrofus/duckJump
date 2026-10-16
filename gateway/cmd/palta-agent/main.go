// palta-agent: edge agent. Runs inside a closed network, keeps an outbound
// tunnel to palta-gw and dials local hosts on its behalf, within its own
// allow list.
package main

import (
	"context"
	"crypto/x509"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/leandrofus/palta/gateway/internal/edge"
)

type allowFlags []edge.AllowRule

func (a *allowFlags) String() string { return fmt.Sprint(*a) }
func (a *allowFlags) Set(s string) error {
	r, err := edge.ParseAllow(s)
	if err == nil {
		*a = append(*a, r)
	}
	return err
}

func main() {
	var allow allowFlags
	server := flag.String("server", os.Getenv("PALTA_AGENT_SERVER"), "gateway agent endpoint, e.g. wss://bastion:8443/agent/connect")
	name := flag.String("name", "", "agent name (default: hostname)")
	flag.Var(&allow, "allow", "CIDR[:port,port] the gateway may reach through this agent (repeatable; none = deny all)")
	flag.Parse()

	ca := flag.String("ca", os.Getenv("PALTA_AGENT_CA"), "PEM file with the gateway's certificate or its CA (for a self-signed gateway)")
	token := os.Getenv("PALTA_AGENT_TOKEN")
	f := os.Getenv("PALTA_AGENT_TOKEN_FILE")
	if dir := os.Getenv("CREDENTIALS_DIRECTORY"); f == "" && dir != "" {
		f = dir + "/agent-token" // systemd LoadCredential=agent-token:…
	}
	if token == "" && f != "" {
		b, err := os.ReadFile(f)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		token = strings.TrimSpace(string(b))
	}
	if *server == "" || token == "" {
		fmt.Fprintln(os.Stderr, "need -server (or PALTA_AGENT_SERVER) and PALTA_AGENT_TOKEN")
		os.Exit(2)
	}
	if env := os.Getenv("PALTA_AGENT_ALLOW"); env != "" {
		for _, s := range strings.Fields(env) {
			if err := allow.Set(s); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(2)
			}
		}
	}
	if *name == "" {
		*name, _ = os.Hostname()
	}
	if len(allow) == 0 {
		slog.Warn("empty allow list: every dial will be refused")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	slog.Info("palta-agent starting", "name", *name, "server", *server, "allow", allow.String())
	var roots *x509.CertPool
	if *ca != "" {
		pem, err := os.ReadFile(*ca)
		roots = x509.NewCertPool()
		if err != nil || !roots.AppendCertsFromPEM(pem) {
			fmt.Fprintln(os.Stderr, "error: no certificate in", *ca, err)
			os.Exit(1)
		}
	}
	edge.RunAgent(ctx, edge.AgentConfig{Server: *server, Token: token, Name: *name, Allow: allow, RootCAs: roots})
}
