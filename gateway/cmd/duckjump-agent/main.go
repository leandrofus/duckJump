// duckjump-agent: edge agent. Runs inside a closed network, keeps an outbound
// tunnel to duckjump-gw and dials local hosts on its behalf, within its own
// allow list.
package main

import (
	"context"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/leandrofus/duckjump/gateway/internal/edge"
	"github.com/leandrofus/duckjump/gateway/internal/envcompat"
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

type options struct {
	server, name, ca, token string
	allow                   allowFlags
}

// parseOptions reads the flags, then the environment for what they left out.
func parseOptions(args []string, getenv func(string) string) (options, error) {
	var o options
	fs := flag.NewFlagSet("duckjump-agent", flag.ContinueOnError)
	fs.StringVar(&o.server, "server", getenv("DUCKJUMP_AGENT_SERVER"), "gateway agent endpoint, e.g. wss://bastion:8443/agent/connect")
	fs.StringVar(&o.name, "name", "", "agent name (default: hostname)")
	fs.Var(&o.allow, "allow", "CIDR[:port,port] the gateway may reach through this agent (repeatable; none = deny all)")
	fs.StringVar(&o.ca, "ca", getenv("DUCKJUMP_AGENT_CA"), "PEM file with the gateway's certificate or its CA (for a self-signed gateway)")
	if err := fs.Parse(args); err != nil {
		return o, err
	}
	o.token = getenv("DUCKJUMP_AGENT_TOKEN")
	f := getenv("DUCKJUMP_AGENT_TOKEN_FILE")
	if dir := getenv("CREDENTIALS_DIRECTORY"); f == "" && dir != "" {
		f = dir + "/agent-token" // systemd LoadCredential=agent-token:…
	}
	if o.token == "" && f != "" {
		b, err := os.ReadFile(f)
		if err != nil {
			return o, err
		}
		o.token = strings.TrimSpace(string(b))
	}
	if o.server == "" || o.token == "" {
		return o, errors.New("need -server (or DUCKJUMP_AGENT_SERVER) and DUCKJUMP_AGENT_TOKEN")
	}
	if env := getenv("DUCKJUMP_AGENT_ALLOW"); env != "" {
		for _, s := range strings.Fields(env) {
			if err := o.allow.Set(s); err != nil {
				return o, err
			}
		}
	}
	return o, nil
}

func main() {
	envcompat.Apply()
	o, err := parseOptions(os.Args[1:], os.Getenv)
	if errors.Is(err, flag.ErrHelp) {
		os.Exit(0)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}
	if o.name == "" {
		o.name, _ = os.Hostname()
	}
	if len(o.allow) == 0 {
		slog.Warn("empty allow list: every dial will be refused")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	slog.Info("duckjump-agent starting", "name", o.name, "server", o.server, "allow", o.allow.String())
	var roots *x509.CertPool
	if o.ca != "" {
		pem, err := os.ReadFile(o.ca)
		roots = x509.NewCertPool()
		if err != nil || !roots.AppendCertsFromPEM(pem) {
			fmt.Fprintln(os.Stderr, "error: no certificate in", o.ca, err)
			os.Exit(1)
		}
	}
	edge.RunAgent(ctx, edge.AgentConfig{Server: o.server, Token: o.token, Name: o.name, Allow: o.allow, RootCAs: roots})
}
