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
)

type allowRuleFlags []edge.AllowRule

func (a *allowRuleFlags) String() string { return fmt.Sprint(*a) }
func (a *allowRuleFlags) Set(s string) error {
	r, err := edge.ParseAllow(s)
	if err == nil {
		*a = append(*a, r)
	}
	return err
}

func agentCmd(args []string) error {
	var (
		serverURL string
		name      string
		caFile    string
		token     string
		allow     allowRuleFlags
	)

	fs := flag.NewFlagSet("agent", flag.ContinueOnError)
	fs.StringVar(&serverURL, "server", os.Getenv("DUCKJUMP_AGENT_SERVER"), "gateway agent endpoint (e.g. wss://bastion:8443/agent/connect)")
	fs.StringVar(&name, "name", "", "agent name (default: hostname)")
	fs.Var(&allow, "allow", "CIDR[:port,port] the gateway may reach through this agent (repeatable)")
	fs.StringVar(&caFile, "ca", os.Getenv("DUCKJUMP_AGENT_CA"), "PEM file with gateway certificate or CA")
	fs.StringVar(&token, "token", os.Getenv("DUCKJUMP_AGENT_TOKEN"), "agent authentication token")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}

	if token == "" {
		if f := os.Getenv("DUCKJUMP_AGENT_TOKEN_FILE"); f != "" {
			if b, err := os.ReadFile(f); err == nil {
				token = strings.TrimSpace(string(b))
			}
		} else if dir := os.Getenv("CREDENTIALS_DIRECTORY"); dir != "" {
			if b, err := os.ReadFile(dir + "/agent-token"); err == nil {
				token = strings.TrimSpace(string(b))
			}
		}
	}

	if envAllow := os.Getenv("DUCKJUMP_AGENT_ALLOW"); envAllow != "" {
		for _, s := range strings.Fields(envAllow) {
			_ = allow.Set(s)
		}
	}

	if serverURL == "" || token == "" {
		return fmt.Errorf("usage: duckjump agent --server <wss://host:port/agent/connect> --token <token>")
	}

	if name == "" {
		name, _ = os.Hostname()
	}

	if len(allow) == 0 {
		slog.Warn("empty allow list: every connection attempt through this agent will be refused (use --allow <CIDR>)")
	}

	var roots *x509.CertPool
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return fmt.Errorf("reading CA file: %w", err)
		}
		roots = x509.NewCertPool()
		if !roots.AppendCertsFromPEM(pem) {
			return fmt.Errorf("no certificate found in %s", caFile)
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	slog.Info("duckjump agent starting", "name", name, "server", serverURL, "allow", allow.String())
	edge.RunAgent(ctx, edge.AgentConfig{
		Server:  serverURL,
		Token:   token,
		Name:    name,
		Allow:   allow,
		RootCAs: roots,
	})
	return nil
}
