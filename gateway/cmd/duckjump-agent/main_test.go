package main

import (
	"testing"
)

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

// Every flag, -ca included, is accepted on the command line.
func TestParseOptionsFlags(t *testing.T) {
	o, err := parseOptions([]string{"-server", "wss://gw:8443/agent/connect", "-ca", "/etc/gw.pem", "-name", "edge1",
		"-allow", "10.0.0.0/24:22,3389"}, env(map[string]string{"DUCKJUMP_AGENT_TOKEN": "tok"}))
	if err != nil {
		t.Fatal(err)
	}
	if o.ca != "/etc/gw.pem" || o.server != "wss://gw:8443/agent/connect" || o.name != "edge1" || o.token != "tok" || len(o.allow) != 1 {
		t.Fatalf("%+v", o)
	}
}

func TestParseOptionsEnvironment(t *testing.T) {
	o, err := parseOptions(nil, env(map[string]string{"DUCKJUMP_AGENT_SERVER": "wss://gw/agent/connect", "DUCKJUMP_AGENT_TOKEN": "tok",
		"DUCKJUMP_AGENT_CA": "/ca.pem", "DUCKJUMP_AGENT_ALLOW": "10.0.0.0/8 192.168.1.5:22"}))
	if err != nil {
		t.Fatal(err)
	}
	if o.ca != "/ca.pem" || len(o.allow) != 2 {
		t.Fatalf("%+v", o)
	}
	if _, err := parseOptions([]string{"-server", "wss://x"}, env(nil)); err == nil {
		t.Fatal("accepted without a token")
	}
}
