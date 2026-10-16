package envcompat

import (
	"os"
	"path/filepath"
	"testing"
)

func TestApply(t *testing.T) {
	t.Setenv("PALTA_DB", "/old.db")
	t.Setenv("PALTAD_ADDR", "10.0.0.1:4823")
	t.Setenv("PALTA_MASTER_KEY", "old")
	t.Setenv("DUCKJUMP_MASTER_KEY", "new")
	os.Unsetenv("DUCKJUMP_DB")
	os.Unsetenv("DUCKJUMPD_ADDR")
	Apply()
	for k, want := range map[string]string{"DUCKJUMP_DB": "/old.db", "DUCKJUMPD_ADDR": "10.0.0.1:4823", "DUCKJUMP_MASTER_KEY": "new"} {
		if got := os.Getenv(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	os.Unsetenv("DUCKJUMP_DB")
	os.Unsetenv("DUCKJUMPD_ADDR")
}

func TestCredential(t *testing.T) {
	d := t.TempDir()
	os.WriteFile(filepath.Join(d, "paltad-token"), []byte("x"), 0o600)
	if got := Credential(d, "duckjumpd-token"); got != filepath.Join(d, "paltad-token") {
		t.Fatalf("old credential not found: %q", got)
	}
	os.WriteFile(filepath.Join(d, "duckjumpd-token"), []byte("y"), 0o600)
	if got := Credential(d, "duckjumpd-token"); got != filepath.Join(d, "duckjumpd-token") {
		t.Fatalf("new credential not preferred: %q", got)
	}
	if Credential(d, "duckjump-master-key") != "" {
		t.Fatal("found a credential that does not exist")
	}
}
