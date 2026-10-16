// Package envcompat keeps configurations from before the rename working:
// DuckJump used to be called palta, and its variables PALTA_* / PALTAD_*.
package envcompat

import (
	"log/slog"
	"os"
	"strings"
)

var renamed = []struct{ old, new string }{
	{"PALTAD_", "DUCKJUMPD_"},
	{"PALTA_", "DUCKJUMP_"},
}

// Apply copies every PALTA_* / PALTAD_* variable to its DUCKJUMP_* /
// DUCKJUMPD_* name when that one is unset, and warns. Call it first thing.
func Apply() {
	for _, kv := range os.Environ() {
		k, v, _ := strings.Cut(kv, "=")
		for _, r := range renamed {
			if !strings.HasPrefix(k, r.old) {
				continue
			}
			nk := r.new + strings.TrimPrefix(k, r.old)
			if _, set := os.LookupEnv(nk); !set {
				os.Setenv(nk, v)
				slog.Warn("deprecated environment variable; rename it", "old", k, "new", nk)
			}
			break
		}
	}
}

// Credential is the systemd credential file for name, falling back to its
// name before the rename (palta-master-key, paltad-token…); "" when neither
// exists.
func Credential(dir, name string) string {
	for _, n := range []string{name, oldCredential(name)} {
		if n == "" {
			continue
		}
		if _, err := os.Stat(dir + "/" + n); err == nil {
			return dir + "/" + n
		}
	}
	return ""
}

func oldCredential(name string) string {
	switch {
	case strings.HasPrefix(name, "duckjumpd-"):
		return "paltad-" + strings.TrimPrefix(name, "duckjumpd-")
	case strings.HasPrefix(name, "duckjump-"):
		return "palta-" + strings.TrimPrefix(name, "duckjump-")
	}
	return ""
}
