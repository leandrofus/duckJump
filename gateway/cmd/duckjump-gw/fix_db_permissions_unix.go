//go:build !windows

package main

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

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
