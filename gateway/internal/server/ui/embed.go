// Package ui embeds the compiled React UI (web/, built with `make web` into
// ui/dist). Without a build, dist holds only .gitkeep and the gateway falls
// back to the minimal PoC viewer.
package ui

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var dist embed.FS

// FS returns the built UI, or nil when it was not built.
func FS() fs.FS {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		return nil
	}
	if _, err := fs.Stat(sub, "index.html"); err != nil {
		return nil
	}
	return sub
}
