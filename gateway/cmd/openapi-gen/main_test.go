package main

import (
	"path/filepath"
	"testing"
)

// The committed spec must match the comments: `go test ./...` fails when
// someone changes a handler or DTO without running `make openapi`.
func TestSpecUpToDate(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	if err := run(root, true); err != nil {
		t.Fatal(err)
	}
}
