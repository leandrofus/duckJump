package services

import (
	"context"
	"testing"

	"github.com/leandrofus/duckjump/gateway/internal/store"
)

func TestPortalService_ListConnections(t *testing.T) {
	st := newTestStore(t)
	connSvc := NewConnectionService(st)
	folderSvc := NewFolderService(st)
	userSvc := NewUserService(st)
	portalSvc := NewPortalService(st)

	ctx := context.Background()
	actor := store.Actor{Name: "admin"}

	// Create user
	u, err := userSvc.Create(ctx, CreateUserParams{
		Username: "portaluser",
		Password: "Password123!",
		Role:     "user",
		Actor:    actor,
	})
	if err != nil {
		t.Fatalf("Create user failed: %v", err)
	}

	// Create folder
	f, err := folderSvc.Create(ctx, CreateFolderParams{
		Name:  "Production",
		Actor: actor,
	})
	if err != nil {
		t.Fatalf("Create folder failed: %v", err)
	}

	// Create connection
	connRes, err := connSvc.Create(ctx, CreateConnectionParams{
		Name:     "web-prod",
		Protocol: "ssh",
		Host:     "10.0.0.5",
		FolderID: &f.ID,
		Tags:     []string{"web", "prod"},
		Actor:    actor,
	})
	if err != nil {
		t.Fatalf("Create connection failed: %v", err)
	}

	// In dev mode, all connections are returned
	devConns, err := portalSvc.ListConnections(ctx, u.ID, true)
	if err != nil {
		t.Fatalf("ListConnections (dev) failed: %v", err)
	}
	if len(devConns) != 1 {
		t.Fatalf("expected 1 connection in dev mode, got %d", len(devConns))
	}
	if devConns[0].Connection.ID != connRes.Connection.ID {
		t.Fatalf("expected connection ID %s, got %s", connRes.Connection.ID, devConns[0].Connection.ID)
	}
	if devConns[0].FolderPath != "Production" {
		t.Fatalf("expected folder path Production, got %s", devConns[0].FolderPath)
	}
	if len(devConns[0].Tags) != 2 {
		t.Fatalf("expected 2 tags, got %d", len(devConns[0].Tags))
	}
	if !devConns[0].CanUpload || !devConns[0].CanDownload || !devConns[0].CanForward {
		t.Fatalf("expected all permissions in dev mode")
	}

	// In non-dev mode without grants, empty list
	userConns, err := portalSvc.ListConnections(ctx, u.ID, false)
	if err != nil {
		t.Fatalf("ListConnections (user) failed: %v", err)
	}
	if len(userConns) != 0 {
		t.Fatalf("expected 0 connections for user without grants, got %d", len(userConns))
	}
}
