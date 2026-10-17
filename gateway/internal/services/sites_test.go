package services

import (
	"context"
	"errors"
	"testing"

	"github.com/leandrofus/duckjump/gateway/internal/store"
)

type mockDisconnector struct {
	disconnected []string
}

func (m *mockDisconnector) DisconnectSite(siteID string) {
	m.disconnected = append(m.disconnected, siteID)
}

func TestSiteService_Lifecycle(t *testing.T) {
	st := newTestStore(t)
	disc := &mockDisconnector{}
	siteSvc := NewSiteService(st, disc)
	ctx := context.Background()
	adminActor := store.Actor{Name: "test-admin"}

	// 1. Validation errors
	_, err := siteSvc.Create(ctx, CreateSiteParams{
		Name:  "bad-kind",
		Kind:  "invalid-kind",
		Actor: adminActor,
	})
	if !errors.Is(err, ErrSiteKindInvalid) {
		t.Fatalf("expected ErrSiteKindInvalid, got %v", err)
	}

	// 2. Create direct site
	dirSite, err := siteSvc.Create(ctx, CreateSiteParams{
		Name:        "Direct-HQ",
		Kind:        "direct",
		Description: "HQ datacenter",
		Actor:       adminActor,
	})
	if err != nil {
		t.Fatalf("Create direct site failed: %v", err)
	}
	if dirSite.Token != "" {
		t.Fatalf("expected empty token for direct site, got %s", dirSite.Token)
	}
	if dirSite.Site.Name != "Direct-HQ" || dirSite.Site.Kind != "direct" {
		t.Fatalf("unexpected site properties: %+v", dirSite.Site)
	}

	// 3. Create agent site
	agentSite, err := siteSvc.Create(ctx, CreateSiteParams{
		Name:        "Edge-Branch1",
		Kind:        "agent",
		Description: "Branch office 1",
		Actor:       adminActor,
	})
	if err != nil {
		t.Fatalf("Create agent site failed: %v", err)
	}
	if agentSite.Token == "" {
		t.Fatalf("expected non-empty token for agent site")
	}

	// 4. Rotate token on direct site should fail
	_, err = siteSvc.RotateToken(ctx, adminActor, dirSite.Site.ID)
	if !errors.Is(err, ErrSiteTokenNotAgent) {
		t.Fatalf("expected ErrSiteTokenNotAgent, got %v", err)
	}

	// 5. Rotate token on agent site
	rotRes, err := siteSvc.RotateToken(ctx, adminActor, agentSite.Site.ID)
	if err != nil {
		t.Fatalf("RotateToken on agent site failed: %v", err)
	}
	if rotRes.Token == "" || rotRes.Token == agentSite.Token {
		t.Fatalf("expected new token, got %s", rotRes.Token)
	}
	if len(disc.disconnected) != 1 || disc.disconnected[0] != agentSite.Site.ID {
		t.Fatalf("expected disconnector to be called with %s, got %v", agentSite.Site.ID, disc.disconnected)
	}

	// 6. Update metadata
	newName := "Edge-Branch1-Renamed"
	newDesc := "Updated branch office description"
	updated, err := siteSvc.Update(ctx, UpdateSiteParams{
		ID:          agentSite.Site.ID,
		Name:        &newName,
		Description: &newDesc,
		Actor:       adminActor,
	})
	if err != nil {
		t.Fatalf("Update site failed: %v", err)
	}
	if updated.Name != newName || updated.Description != newDesc {
		t.Fatalf("unexpected updated properties: %+v", updated)
	}

	// 7. GetByName
	byName, err := siteSvc.GetByName(ctx, newName)
	if err != nil {
		t.Fatalf("GetByName failed: %v", err)
	}
	if byName.ID != agentSite.Site.ID {
		t.Fatalf("GetByName ID mismatch: %s vs %s", byName.ID, agentSite.Site.ID)
	}

	// 8. DeleteByName
	if err := siteSvc.DeleteByName(ctx, adminActor, newName); err != nil {
		t.Fatalf("DeleteByName failed: %v", err)
	}

	// 9. Verify deleted
	_, err = siteSvc.Get(ctx, agentSite.Site.ID)
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}
