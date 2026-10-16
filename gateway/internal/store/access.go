package store

import (
	"context"

	"github.com/leandrofus/duckjump/gateway/internal/store/db"
)

// GrantedConnections lists the connections a user may open.
func (s *Store) GrantedConnections(ctx context.Context, userID string) ([]db.ConfigConnection, error) {
	return s.Q.ConnectionsGrantedToUser(ctx, db.ConnectionsGrantedToUserParams{UserID: userID, Now: TS(Now())})
}

// Grants returns the unexpired policies that give a user access to a
// connection (directly, through a group, an ancestor folder or a tag).
func (s *Store) Grants(ctx context.Context, userID, connID string) ([]db.ConfigPolicy, error) {
	return s.Q.PoliciesGrantingConnection(ctx, db.PoliciesGrantingConnectionParams{
		UserID: userID, ConnectionID: connID, Now: TS(Now()),
	})
}

// CanConnect reports whether any unexpired grant lets the user connect.
func (s *Store) CanConnect(ctx context.Context, userID, connID string) (bool, error) {
	ps, err := s.Grants(ctx, userID, connID)
	if err != nil {
		return false, err
	}
	for _, p := range ps {
		if p.CanConnect {
			return true, nil
		}
	}
	return false, nil
}

// CanViewRecordings reports whether any unexpired grant on the connection
// allows viewing its recordings.
func (s *Store) CanViewRecordings(ctx context.Context, userID, connID string) (bool, error) {
	ps, err := s.Grants(ctx, userID, connID)
	if err != nil {
		return false, err
	}
	for _, p := range ps {
		if p.CanViewRecordings {
			return true, nil
		}
	}
	return false, nil
}

// CanUpload reports whether any unexpired grant on the connection allows
// sending files to it.
func (s *Store) CanUpload(ctx context.Context, userID, connID string) (bool, error) {
	return s.anyGrant(ctx, userID, connID, func(p db.ConfigPolicy) bool { return p.CanUpload })
}

// CanDownload reports whether any unexpired grant on the connection allows
// taking files from it.
func (s *Store) CanDownload(ctx context.Context, userID, connID string) (bool, error) {
	return s.anyGrant(ctx, userID, connID, func(p db.ConfigPolicy) bool { return p.CanDownload })
}

func (s *Store) anyGrant(ctx context.Context, userID, connID string, ok func(db.ConfigPolicy) bool) (bool, error) {
	ps, err := s.Grants(ctx, userID, connID)
	if err != nil {
		return false, err
	}
	for _, p := range ps {
		if ok(p) {
			return true, nil
		}
	}
	return false, nil
}

// AgentSiteLookup adapts GetAgentSiteByToken to edge.SiteLookup.
func (s *Store) AgentSiteLookup(ctx context.Context, tokenHash string) (string, string, error) {
	st, err := s.Q.GetAgentSiteByToken(ctx, NullString(tokenHash))
	return st.ID, st.Name, Classify(err)
}
