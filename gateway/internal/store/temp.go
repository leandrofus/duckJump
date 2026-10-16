package store

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// TestPostgresEnv names a PostgreSQL database the test suites run against
// instead of SQLite (make test-postgres sets it).
const TestPostgresEnv = "DUCKJUMP_TEST_POSTGRES"

// OpenTemp opens an empty database for tests: a SQLite file in dir, or,
// with DUCKJUMP_TEST_POSTGRES set, a fresh schema in that database. close
// removes it.
func OpenTemp(dir string) (s *Store, close func(), err error) {
	base := os.Getenv(TestPostgresEnv)
	if base == "" {
		s, err := Open(filepath.Join(dir, "t.db"))
		if err != nil {
			return nil, nil, err
		}
		return s, func() { s.Close() }, nil
	}
	schema := "t_" + strings.ReplaceAll(NewID(), "-", "")
	admin, err := sql.Open("pgx", base)
	if err != nil {
		return nil, nil, err
	}
	defer admin.Close()
	if _, err := admin.Exec(`CREATE SCHEMA ` + schema); err != nil {
		return nil, nil, err
	}
	u, err := url.Parse(base)
	if err != nil {
		return nil, nil, err
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	if s, err = Open(u.String()); err != nil {
		return nil, nil, fmt.Errorf("opening schema %s: %w", schema, err)
	}
	return s, func() {
		s.Close()
		if a, err := sql.Open("pgx", base); err == nil {
			a.ExecContext(context.Background(), `DROP SCHEMA `+schema+` CASCADE`)
			a.Close()
		}
	}, nil
}
