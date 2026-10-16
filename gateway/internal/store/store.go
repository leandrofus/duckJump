// Package store is the persistence layer: SQLite (one node, nothing to run)
// or PostgreSQL (several gateways sharing one database), with goose
// migrations per engine and sqlc-generated queries in package db that run
// unchanged on both.
package store

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	_ "modernc.org/sqlite"

	"github.com/leandrofus/duckjump/gateway/internal/store/db"
)

//go:embed migrations/sqlite/*.sql migrations/postgres/*.sql
var migrations embed.FS

var (
	ErrNotFound = errors.New("not found")
	ErrConflict = errors.New("conflict")
)

type Store struct {
	DB *sql.DB
	Q  *db.Queries
	// Postgres: the database is PostgreSQL (else SQLite).
	Postgres bool
}

// IsPostgres reports whether a DUCKJUMP_DB value names a PostgreSQL database.
func IsPostgres(dsn string) bool {
	return strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://")
}

// Open opens the database and migrates it: a postgres:// URL, or the path
// of a SQLite file (created if needed).
func Open(dsn string) (*Store, error) {
	if IsPostgres(dsn) {
		return openPostgres(dsn)
	}
	return openSQLite(dsn)
}

func openPostgres(dsn string) (*Store, error) {
	sqldb, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}
	sqldb.SetMaxOpenConns(20)
	sqldb.SetConnMaxIdleTime(5 * time.Minute)
	if err := migrate(sqldb, "postgres", "migrations/postgres"); err != nil {
		sqldb.Close()
		return nil, err
	}
	return &Store{DB: sqldb, Q: db.New(sqldb), Postgres: true}, nil
}

func openSQLite(path string) (*Store, error) {
	// _txlock=immediate: write transactions take the lock up front, so two
	// writers never deadlock upgrading from a read lock (the audit chain
	// reads then writes inside one transaction).
	// _time_format=sqlite: store times as "2006-01-02 15:04:05.999999999-07:00",
	// which SQLite's date functions parse; the driver default (time.String())
	// is opaque to julianday().
	dsn := "file:" + path + "?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)" +
		"&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)&_txlock=immediate&_time_format=sqlite"
	sqldb, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	if err := migrate(sqldb, "sqlite3", "migrations/sqlite"); err != nil {
		sqldb.Close()
		return nil, err
	}
	return &Store{DB: sqldb, Q: db.New(sqldb)}, nil
}

func migrate(sqldb *sql.DB, dialect, dir string) error {
	p, err := goose.NewProvider(goose.Dialect(dialect), sqldb, mustSub(dir))
	if err != nil {
		return err
	}
	if _, err := p.Up(context.Background()); err != nil {
		return fmt.Errorf("migrating: %w", err)
	}
	return nil
}

func mustSub(dir string) fs.FS {
	f, err := fs.Sub(migrations, dir)
	if err != nil {
		panic(err)
	}
	return f
}

// writeLock is the advisory lock every PostgreSQL write transaction takes:
// writes are serialized, as SQLite does (_txlock=immediate), so the audit
// chain, read then appended inside a transaction, never forks, even across
// gateways sharing the database.
const writeLock = 0x70616c7461 // "palta"

func (s *Store) Close() error { return s.DB.Close() }

// Tx runs fn in a transaction, committing if it returns nil.
func (s *Store) Tx(ctx context.Context, fn func(q *db.Queries) error) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if s.Postgres {
		if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, writeLock); err != nil {
			return err
		}
	}
	if err := fn(s.Q.WithTx(tx)); err != nil {
		return err
	}
	return tx.Commit()
}

// BackendNative is how connections served by the native session daemon
// (duckjumpd) are stored: the value predates the rename and stays, so
// existing databases and API clients keep working.
const BackendNative = "paltad"

// NewID returns a time-ordered UUIDv7.
func NewID() string { return uuid.Must(uuid.NewV7()).String() }

// Now is the timestamp every row gets: UTC, to the microsecond, which both
// SQLite and PostgreSQL store exactly (audit hashes cover it).
func Now() time.Time { return time.Now().UTC().Truncate(time.Microsecond) }

// TS formats t like stored timestamps, for the queries that compare them
// with julianday().
func TS(t time.Time) string { return t.UTC().Format("2006-01-02 15:04:05.999999999-07:00") }

func NullString(s string) sql.NullString { return sql.NullString{String: s, Valid: s != ""} }

func NullTime(t time.Time) sql.NullTime { return sql.NullTime{Time: t.UTC(), Valid: !t.IsZero()} }

// Classify maps driver errors to ErrNotFound / ErrConflict, keeping the
// original message.
func Classify(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, sql.ErrNoRows):
		return ErrNotFound
	}
	msg := err.Error()
	if strings.Contains(msg, "UNIQUE constraint failed") || strings.Contains(msg, "FOREIGN KEY constraint failed") {
		return fmt.Errorf("%w: %s", ErrConflict, msg)
	}
	// PostgreSQL: worded like SQLite's, which callers look for.
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		switch pe.Code {
		case "23505":
			return fmt.Errorf("%w: UNIQUE constraint failed: %s", ErrConflict, pe.ConstraintName)
		case "23503":
			return fmt.Errorf("%w: FOREIGN KEY constraint failed: %s", ErrConflict, pe.ConstraintName)
		}
	}
	return err
}
