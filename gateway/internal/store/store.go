// Package store is the persistence layer: SQLite (fast start) with goose
// migrations and sqlc-generated queries in package db. The schema is written
// to be portable to PostgreSQL (see migrations/00001_init.sql).
package store

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/pressly/goose/v3"
	_ "modernc.org/sqlite"

	"github.com/leandrofus/palta/gateway/internal/store/db"
)

//go:embed migrations/*.sql
var migrations embed.FS

var (
	ErrNotFound = errors.New("not found")
	ErrConflict = errors.New("conflict")
)

type Store struct {
	DB *sql.DB
	Q  *db.Queries
}

// Open opens (creating if needed) the database at path and migrates it.
func Open(path string) (*Store, error) {
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
	if err := migrate(sqldb); err != nil {
		sqldb.Close()
		return nil, err
	}
	return &Store{DB: sqldb, Q: db.New(sqldb)}, nil
}

func migrate(sqldb *sql.DB) error {
	goose.SetBaseFS(migrations)
	goose.SetLogger(goose.NopLogger())
	if err := goose.SetDialect("sqlite3"); err != nil {
		return err
	}
	if err := goose.Up(sqldb, "migrations"); err != nil {
		return fmt.Errorf("migrating: %w", err)
	}
	return nil
}

func (s *Store) Close() error { return s.DB.Close() }

// Tx runs fn in a transaction, committing if it returns nil.
func (s *Store) Tx(ctx context.Context, fn func(q *db.Queries) error) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := fn(s.Q.WithTx(tx)); err != nil {
		return err
	}
	return tx.Commit()
}

// NewID returns a time-ordered UUIDv7.
func NewID() string { return uuid.Must(uuid.NewV7()).String() }

// Now is the timestamp every row gets, in UTC.
func Now() time.Time { return time.Now().UTC() }

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
	return err
}
