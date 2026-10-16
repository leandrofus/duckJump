package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Moving a gateway from SQLite to PostgreSQL: CopyTo copies every row into an
// empty, migrated PostgreSQL database in one transaction. Audit events keep
// their ids, hashes and MACs, and the timestamp they were hashed with
// (ts_exact, when PostgreSQL's microseconds cannot hold it), so the chain
// still verifies afterwards. The source is only read.

// copyOrder lists the tables parents first.
var copyOrder = []string{
	"config_users", "config_groups", "config_group_members", "config_folders", "config_sites", "config_secrets",
	"config_connections", "config_connection_tags", "config_policies", "config_web_sessions", "config_settings",
	"audit_events", "audit_sessions", "audit_recording_purges", "audit_session_kills", "audit_files", "config_access_requests",
}

// CopyTo copies this (SQLite) store into dst (PostgreSQL, empty). It returns
// the rows copied per table.
func (s *Store) CopyTo(ctx context.Context, dst *Store) (map[string]int64, error) {
	if s.Postgres || !dst.Postgres {
		return nil, errors.New("copy goes from SQLite to PostgreSQL")
	}
	for _, t := range copyOrder {
		var n int64
		if err := dst.DB.QueryRowContext(ctx, `SELECT count(*) FROM `+t).Scan(&n); err != nil {
			return nil, err
		}
		if n > 0 {
			return nil, fmt.Errorf("the PostgreSQL database is not empty (%s has %d rows)", t, n)
		}
	}
	counts := map[string]int64{}
	tx, err := dst.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, writeLock); err != nil {
		return nil, err
	}
	for _, t := range copyOrder {
		n, err := s.copyTable(ctx, tx, t)
		if err != nil {
			return nil, fmt.Errorf("copying %s: %w", t, err)
		}
		counts[t] = n
	}
	// Audit ids were copied explicitly: move the identity past them.
	if _, err := tx.ExecContext(ctx, `SELECT setval(pg_get_serial_sequence('audit_events', 'id'), GREATEST((SELECT max(id) FROM audit_events), 1), (SELECT count(*) > 0 FROM audit_events))`); err != nil {
		return nil, err
	}
	return counts, tx.Commit()
}

// pgTypes: column -> data_type in the destination.
func pgTypes(ctx context.Context, tx *sql.Tx, table string) (map[string]string, error) {
	rows, err := tx.QueryContext(ctx, `SELECT column_name, data_type FROM information_schema.columns
		WHERE table_name = $1 AND table_schema = current_schema()`, table)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	m := map[string]string{}
	for rows.Next() {
		var c, t string
		if err := rows.Scan(&c, &t); err != nil {
			return nil, err
		}
		m[c] = t
	}
	return m, rows.Err()
}

func (s *Store) copyTable(ctx context.Context, tx *sql.Tx, table string) (int64, error) {
	types, err := pgTypes(ctx, tx, table)
	if err != nil {
		return 0, err
	}
	order := ""
	switch table {
	case "audit_events":
		order = " ORDER BY id"
	case "config_folders":
		// Parents before children.
		order = ` ORDER BY (WITH RECURSIVE d(id, depth) AS (SELECT id, 0 FROM config_folders WHERE parent_id IS NULL
			UNION ALL SELECT f.id, d.depth + 1 FROM config_folders f JOIN d ON f.parent_id = d.id)
			SELECT depth FROM d WHERE d.id = config_folders.id)`
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT * FROM `+table+order)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return 0, err
	}
	names, marks := append([]string{}, cols...), make([]string, 0, len(cols)+1)
	tsAt := -1
	for i, c := range cols {
		if _, ok := types[c]; !ok {
			return 0, fmt.Errorf("column %s missing in PostgreSQL (schema versions differ?)", c)
		}
		if table == "audit_events" && c == "ts" {
			tsAt = i
		}
		marks = append(marks, fmt.Sprintf("$%d", i+1))
	}
	exactAt := -1
	if table == "audit_events" {
		for i, c := range cols {
			if c == "ts_exact" {
				exactAt = i
			}
		}
	}
	override := ""
	if table == "audit_events" {
		override = " OVERRIDING SYSTEM VALUE"
	}
	ins, err := tx.PrepareContext(ctx, `INSERT INTO `+table+` (`+strings.Join(names, ", ")+`)`+override+` VALUES (`+strings.Join(marks, ", ")+`)`)
	if err != nil {
		return 0, err
	}
	defer ins.Close()
	var n int64
	vals := make([]any, len(cols))
	ptrs := make([]any, len(cols))
	for i := range vals {
		ptrs[i] = &vals[i]
	}
	for rows.Next() {
		if err := rows.Scan(ptrs...); err != nil {
			return n, err
		}
		args := make([]any, len(cols))
		for i, v := range vals {
			args[i] = convert(v, types[cols[i]])
		}
		// Keep the exact timestamp the event was hashed with.
		if tsAt >= 0 && exactAt >= 0 && args[exactAt] == nil {
			if ts, ok := args[tsAt].(time.Time); ok && ts.Nanosecond()%1000 != 0 {
				args[exactAt] = ts.UTC().Format(time.RFC3339Nano)
			}
		}
		if _, err := ins.ExecContext(ctx, args...); err != nil {
			return n, err
		}
		n++
	}
	return n, rows.Err()
}

// convert adapts a SQLite value to the PostgreSQL column type.
func convert(v any, pgType string) any {
	switch pgType {
	case "boolean":
		switch x := v.(type) {
		case int64:
			return x != 0
		case string:
			return x == "1" || strings.EqualFold(x, "true")
		}
	case "timestamp with time zone":
		if s, ok := v.(string); ok {
			for _, layout := range []string{"2006-01-02 15:04:05.999999999-07:00", time.RFC3339Nano} {
				if t, err := time.Parse(layout, s); err == nil {
					return t
				}
			}
		}
	case "text":
		if b, ok := v.([]byte); ok {
			return string(b)
		}
	}
	return v
}
