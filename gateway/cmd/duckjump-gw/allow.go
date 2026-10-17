package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/leandrofus/duckjump/gateway/internal/access"
	"github.com/leandrofus/duckjump/gateway/internal/store"
	"github.com/leandrofus/duckjump/gateway/internal/store/db"
)

func allowCmd(ctx context.Context, st *store.Store, args []string) error {
	if len(args) == 0 || args[0] == "ls" {
		entries, err := loadAllowlist(ctx, st)
		if err != nil {
			return err
		}
		fmt.Println("loopback (always)")
		for _, e := range entries {
			fmt.Println(e)
		}
		return nil
	}

	switch args[0] {
	case "add":
		if len(args) < 2 {
			return fmt.Errorf("usage: duckjump allow add <IP|CIDR|host>...")
		}
		for _, e := range args[1:] {
			if err := access.Validate(e); err != nil {
				return err
			}
		}
		entries, _ := loadAllowlist(ctx, st)
		var added []string
		for _, e := range args[1:] {
			e = strings.TrimSpace(e)
			if e != "" && !containsStr(entries, e) {
				entries = append(entries, e)
				added = append(added, e)
			}
		}
		if len(added) == 0 {
			fmt.Println("entries already in allowlist")
			return nil
		}
		if err := saveAllowlist(ctx, st, entries); err != nil {
			return err
		}
		fmt.Printf("allowed: %s\n", strings.Join(added, ", "))
		return nil

	case "rm":
		if len(args) < 2 {
			return fmt.Errorf("usage: duckjump allow rm <entry>...")
		}
		entries, _ := loadAllowlist(ctx, st)
		var kept []string
		var removed []string
		for _, e := range entries {
			if containsStr(args[1:], e) {
				removed = append(removed, e)
			} else {
				kept = append(kept, e)
			}
		}
		if len(removed) == 0 {
			fmt.Println("no matching entries found in allowlist")
			return nil
		}
		if err := saveAllowlist(ctx, st, kept); err != nil {
			return err
		}
		fmt.Printf("removed: %s\n", strings.Join(removed, ", "))
		return nil

	default:
		return fmt.Errorf("usage: duckjump allow ls | add <IP|CIDR|host>... | rm <entry>...")
	}
}

func loadAllowlist(ctx context.Context, st *store.Store) ([]string, error) {
	val, err := st.Q.GetSetting(ctx, "allowlist")
	if err != nil {
		return nil, nil
	}
	var entries []string
	if err := json.Unmarshal([]byte(val), &entries); err != nil {
		return nil, nil
	}
	return entries, nil
}

func saveAllowlist(ctx context.Context, st *store.Store, entries []string) error {
	b, err := json.Marshal(entries)
	if err != nil {
		return err
	}
	return st.Tx(ctx, func(q *db.Queries) error {
		if err := q.SetSetting(ctx, db.SetSettingParams{
			Key:       "allowlist",
			Value:     string(b),
			Now:       store.Now(),
			UpdatedBy: store.NullString("cli"),
		}); err != nil {
			return err
		}
		return store.Audit(ctx, q, store.Event{
			Actor:      cli,
			Action:     "allowlist.update",
			ObjectType: "system",
			ObjectID:   "allowlist",
			Details:    map[string]any{"entries": entries},
		})
	})
}

func containsStr(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
