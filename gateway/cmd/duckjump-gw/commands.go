package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/leandrofus/duckjump/gateway/internal/edge"
	"github.com/leandrofus/duckjump/gateway/internal/server"
	"github.com/leandrofus/duckjump/gateway/internal/services"
	"github.com/leandrofus/duckjump/gateway/internal/store"
	"github.com/leandrofus/duckjump/gateway/internal/store/db"
)

// userCmd handles `user [ls | add | rm | passwd | enable | disable]`.
func userCmd(ctx context.Context, st *store.Store, args []string) error {
	userSvc := services.NewUserService(st)

	if len(args) == 0 || args[0] == "ls" {
		users, err := userSvc.List(ctx)
		if err != nil {
			return err
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
		fmt.Fprintln(tw, "USERNAME\tROLE\tSOURCE\tDISABLED\tLAST LOGIN")
		for _, u := range users {
			lastLogin := "-"
			if u.LastLoginAt.Valid {
				lastLogin = u.LastLoginAt.Time.Local().Format(time.DateTime)
			}
			disabled := "no"
			if u.Disabled {
				disabled = "yes"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", u.Username, u.Role, u.Source, disabled, lastLogin)
		}
		return tw.Flush()
	}

	sub := args[0]
	rest := args[1:]
	if strings.HasPrefix(sub, "-") {
		sub = "add"
		rest = args
	}

	switch sub {
	case "add":
		fs := flag.NewFlagSet("user add", flag.ExitOnError)
		name := fs.String("name", "", "username")
		password := fs.String("password", "", "password (at least 10 characters)")
		role := fs.String("role", "user", "superadmin | admin | auditor | user")
		if len(rest) > 0 && !strings.HasPrefix(rest[0], "-") {
			*name = rest[0]
			rest = rest[1:]
		}
		fs.Parse(rest)
		if *name == "" {
			return fmt.Errorf("need username: duckjump user add <name> --password <pass>")
		}
		u, err := userSvc.Create(ctx, services.CreateUserParams{
			Username:   *name,
			Password:   *password,
			Role:       *role,
			CallerRole: "superadmin",
			Actor:      cli,
		})
		if err != nil {
			return err
		}
		fmt.Printf("user %s created (%s)\n", u.Username, u.Role)
		return nil

	case "rm":
		if len(rest) < 1 {
			return fmt.Errorf("usage: duckjump user rm <username>")
		}
		name := strings.ToLower(rest[0])
		u, err := userSvc.GetByUsername(ctx, name)
		if err != nil {
			return fmt.Errorf("user %q: %w", name, err)
		}
		if err := userSvc.Delete(ctx, cli, "", "superadmin", u.ID); err != nil {
			return err
		}
		fmt.Printf("user %s deleted\n", name)
		return nil

	case "passwd":
		fs := flag.NewFlagSet("user passwd", flag.ExitOnError)
		password := fs.String("password", "", "new password")
		var name string
		if len(rest) > 0 && !strings.HasPrefix(rest[0], "-") {
			name = strings.ToLower(rest[0])
			rest = rest[1:]
		}
		fs.Parse(rest)
		if name == "" {
			return fmt.Errorf("usage: duckjump user passwd <username> [--password <newpass>]")
		}
		u, err := userSvc.GetByUsername(ctx, name)
		if err != nil {
			return fmt.Errorf("user %q: %w", name, err)
		}
		if err := userSvc.SetPassword(ctx, cli, "superadmin", u.ID, *password); err != nil {
			return err
		}
		fmt.Printf("password updated for user %s\n", name)
		return nil

	case "disable", "enable":
		if len(rest) < 1 {
			return fmt.Errorf("usage: duckjump user %s <username>", sub)
		}
		name := strings.ToLower(rest[0])
		disabled := (sub == "disable")
		u, err := userSvc.GetByUsername(ctx, name)
		if err != nil {
			return fmt.Errorf("user %q: %w", name, err)
		}
		if _, err := userSvc.Update(ctx, services.UpdateUserParams{
			ID:         u.ID,
			Disabled:   &disabled,
			CallerRole: "superadmin",
			Actor:      cli,
		}); err != nil {
			return err
		}
		status := "enabled"
		if disabled {
			status = "disabled"
		}
		fmt.Printf("user %s %s\n", name, status)
		return nil

	default:
		return fmt.Errorf("usage: duckjump user [ls | add <name> --password <p> | rm <name> | passwd <name> | enable <name> | disable <name>]")
	}
}

// connCmd handles `conn [ls | add | rm | tag]`.
func connCmd(ctx context.Context, st *store.Store, args []string) error {
	connSvc := services.NewConnectionService(st)

	if len(args) == 0 || args[0] == "ls" {
		conns, err := connSvc.List(ctx)
		if err != nil {
			return err
		}
		secMap := make(map[string]string)
		if secs, err := st.Q.ListSecrets(ctx); err == nil {
			for _, s := range secs {
				secMap[s.ID] = s.Name
			}
		}
		siteMap := make(map[string]string)
		if sites, err := st.Q.ListSites(ctx); err == nil {
			for _, s := range sites {
				siteMap[s.ID] = s.Name
			}
		}
		tagMap, _ := connSvc.TagIndex(ctx)
		tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
		fmt.Fprintln(tw, "NAME\tPROTOCOL\tHOST:PORT\tSECRET\tSITE\tTAGS\tRECORD")
		for _, c := range conns {
			sec := "-"
			if c.SecretID.Valid {
				if n, ok := secMap[c.SecretID.String]; ok {
					sec = n
				} else {
					sec = c.SecretID.String
				}
			}
			site := "-"
			if c.SiteID.Valid {
				if n, ok := siteMap[c.SiteID.String]; ok {
					site = n
				} else {
					site = c.SiteID.String
				}
			}
			tags := "-"
			if tg := tagMap[c.ID]; len(tg) > 0 {
				tags = strings.Join(tg, ",")
			}
			rec := "no"
			if c.Record {
				rec = "yes"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s:%d\t%s\t%s\t%s\t%s\n", c.Name, c.Protocol, c.Host, c.Port, sec, site, tags, rec)
		}
		return tw.Flush()
	}

	sub := args[0]
	rest := args[1:]
	if strings.HasPrefix(sub, "-") {
		sub = "add"
		rest = args
	}

	switch sub {
	case "add":
		fs := flag.NewFlagSet("conn add", flag.ExitOnError)
		name := fs.String("name", "", "connection name")
		protocol := fs.String("protocol", "ssh", "ssh | rdp | vnc | tcp | http | https")
		host := fs.String("host", "", "target host")
		port := fs.Int("port", 0, "target port (defaults: ssh 22, rdp 3389, vnc 5900, http 80, https 443)")
		vhost := fs.String("vhost", "", "virtual host header for HTTP virtual servers")
		secret := fs.String("secret", "", "vaulted credential name")
		site := fs.String("site", "", "site the host belongs to (default: reachable directly)")
		folder := fs.String("folder", "", "folder name to place the connection in")
		noRecord := fs.Bool("no-record", false, "do not record sessions")
		recInput := fs.Bool("record-input", false, "also record keystrokes")
		hostKey := fs.String("host-key", "", "pin this server key (SHA256:...) up front")
		if len(rest) > 0 && !strings.HasPrefix(rest[0], "-") {
			*name = rest[0]
			rest = rest[1:]
		}
		fs.Parse(rest)
		if *name == "" || *host == "" {
			return fmt.Errorf("need name and host: duckjump conn add <name> --host <host>")
		}
		if *hostKey != "" && !strings.HasPrefix(*hostKey, "SHA256:") {
			return fmt.Errorf("-host-key must look like SHA256:...")
		}

		var secretID *string
		if *secret != "" {
			sec, err := st.Q.GetSecretByName(ctx, *secret)
			if err != nil {
				return fmt.Errorf("secret %q: %w", *secret, store.Classify(err))
			}
			secretID = &sec.ID
		}
		var siteID *string
		if *site != "" {
			s, err := st.Q.GetSiteByName(ctx, *site)
			if err != nil {
				return fmt.Errorf("site %q: %w", *site, store.Classify(err))
			}
			siteID = &s.ID
		}
		var folderID *string
		if *folder != "" {
			folders, err := st.Q.ListFolders(ctx)
			if err == nil {
				for _, f := range folders {
					if f.Name == *folder {
						folderID = &f.ID
						break
					}
				}
			}
			if folderID == nil {
				return fmt.Errorf("folder %q not found", *folder)
			}
		}

		paramsMap := map[string]any{}
		if *vhost != "" {
			paramsMap["virtual_host"] = *vhost
		}
		paramsBytes, _ := json.Marshal(paramsMap)
		record := !*noRecord

		res, err := connSvc.Create(ctx, services.CreateConnectionParams{
			Name:           *name,
			Protocol:       *protocol,
			Host:           *host,
			Port:           int64(*port),
			FolderID:       folderID,
			SiteID:         siteID,
			SecretID:       secretID,
			Params:         string(paramsBytes),
			Record:         &record,
			RecordInput:    *recInput,
			HostKey:        *hostKey,
			Actor:          cli,
		})
		if err != nil {
			return err
		}
		fmt.Printf("connection %s created (%s)\n", res.Connection.Name, res.Connection.ID)
		return nil

	case "rm":
		if len(rest) < 1 {
			return fmt.Errorf("usage: duckjump conn rm <name>")
		}
		name := rest[0]
		c, err := connSvc.GetByName(ctx, name)
		if err != nil {
			return fmt.Errorf("connection %q: %w", name, err)
		}
		if err := connSvc.Delete(ctx, cli, c.ID); err != nil {
			return err
		}
		fmt.Printf("connection %s deleted\n", name)
		return nil

	case "tag":
		if len(rest) < 2 {
			return fmt.Errorf("usage: duckjump conn tag [ls <conn> | add <conn> <tag>... | clear <conn>]")
		}
		tagAction := rest[0]
		connName := rest[1]
		c, err := connSvc.GetByName(ctx, connName)
		if err != nil {
			return fmt.Errorf("connection %q: %w", connName, err)
		}
		switch tagAction {
		case "ls":
			tags, err := connSvc.ListTags(ctx, c.ID)
			if err != nil {
				return err
			}
			for _, t := range tags {
				fmt.Println(t)
			}
			return nil
		case "add":
			if len(rest) < 3 {
				return fmt.Errorf("usage: duckjump conn tag add <conn> <tag>...")
			}
			if err := connSvc.AddTags(ctx, cli, c.ID, rest[2:]); err != nil {
				return err
			}
			fmt.Printf("tags added to %s: %s\n", connName, strings.Join(rest[2:], ", "))
			return nil
		case "clear", "rm":
			if err := connSvc.ClearTags(ctx, cli, c.ID); err != nil {
				return err
			}
			fmt.Printf("tags cleared for %s\n", connName)
			return nil
		default:
			return fmt.Errorf("usage: duckjump conn tag [ls <conn> | add <conn> <tag>... | clear <conn>]")
		}

	default:
		return fmt.Errorf("usage: duckjump conn [ls | add <name> --host <h> | rm <name> | tag ...]")
	}
}

// secretCmd handles `secret [ls | add | rm]`.
func secretCmd(ctx context.Context, st *store.Store, args []string) error {
	if len(args) == 0 || args[0] == "ls" {
		secs, err := st.Q.ListSecrets(ctx)
		if err != nil {
			return err
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
		fmt.Fprintln(tw, "NAME\tKIND\tUSERNAME\tCONNECTIONS\tUPDATED")
		for _, s := range secs {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%s\n", s.Name, s.Kind, s.Username, s.ConnectionCount, s.UpdatedAt.Local().Format(time.DateTime))
		}
		return tw.Flush()
	}

	sub := args[0]
	rest := args[1:]
	if strings.HasPrefix(sub, "-") {
		sub = "add"
		rest = args
	}

	switch sub {
	case "add":
		fs := flag.NewFlagSet("secret add", flag.ExitOnError)
		name := fs.String("name", "", "secret name")
		user := fs.String("user", "", "remote username")
		password := fs.String("password", "", "remote password")
		keyFile := fs.String("key-file", "", "private key file (OpenSSH/PEM)")
		if len(rest) > 0 && !strings.HasPrefix(rest[0], "-") {
			*name = rest[0]
			rest = rest[1:]
		}
		fs.Parse(rest)
		if *name == "" || *user == "" || (*password == "") == (*keyFile == "") {
			return fmt.Errorf("need name, user and exactly one of --password or --key-file")
		}
		v, err := openVault()
		if err != nil {
			return err
		}
		kind, plain := "password", []byte(*password)
		if *keyFile != "" {
			if plain, err = os.ReadFile(*keyFile); err != nil {
				return err
			}
			kind = "private_key"
		}
		id := store.NewID()
		return st.Tx(ctx, func(q *db.Queries) error {
			if err := q.CreateSecret(ctx, db.CreateSecretParams{
				ID: id, Name: *name, Kind: kind, Username: *user,
				Sealed: v.Seal(plain, []byte(id)), Now: store.Now(),
			}); err != nil {
				return store.Classify(err)
			}
			fmt.Printf("secret %s stored (%s)\n", *name, kind)
			return store.Audit(ctx, q, store.Event{
				Actor: cli, Action: "secret.create", ObjectType: "secret", ObjectID: id,
				Details: map[string]any{"name": *name, "kind": kind, "username": *user},
			})
		})

	case "rm":
		if len(rest) < 1 {
			return fmt.Errorf("usage: duckjump secret rm <name>")
		}
		name := rest[0]
		return st.Tx(ctx, func(q *db.Queries) error {
			s, err := q.GetSecretByName(ctx, name)
			if err != nil {
				return fmt.Errorf("secret %q: %w", name, store.Classify(err))
			}
			n, err := q.DeleteSecret(ctx, s.ID)
			if err != nil {
				return err
			}
			if n == 0 {
				return fmt.Errorf("secret %q not found", name)
			}
			fmt.Printf("secret %s deleted\n", name)
			return store.Audit(ctx, q, store.Event{
				Actor: cli, Action: "secret.delete", ObjectType: "secret", ObjectID: s.ID,
				Details: map[string]any{"name": name},
			})
		})

	default:
		return fmt.Errorf("usage: duckjump secret [ls | add <name> --user <u> ... | rm <name>]")
	}
}

// siteCmd handles `site [ls | add | rm | token]`.
func siteCmd(ctx context.Context, st *store.Store, args []string) error {
	if len(args) == 0 || args[0] == "ls" {
		sites, err := st.Q.ListSites(ctx)
		if err != nil {
			return err
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
		fmt.Fprintln(tw, "NAME\tKIND\tCONNECTIONS\tCREATED")
		for _, s := range sites {
			fmt.Fprintf(tw, "%s\t%s\t%d\t%s\n", s.Name, s.Kind, s.ConnectionCount, s.CreatedAt.Local().Format(time.DateTime))
		}
		return tw.Flush()
	}

	sub := args[0]
	rest := args[1:]
	if strings.HasPrefix(sub, "-") {
		sub = "add"
		rest = args
	}

	switch sub {
	case "add":
		fs := flag.NewFlagSet("site add", flag.ExitOnError)
		name := fs.String("name", "", "site name")
		direct := fs.Bool("direct", false, "hosts reachable directly without agent")
		if len(rest) > 0 && !strings.HasPrefix(rest[0], "-") {
			*name = rest[0]
			rest = rest[1:]
		}
		fs.Parse(rest)
		if *name == "" {
			return fmt.Errorf("need site name: duckjump site add <name> [--direct]")
		}
		kind, tok, hash := "agent", edge.NewToken(), ""
		if *direct {
			kind, tok = "direct", ""
		} else {
			hash = edge.HashToken(tok)
		}
		id := store.NewID()
		return st.Tx(ctx, func(q *db.Queries) error {
			if err := q.CreateSite(ctx, db.CreateSiteParams{
				ID: id, Name: *name, Kind: kind, AgentTokenHash: store.NullString(hash), Now: store.Now(),
			}); err != nil {
				return store.Classify(err)
			}
			if tok != "" {
				fmt.Printf("site %s created (agent). Agent token, shown only once:\n%s\n", *name, tok)
			} else {
				fmt.Printf("site %s created (direct)\n", *name)
			}
			return store.Audit(ctx, q, store.Event{
				Actor: cli, Action: "site.create", ObjectType: "site", ObjectID: id,
				Details: map[string]any{"name": *name, "kind": kind},
			})
		})

	case "rm":
		if len(rest) < 1 {
			return fmt.Errorf("usage: duckjump site rm <name>")
		}
		name := rest[0]
		return st.Tx(ctx, func(q *db.Queries) error {
			s, err := q.GetSiteByName(ctx, name)
			if err != nil {
				return fmt.Errorf("site %q: %w", name, store.Classify(err))
			}
			n, err := q.DeleteSite(ctx, s.ID)
			if err != nil {
				return err
			}
			if n == 0 {
				return fmt.Errorf("site %q not found", name)
			}
			fmt.Printf("site %s deleted\n", name)
			return store.Audit(ctx, q, store.Event{
				Actor: cli, Action: "site.delete", ObjectType: "site", ObjectID: s.ID,
				Details: map[string]any{"name": name},
			})
		})

	case "token":
		if len(rest) < 1 {
			return fmt.Errorf("usage: duckjump site token <name>")
		}
		name := rest[0]
		return st.Tx(ctx, func(q *db.Queries) error {
			s, err := q.GetSiteByName(ctx, name)
			if err != nil {
				return fmt.Errorf("site %q: %w", name, store.Classify(err))
			}
			if s.Kind != "agent" {
				return fmt.Errorf("site %s is a direct site (no agent token)", name)
			}
			tok := edge.NewToken()
			hash := edge.HashToken(tok)
			if err := q.SetSiteToken(ctx, db.SetSiteTokenParams{
				ID: s.ID, AgentTokenHash: store.NullString(hash),
			}); err != nil {
				return err
			}
			fmt.Printf("new agent token for %s (shown only once):\n%s\n", name, tok)
			return store.Audit(ctx, q, store.Event{
				Actor: cli, Action: "site.token_rotate", ObjectType: "site", ObjectID: s.ID,
				Details: map[string]any{"name": name},
			})
		})

	default:
		return fmt.Errorf("usage: duckjump site [ls | add <name> | rm <name> | token <name>]")
	}
}

// grantCmd handles `grant [ls | add | rm]`.
func grantCmd(ctx context.Context, st *store.Store, args []string) error {
	polSvc := services.NewPolicyService(st)
	userSvc := services.NewUserService(st)
	connSvc := services.NewConnectionService(st)

	if len(args) == 0 || args[0] == "ls" {
		policies, err := polSvc.List(ctx, "", "")
		if err != nil {
			return err
		}
		userMap := make(map[string]string)
		if users, err := userSvc.List(ctx); err == nil {
			for _, u := range users {
				userMap[u.ID] = u.Username
			}
		}
		connMap := make(map[string]string)
		if conns, err := connSvc.List(ctx); err == nil {
			for _, c := range conns {
				connMap[c.ID] = c.Name
			}
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
		fmt.Fprintln(tw, "ID\tSUBJECT\tOBJECT\tPERMISSIONS\tEXPIRES")
		for _, p := range policies {
			subj := p.SubjectType + ":" + p.SubjectID
			if p.SubjectType == "user" {
				if name, ok := userMap[p.SubjectID]; ok {
					subj = "user:" + name
				}
			}
			obj := p.ObjectType + ":" + p.ObjectRef
			if p.ObjectType == "connection" {
				if name, ok := connMap[p.ObjectRef]; ok {
					obj = "conn:" + name
				}
			}
			var perms []string
			if p.CanConnect {
				perms = append(perms, "connect")
			}
			if p.CanUpload {
				perms = append(perms, "upload")
			}
			if p.CanDownload {
				perms = append(perms, "download")
			}
			if p.CanForward {
				perms = append(perms, "forward")
			}
			exp := "permanent"
			if p.ExpiresAt.Valid {
				exp = p.ExpiresAt.Time.Local().Format(time.DateTime)
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", p.ID, subj, obj, strings.Join(perms, ","), exp)
		}
		return tw.Flush()
	}

	sub := args[0]
	rest := args[1:]
	if strings.HasPrefix(sub, "-") {
		sub = "add"
		rest = args
	}

	switch sub {
	case "add":
		fs := flag.NewFlagSet("grant add", flag.ExitOnError)
		user := fs.String("user", "", "username")
		conn := fs.String("conn", "", "connection name")
		ttl := fs.Duration("ttl", 0, "access duration (0 = permanent)")
		upload := fs.Bool("upload", false, "allow sending files to host")
		download := fs.Bool("download", false, "allow taking files from host")
		forward := fs.Bool("forward", false, "allow port forwarding to host")
		fs.Parse(rest)
		if *user == "" || *conn == "" {
			return fmt.Errorf("need --user and --conn: duckjump grant add --user <u> --conn <c>")
		}
		u, err := userSvc.GetByUsername(ctx, *user)
		if err != nil {
			return fmt.Errorf("user %q: %w", *user, err)
		}
		c, err := connSvc.GetByName(ctx, *conn)
		if err != nil {
			return fmt.Errorf("connection %q: %w", *conn, err)
		}
		var ttlSecs int64
		if *ttl > 0 {
			ttlSecs = int64(ttl.Seconds())
		}
		if _, err := polSvc.Create(ctx, services.CreatePolicyParams{
			SubjectType: "user",
			SubjectID:   u.ID,
			ObjectType:  "connection",
			ObjectRef:   c.ID,
			CanUpload:   *upload,
			CanDownload: *download,
			CanForward:  *forward,
			TTLSeconds:  ttlSecs,
			Actor:       cli,
		}); err != nil {
			return err
		}
		fmt.Printf("granted %s -> %s\n", *user, *conn)
		return nil

	case "rm":
		if len(rest) < 1 {
			return fmt.Errorf("usage: duckjump grant rm <policy-id>")
		}
		id := rest[0]
		if err := polSvc.Delete(ctx, cli, id); err != nil {
			return fmt.Errorf("grant %q: %w", id, err)
		}
		fmt.Printf("grant %s deleted\n", id)
		return nil

	default:
		return fmt.Errorf("usage: duckjump grant [ls | add --user <u> --conn <c> | rm <id>]")
	}
}

// groupCmd handles `group [ls | add | rm | member]`.
func groupCmd(ctx context.Context, st *store.Store, args []string) error {
	if len(args) == 0 || args[0] == "ls" {
		groups, err := st.Q.ListGroups(ctx)
		if err != nil {
			return err
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
		fmt.Fprintln(tw, "NAME\tSOURCE\tMEMBERS\tDESCRIPTION")
		for _, g := range groups {
			fmt.Fprintf(tw, "%s\t%s\t%d\t%s\n", g.Name, g.Source, g.MemberCount, g.Description)
		}
		return tw.Flush()
	}

	switch args[0] {
	case "add":
		fs := flag.NewFlagSet("group add", flag.ExitOnError)
		desc := fs.String("desc", "", "group description")
		var name string
		rest := args[1:]
		if len(rest) > 0 && !strings.HasPrefix(rest[0], "-") {
			name = rest[0]
			rest = rest[1:]
		}
		fs.Parse(rest)
		if name == "" {
			return fmt.Errorf("usage: duckjump group add <name> [--desc \"...\"]")
		}
		id := store.NewID()
		return st.Tx(ctx, func(q *db.Queries) error {
			if err := q.CreateGroup(ctx, db.CreateGroupParams{
				ID: id, Name: name, Description: *desc, Source: "local", Now: store.Now(),
			}); err != nil {
				return store.Classify(err)
			}
			fmt.Printf("group %s created\n", name)
			return store.Audit(ctx, q, store.Event{
				Actor: cli, Action: "group.create", ObjectType: "group", ObjectID: id,
				Details: map[string]any{"name": name},
			})
		})

	case "rm":
		if len(args) < 2 {
			return fmt.Errorf("usage: duckjump group rm <name>")
		}
		name := args[1]
		return st.Tx(ctx, func(q *db.Queries) error {
			g, err := q.GetGroupByName(ctx, name)
			if err != nil {
				return fmt.Errorf("group %q: %w", name, store.Classify(err))
			}
			n, err := q.DeleteGroup(ctx, g.ID)
			if err != nil {
				return err
			}
			if n == 0 {
				return fmt.Errorf("group %q not found", name)
			}
			fmt.Printf("group %s deleted\n", name)
			return store.Audit(ctx, q, store.Event{
				Actor: cli, Action: "group.delete", ObjectType: "group", ObjectID: g.ID,
				Details: map[string]any{"name": name},
			})
		})

	case "member":
		if len(args) < 3 {
			return fmt.Errorf("usage: duckjump group member [ls <group> | add <group> <user> | rm <group> <user>]")
		}
		action := args[1]
		groupName := args[2]
		g, err := st.Q.GetGroupByName(ctx, groupName)
		if err != nil {
			return fmt.Errorf("group %q: %w", groupName, store.Classify(err))
		}
		switch action {
		case "ls":
			members, err := st.Q.ListGroupMembers(ctx, g.ID)
			if err != nil {
				return err
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
			fmt.Fprintln(tw, "USERNAME\tROLE\tSOURCE")
			for _, m := range members {
				fmt.Fprintf(tw, "%s\t%s\t%s\n", m.Username, m.Role, m.Source)
			}
			return tw.Flush()
		case "add":
			if len(args) < 4 {
				return fmt.Errorf("usage: duckjump group member add <group> <user>")
			}
			userName := strings.ToLower(args[3])
			u, err := st.Q.GetUserByUsername(ctx, userName)
			if err != nil {
				return fmt.Errorf("user %q: %w", userName, store.Classify(err))
			}
			return st.Tx(ctx, func(q *db.Queries) error {
				if err := q.AddGroupMember(ctx, db.AddGroupMemberParams{GroupID: g.ID, UserID: u.ID}); err != nil {
					return err
				}
				fmt.Printf("user %s added to group %s\n", userName, groupName)
				return store.Audit(ctx, q, store.Event{
					Actor: cli, Action: "group.member_add", ObjectType: "group", ObjectID: g.ID,
					Details: map[string]any{"group": groupName, "user": userName},
				})
			})
		case "rm":
			if len(args) < 4 {
				return fmt.Errorf("usage: duckjump group member rm <group> <user>")
			}
			userName := strings.ToLower(args[3])
			u, err := st.Q.GetUserByUsername(ctx, userName)
			if err != nil {
				return fmt.Errorf("user %q: %w", userName, store.Classify(err))
			}
			return st.Tx(ctx, func(q *db.Queries) error {
				_, err := q.RemoveGroupMember(ctx, db.RemoveGroupMemberParams{GroupID: g.ID, UserID: u.ID})
				if err != nil {
					return err
				}
				fmt.Printf("user %s removed from group %s\n", userName, groupName)
				return store.Audit(ctx, q, store.Event{
					Actor: cli, Action: "group.member_remove", ObjectType: "group", ObjectID: g.ID,
					Details: map[string]any{"group": groupName, "user": userName},
				})
			})
		default:
			return fmt.Errorf("usage: duckjump group member [ls <group> | add <group> <user> | rm <group> <user>]")
		}

	default:
		return fmt.Errorf("usage: duckjump group [ls | add <name> | rm <name> | member ...]")
	}
}

// folderCmd handles `folder [ls | add | rm]`.
func folderCmd(ctx context.Context, st *store.Store, args []string) error {
	if len(args) == 0 || args[0] == "ls" {
		folders, err := st.Q.ListFolders(ctx)
		if err != nil {
			return err
		}
		parentMap := make(map[string]string)
		for _, f := range folders {
			parentMap[f.ID] = f.Name
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
		fmt.Fprintln(tw, "NAME\tPARENT\tCREATED")
		for _, f := range folders {
			parent := "-"
			if f.ParentID.Valid {
				if pName, ok := parentMap[f.ParentID.String]; ok {
					parent = pName
				}
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\n", f.Name, parent, f.CreatedAt.Local().Format(time.DateTime))
		}
		return tw.Flush()
	}

	switch args[0] {
	case "add":
		fs := flag.NewFlagSet("folder add", flag.ExitOnError)
		parentName := fs.String("parent", "", "parent folder name")
		var name string
		rest := args[1:]
		if len(rest) > 0 && !strings.HasPrefix(rest[0], "-") {
			name = rest[0]
			rest = rest[1:]
		}
		fs.Parse(rest)
		if name == "" {
			return fmt.Errorf("usage: duckjump folder add <name> [--parent <parent>]")
		}
		var parentID string
		if *parentName != "" {
			folders, _ := st.Q.ListFolders(ctx)
			for _, f := range folders {
				if f.Name == *parentName {
					parentID = f.ID
					break
				}
			}
			if parentID == "" {
				return fmt.Errorf("parent folder %q not found", *parentName)
			}
		}
		id := store.NewID()
		return st.Tx(ctx, func(q *db.Queries) error {
			if err := q.CreateFolder(ctx, db.CreateFolderParams{
				ID: id, ParentID: store.NullString(parentID), Name: name, Now: store.Now(),
			}); err != nil {
				return store.Classify(err)
			}
			fmt.Printf("folder %s created\n", name)
			return store.Audit(ctx, q, store.Event{
				Actor: cli, Action: "folder.create", ObjectType: "folder", ObjectID: id,
				Details: map[string]any{"name": name},
			})
		})

	case "rm":
		if len(args) < 2 {
			return fmt.Errorf("usage: duckjump folder rm <name>")
		}
		name := args[1]
		folders, err := st.Q.ListFolders(ctx)
		if err != nil {
			return err
		}
		var fID string
		for _, f := range folders {
			if f.Name == name {
				fID = f.ID
				break
			}
		}
		if fID == "" {
			return fmt.Errorf("folder %q not found", name)
		}
		return st.Tx(ctx, func(q *db.Queries) error {
			n, err := q.DeleteFolder(ctx, fID)
			if err != nil {
				return err
			}
			if n == 0 {
				return fmt.Errorf("folder %q not found", name)
			}
			fmt.Printf("folder %s deleted\n", name)
			return store.Audit(ctx, q, store.Event{
				Actor: cli, Action: "folder.delete", ObjectType: "folder", ObjectID: fID,
				Details: map[string]any{"name": name},
			})
		})

	default:
		return fmt.Errorf("usage: duckjump folder [ls | add <name> [--parent <p>] | rm <name>]")
	}
}

// requestCmd handles `request [ls | approve | deny]`.
func requestCmd(ctx context.Context, st *store.Store, args []string) error {
	if len(args) == 0 || args[0] == "ls" {
		status := ""
		if len(args) > 1 {
			status = args[1]
		}
		reqs, err := st.Q.ListAccessRequests(ctx, db.ListAccessRequestsParams{
			Status: status,
		})
		if err != nil {
			return err
		}
		userMap := make(map[string]string)
		if users, err := st.Q.ListUsers(ctx); err == nil {
			for _, u := range users {
				userMap[u.ID] = u.Username
			}
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
		fmt.Fprintln(tw, "ID\tUSER\tOBJECT\tSTATUS\tREASON\tCREATED")
		for _, r := range reqs {
			userName := r.UserID
			if n, ok := userMap[r.UserID]; ok {
				userName = n
			}
			obj := r.ObjectType + ":" + r.ObjectRef
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", r.ID, userName, obj, r.Status, r.Reason, r.CreatedAt.Local().Format(time.DateTime))
		}
		return tw.Flush()
	}

	switch args[0] {
	case "approve":
		fs := flag.NewFlagSet("request approve", flag.ExitOnError)
		comment := fs.String("comment", "", "review comment")
		var id string
		rest := args[1:]
		if len(rest) > 0 && !strings.HasPrefix(rest[0], "-") {
			id = rest[0]
			rest = rest[1:]
		}
		fs.Parse(rest)
		if id == "" {
			return fmt.Errorf("usage: duckjump request approve <request-id> [--comment \"...\"]")
		}
		return st.Tx(ctx, func(q *db.Queries) error {
			req, err := q.GetAccessRequest(ctx, id)
			if err != nil {
				return fmt.Errorf("request %q: %w", id, store.Classify(err))
			}
			if req.Status != "pending" {
				return fmt.Errorf("request %s is already %s", id, req.Status)
			}
			policyID := store.NewID()
			now := store.Now()
			if err := q.CreatePolicy(ctx, db.CreatePolicyParams{
				ID: policyID, SubjectType: "user", SubjectID: req.UserID, ObjectType: req.ObjectType, ObjectRef: req.ObjectRef,
				CanConnect: req.CanConnect, CanViewRecordings: req.CanViewRecordings, CanUpload: req.CanUpload, CanDownload: req.CanDownload,
				StartsAt: store.NullTime(req.StartsAt), ExpiresAt: store.NullTime(req.EndsAt), Description: "approved request: " + req.Reason,
				CreatedBy: store.NullString("cli"), Now: now,
			}); err != nil {
				return err
			}
			if err := q.ApproveAccessRequest(ctx, db.ApproveAccessRequestParams{
				ID: id, ReviewedBy: store.NullString("cli"), ReviewedAt: store.NullTime(now),
				ReviewComment: *comment, CreatedPolicyID: store.NullString(policyID),
			}); err != nil {
				return err
			}
			fmt.Printf("access request %s approved (policy %s created)\n", id, policyID)
			return store.Audit(ctx, q, store.Event{
				Actor: cli, Action: "access_request.approve", ObjectType: "access_request", ObjectID: id,
				Details: map[string]any{"policy_id": policyID, "comment": *comment},
			})
		})

	case "deny", "reject":
		fs := flag.NewFlagSet("request deny", flag.ExitOnError)
		comment := fs.String("comment", "", "review comment")
		var id string
		rest := args[1:]
		if len(rest) > 0 && !strings.HasPrefix(rest[0], "-") {
			id = rest[0]
			rest = rest[1:]
		}
		fs.Parse(rest)
		if id == "" {
			return fmt.Errorf("usage: duckjump request deny <request-id> [--comment \"...\"]")
		}
		return st.Tx(ctx, func(q *db.Queries) error {
			req, err := q.GetAccessRequest(ctx, id)
			if err != nil {
				return fmt.Errorf("request %q: %w", id, store.Classify(err))
			}
			if req.Status != "pending" {
				return fmt.Errorf("request %s is already %s", id, req.Status)
			}
			now := store.Now()
			if err := q.RejectAccessRequest(ctx, db.RejectAccessRequestParams{
				ID: id, ReviewedBy: store.NullString("cli"), ReviewedAt: store.NullTime(now),
				ReviewComment: *comment,
			}); err != nil {
				return err
			}
			fmt.Printf("access request %s rejected\n", id)
			return store.Audit(ctx, q, store.Event{
				Actor: cli, Action: "access_request.reject", ObjectType: "access_request", ObjectID: id,
				Details: map[string]any{"comment": *comment},
			})
		})

	default:
		return fmt.Errorf("usage: duckjump request [ls | approve <id> | deny <id>]")
	}
}

// auditCmd handles `audit [ls | verify | seal]`.
func auditCmd(ctx context.Context, st *store.Store, args []string) error {
	if len(args) == 0 || args[0] == "ls" {
		fs := flag.NewFlagSet("audit ls", flag.ExitOnError)
		lim := fs.Int64("limit", 50, "max events to show")
		action := fs.String("action", "", "filter by action (e.g. session.start)")
		rest := args
		if len(rest) > 0 && rest[0] == "ls" {
			rest = rest[1:]
		}
		fs.Parse(rest)

		events, err := st.Q.ListAuditEvents(ctx, db.ListAuditEventsParams{
			Lim:    *lim,
			Action: *action,
		})
		if err != nil {
			return err
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
		fmt.Fprintln(tw, "ID\tTIME\tACTOR\tACTION\tOBJECT\tDETAILS")
		for _, e := range events {
			obj := e.ObjectType
			if e.ObjectID != "" {
				obj += ":" + e.ObjectID
			}
			details := e.Details
			if len(details) > 40 {
				details = details[:37] + "..."
			}
			fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\t%s\n", e.ID, e.Ts.Local().Format(time.DateTime), e.ActorName, e.Action, obj, details)
		}
		return tw.Flush()
	}

	switch args[0] {
	case "verify":
		res, err := st.VerifyAudit(ctx)
		if err != nil {
			return err
		}
		if !res.OK {
			return fmt.Errorf("audit chain BROKEN at event %d: %s", res.BrokenAt, res.Reason)
		}
		sealStatus := "unsealed"
		if res.Sealed {
			sealStatus = "sealed (MAC chain verified)"
		}
		fmt.Printf("audit chain verified ✓ (%d events, %s)\n", res.Events, sealStatus)
		return nil

	case "seal":
		return auditSeal(ctx, st, args[1:])

	default:
		return fmt.Errorf("usage: duckjump audit [ls | verify | seal]")
	}
}

// recordingCmd handles `recording [ls]`.
func recordingCmd(ctx context.Context, st *store.Store, args []string) error {
	recs, err := st.Q.LiveRecordings(ctx)
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "SESSION ID\tRECORDING\tSTARTED\tENDED")
	for _, r := range recs {
		recName := r.Recording.String
		ended := "-"
		if r.EndedAt.Valid {
			ended = r.EndedAt.Time.Local().Format(time.DateTime)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", r.ID, recName, r.StartedAt.Local().Format(time.DateTime), ended)
	}
	return tw.Flush()
}

// sessionCmd handles `session [ls | kill]`.
func sessionCmd(ctx context.Context, st *store.Store, args []string) error {
	if len(args) == 0 || args[0] == "ls" {
		return listSessions(ctx, st, args)
	}
	switch args[0] {
	case "kill":
		rest := args[1:]
		fs := flag.NewFlagSet("session kill", flag.ExitOnError)
		id := fs.String("session", "", "session id")
		reason := fs.String("reason", "", "termination reason")
		if len(rest) > 0 && !strings.HasPrefix(rest[0], "-") {
			*id = rest[0]
			rest = rest[1:]
		}
		fs.Parse(rest)
		if *id == "" {
			return fmt.Errorf("usage: duckjump session kill <session-id> [--reason \"...\"]")
		}
		return st.Tx(ctx, func(q *db.Queries) error {
			x, err := q.GetSessionRecord(ctx, *id)
			if err != nil {
				return fmt.Errorf("session %q: %w", *id, store.Classify(err))
			}
			if x.EndedAt.Valid {
				return fmt.Errorf("session %s already ended", *id)
			}
			if err := server.RequestKill(ctx, q, x.ID, cli, *reason); err != nil {
				return err
			}
			fmt.Printf("termination of %s (%s) requested; the gateway ends it within %s\n", x.ID, x.Username, server.SuperviseInterval)
			return nil
		})
	default:
		return fmt.Errorf("usage: duckjump session [ls | kill <id>]")
	}
}
