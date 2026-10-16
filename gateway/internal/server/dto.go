package server

import (
	"database/sql"
	"encoding/json"
	"regexp"
	"strings"
	"time"

	"github.com/leandrofus/duckjump/gateway/internal/store/db"
)

// JSON shapes returned by the API. Secrets, hashes and sealed values never
// appear here.

func strPtr(n sql.NullString) *string {
	if !n.Valid {
		return nil
	}
	return &n.String
}

func timePtr(n sql.NullTime) *time.Time {
	if !n.Valid {
		return nil
	}
	t := n.Time.UTC()
	return &t
}

// openapi:schema Role
// type: string
// enum: [superadmin, admin, auditor, user]
// description: 'superadmin manages everything; admin manages the catalog, users and policies (not superadmins); auditor reads the audit log and recordings; user opens what they are granted.'

// openapi:schema User
// type: object
// required: [id, username, display_name, email, source, role, disabled, totp_enabled, created_at, updated_at, last_login_at]
// properties:
//   id: { type: string, format: uuid }
//   username: { type: string }
//   display_name: { type: string }
//   email: { type: string }
//   source: { type: string, enum: [local, oidc] }
//   role: { $ref: '#/components/schemas/Role' }
//   disabled: { type: boolean }
//   totp_enabled: { type: boolean }
//   created_at: { type: string, format: date-time }
//   updated_at: { type: string, format: date-time }
//   last_login_at: { type: [string, 'null'], format: date-time }

type userDTO struct {
	ID          string     `json:"id"`
	Username    string     `json:"username"`
	DisplayName string     `json:"display_name"`
	Email       string     `json:"email"`
	Source      string     `json:"source"`
	Role        string     `json:"role"`
	Disabled    bool       `json:"disabled"`
	TOTPEnabled bool       `json:"totp_enabled"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	LastLoginAt *time.Time `json:"last_login_at"`
}

func toUser(u db.ConfigUser) userDTO {
	return userDTO{u.ID, u.Username, u.DisplayName, u.Email, u.Source, u.Role, u.Disabled, u.TOTPEnabled,
		u.CreatedAt.UTC(), u.UpdatedAt.UTC(), timePtr(u.LastLoginAt)}
}

// openapi:schema Group
// type: object
// required: [id, name, description, source, created_at]
// properties:
//   id: { type: string, format: uuid }
//   name: { type: string }
//   description: { type: string }
//   source: { type: string, enum: [local, oidc] }
//   member_count: { type: integer, description: Only in list responses. }
//   created_at: { type: string, format: date-time }

type groupDTO struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Source      string    `json:"source"`
	MemberCount *int64    `json:"member_count,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

func toGroup(g db.ConfigGroup) groupDTO {
	return groupDTO{ID: g.ID, Name: g.Name, Description: g.Description, Source: g.Source, CreatedAt: g.CreatedAt.UTC()}
}

// openapi:schema Folder
// type: object
// required: [id, parent_id, name, created_at]
// properties:
//   id: { type: string, format: uuid }
//   parent_id: { type: [string, 'null'], format: uuid }
//   name: { type: string }
//   created_at: { type: string, format: date-time }

type folderDTO struct {
	ID        string    `json:"id"`
	ParentID  *string   `json:"parent_id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

func toFolder(f db.ConfigFolder) folderDTO {
	return folderDTO{f.ID, strPtr(f.ParentID), f.Name, f.CreatedAt.UTC()}
}

// openapi:schema Site
// type: object
// required: [id, name, kind, description, created_at]
// properties:
//   id: { type: string, format: uuid }
//   name: { type: string }
//   kind: { type: string, enum: [direct, agent] }
//   description: { type: string }
//   connection_count: { type: integer, description: Only in list responses. }
//   agents_online: { type: integer, description: Agent sites only. }
//   created_at: { type: string, format: date-time }
//   agent_token: { type: string, description: Only when created or rotated. Store it; it is not shown again. }
//   agent_download_url: { type: string, description: Download URL for the edge agent binary. }
//   agent_install_url: { type: string, description: Installer script URL to install the edge agent as a systemd service. }
//   agent_server_url: { type: string, description: WebSocket URL the edge agent connects to. }
//   frontend_url: { type: string, description: Base URL where the frontend/gateway is reached. }

type siteDTO struct {
	ID               string    `json:"id"`
	Name             string    `json:"name"`
	Kind             string    `json:"kind"`
	Description      string    `json:"description"`
	ConnectionCount  *int64    `json:"connection_count,omitempty"`
	AgentsOnline     *int      `json:"agents_online,omitempty"`
	CreatedAt        time.Time `json:"created_at"`
	// Only in the responses that create or rotate it.
	AgentToken       string    `json:"agent_token,omitempty"`
	AgentDownloadURL string    `json:"agent_download_url,omitempty"`
	AgentInstallURL  string    `json:"agent_install_url,omitempty"`
	AgentServerURL   string    `json:"agent_server_url,omitempty"`
	FrontendURL      string    `json:"frontend_url,omitempty"`
}

// openapi:schema Secret
// type: object
// description: Credential metadata. The value is write-only and never returned.
// required: [id, name, kind, username, created_at, updated_at]
// properties:
//   id: { type: string, format: uuid }
//   name: { type: string }
//   kind: { type: string, enum: [password, private_key] }
//   username: { type: string }
//   connection_count: { type: integer, description: Only in list responses. }
//   created_at: { type: string, format: date-time }
//   updated_at: { type: string, format: date-time }

type secretDTO struct {
	ID              string    `json:"id"`
	Name            string    `json:"name"`
	Kind            string    `json:"kind"`
	Username        string    `json:"username"`
	ConnectionCount *int64    `json:"connection_count,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

func toSecret(s db.ConfigSecret) secretDTO {
	return secretDTO{ID: s.ID, Name: s.Name, Kind: s.Kind, Username: s.Username, CreatedAt: s.CreatedAt.UTC(), UpdatedAt: s.UpdatedAt.UTC()}
}

// openapi:schema Connection
// type: object
// required: [id, name, protocol, host, port, folder_id, site_id, environment, description, tags, backend, credential_mode, secret_id, params, record, record_input, host_key, host_key_pending, created_at, updated_at]
// properties:
//   id: { type: string, format: uuid }
//   name: { type: string }
//   protocol: { type: string, enum: [ssh, rdp, vnc] }
//   host: { type: string }
//   port: { type: integer }
//   folder_id: { type: [string, 'null'], format: uuid }
//   site_id: { type: [string, 'null'], format: uuid }
//   environment: { type: string }
//   description: { type: string }
//   tags: { type: array, items: { type: string } }
//   backend: { type: string, enum: [paltad, guacd] }
//   credential_mode: { type: string, enum: [vault, prompt] }
//   secret_id: { type: [string, 'null'], format: uuid }
//   params: { type: object }
//   record: { type: boolean }
//   record_input: { type: boolean }
//   host_key: { type: [string, 'null'], description: Pinned SHA256 fingerprint. }
//   host_key_pending: { type: [string, 'null'], description: 'Key the server presented with none pinned, waiting for an admin to approve it (PUT /connections/{id}/host-key).' }
//   created_at: { type: string, format: date-time }
//   updated_at: { type: string, format: date-time }

type connectionDTO struct {
	ID             string          `json:"id"`
	Name           string          `json:"name"`
	Protocol       string          `json:"protocol"`
	Host           string          `json:"host"`
	Port           int64           `json:"port"`
	FolderID       *string         `json:"folder_id"`
	SiteID         *string         `json:"site_id"`
	Environment    string          `json:"environment"`
	Description    string          `json:"description"`
	Tags           []string        `json:"tags"`
	Backend        string          `json:"backend"`
	CredentialMode string          `json:"credential_mode"`
	SecretID       *string         `json:"secret_id"`
	Params         json.RawMessage `json:"params"`
	Record         bool            `json:"record"`
	RecordInput    bool            `json:"record_input"`
	HostKey        *string         `json:"host_key"`
	HostKeyPending *string         `json:"host_key_pending"`
	CreatedAt      time.Time       `json:"created_at"`
	UpdatedAt      time.Time       `json:"updated_at"`
}

func toConnection(c db.ConfigConnection, tags []string) connectionDTO {
	if tags == nil {
		tags = []string{}
	}
	return connectionDTO{c.ID, c.Name, c.Protocol, c.Host, c.Port, strPtr(c.FolderID), strPtr(c.SiteID),
		c.Environment, c.Description, tags, c.Backend, c.CredentialMode, strPtr(c.SecretID),
		json.RawMessage(c.Params), c.Record, c.RecordInput, strPtr(c.HostKey), strPtr(c.HostKeyPending), c.CreatedAt.UTC(), c.UpdatedAt.UTC()}
}

// openapi:schema Policy
// type: object
// required: [id, subject_type, subject_id, object_type, object_ref, can_connect, can_view_recordings, can_upload, can_download, expires_at, description, created_by, created_at]
// properties:
//   id: { type: string, format: uuid }
//   subject_type: { type: string, enum: [user, group] }
//   subject_id: { type: string, format: uuid }
//   object_type: { type: string, enum: [connection, folder, tag] }
//   object_ref: { type: string }
//   can_connect: { type: boolean }
//   can_view_recordings: { type: boolean }
//   can_upload: { type: boolean }
//   can_download: { type: boolean }
//   starts_at: { type: [string, 'null'], format: date-time }
//   expires_at: { type: [string, 'null'], format: date-time }
//   description: { type: string }
//   created_by: { type: [string, 'null'], format: uuid }
//   created_at: { type: string, format: date-time }

type policyDTO struct {
	ID                string     `json:"id"`
	SubjectType       string     `json:"subject_type"`
	SubjectID         string     `json:"subject_id"`
	ObjectType        string     `json:"object_type"`
	ObjectRef         string     `json:"object_ref"`
	CanConnect        bool       `json:"can_connect"`
	CanViewRecordings bool       `json:"can_view_recordings"`
	CanUpload         bool       `json:"can_upload"`
	CanDownload       bool       `json:"can_download"`
	StartsAt          *time.Time `json:"starts_at"`
	ExpiresAt         *time.Time `json:"expires_at"`
	Description       string     `json:"description"`
	CreatedBy         *string    `json:"created_by"`
	CreatedAt         time.Time  `json:"created_at"`
}

func toPolicy(p db.ConfigPolicy) policyDTO {
	return policyDTO{p.ID, p.SubjectType, p.SubjectID, p.ObjectType, p.ObjectRef, p.CanConnect, p.CanViewRecordings,
		p.CanUpload, p.CanDownload, timePtr(p.StartsAt), timePtr(p.ExpiresAt), p.Description, strPtr(p.CreatedBy), p.CreatedAt.UTC()}
}

// openapi:schema AuditEvent
// type: object
// required: [id, ts, actor_id, actor_name, actor_ip, action, object_type, object_id, details, hash]
// properties:
//   id: { type: integer }
//   ts: { type: string, format: date-time }
//   actor_id: { type: [string, 'null'], format: uuid }
//   actor_name: { type: string }
//   actor_ip: { type: string }
//   action: { type: string, examples: [auth.login, connection.update, session.start] }
//   object_type: { type: string }
//   object_id: { type: string }
//   details: { type: object }
//   hash: { type: string, description: 'sha256(prev_hash || event); see GET /audit/verify.' }

type auditEventDTO struct {
	ID         int64           `json:"id"`
	TS         time.Time       `json:"ts"`
	ActorID    *string         `json:"actor_id"`
	ActorName  string          `json:"actor_name"`
	ActorIP    string          `json:"actor_ip"`
	Action     string          `json:"action"`
	ObjectType string          `json:"object_type"`
	ObjectID   string          `json:"object_id"`
	Details    json.RawMessage `json:"details"`
	Hash       string          `json:"hash"`
}

func toAuditEvent(e db.AuditEvent) auditEventDTO {
	return auditEventDTO{e.ID, e.Ts.UTC(), strPtr(e.ActorID), e.ActorName, e.ActorIP, e.Action, e.ObjectType,
		e.ObjectID, json.RawMessage(e.Details), e.Hash}
}

// openapi:schema Session
// type: object
// required: [id, user_id, username, connection_id, connection, site, client_ip, reason, has_recording, started_at, ended_at, end_reason]
// properties:
//   id: { type: string }
//   user_id: { type: [string, 'null'], format: uuid }
//   username: { type: string }
//   connection_id: { type: string, format: uuid }
//   connection: { type: object, description: The connection as it was when the session started. }
//   site: { type: string }
//   client_ip: { type: string }
//   reason: { type: string }
//   has_recording: { type: boolean, description: A recording exists and has not been deleted. }
//   recording_purged_at: { type: [string, 'null'], format: date-time, description: When the retention policy deleted the recording. }
//   recording_expires_at: { type: [string, 'null'], format: date-time, description: 'When the retention policy will delete it (null = kept forever, or still recording).' }
//   recording_bytes: { type: integer, description: 'Size on disk, compressed. Only in GET /audit/sessions/{id}.' }
//   started_at: { type: string, format: date-time }
//   ended_at: { type: [string, 'null'], format: date-time }
//   end_reason: { type: [string, 'null'] }

type sessionDTO struct {
	ID           string          `json:"id"`
	UserID       *string         `json:"user_id"`
	Username     string          `json:"username"`
	ConnectionID string          `json:"connection_id"`
	Connection   json.RawMessage `json:"connection"`
	Site         string          `json:"site"`
	ClientIP     string          `json:"client_ip"`
	Reason       string          `json:"reason"`
	HasRecording bool            `json:"has_recording"`
	PurgedAt     *time.Time      `json:"recording_purged_at"`
	ExpiresAt    *time.Time      `json:"recording_expires_at"`
	Bytes        *int64          `json:"recording_bytes,omitempty"`
	StartedAt    time.Time       `json:"started_at"`
	EndedAt      *time.Time      `json:"ended_at"`
	EndReason    *string         `json:"end_reason"`
}

// toSession builds the DTO. purged is when the recording was deleted (zero
// if not); retentionDays the current policy, to compute the expiry.
func toSession(s db.AuditSession, purged time.Time, retentionDays int) sessionDTO {
	d := sessionDTO{ID: s.ID, UserID: strPtr(s.UserID), Username: s.Username, ConnectionID: s.ConnectionID,
		Connection: json.RawMessage(s.ConnectionSnapshot), Site: s.Site, ClientIP: s.ClientIP, Reason: s.Reason,
		HasRecording: s.Recording.Valid && purged.IsZero(), StartedAt: s.StartedAt.UTC(), EndedAt: timePtr(s.EndedAt), EndReason: strPtr(s.EndReason)}
	if !purged.IsZero() {
		t := purged.UTC()
		d.PurgedAt = &t
	} else if d.HasRecording && retentionDays > 0 && s.EndedAt.Valid {
		t := s.EndedAt.Time.UTC().Add(time.Duration(retentionDays) * 24 * time.Hour)
		d.ExpiresAt = &t
	}
	return d
}

// ---- validation ----

var (
	reUsername = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	reTag      = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,31}$`)
	roles      = map[string]bool{"superadmin": true, "admin": true, "auditor": true, "user": true}
	protocols  = map[string]int64{"ssh": 22, "rdp": 3389, "vnc": 5900}
)

func validName(field, v string) error {
	v = strings.TrimSpace(v)
	if v == "" || len(v) > 128 {
		return badRequest("%s must be 1-128 characters", field)
	}
	return nil
}

func validTags(tags []string) ([]string, error) {
	seen := map[string]bool{}
	out := []string{}
	for _, t := range tags {
		t = strings.ToLower(strings.TrimSpace(t))
		if !reTag.MatchString(t) {
			return nil, badRequest("invalid tag %q (lowercase letters, digits, . _ -; max 32)", t)
		}
		if !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	return out, nil
}

// openapi:schema SessionShare
// type: object
// required: [share_token, session_id, connection_id]
// properties:
//   share_token: { type: string }
//   session_id: { type: string }
//   connection_id: { type: string }

type sessionShareDTO struct {
	ShareToken   string `json:"share_token"`
	SessionID    string `json:"session_id"`
	ConnectionID string `json:"connection_id"`
}

// openapi:schema SessionInfo
// type: object
// required: [session_id, connection_id, connection_name, protocol, owner_username, active]
// properties:
//   session_id: { type: string }
//   connection_id: { type: string }
//   connection_name: { type: string }
//   protocol: { type: string }
//   owner_username: { type: string }
//   active: { type: boolean }

type sessionInfoDTO struct {
	SessionID      string `json:"session_id"`
	ConnectionID   string `json:"connection_id"`
	ConnectionName string `json:"connection_name"`
	Protocol       string `json:"protocol"`
	OwnerUsername  string `json:"owner_username"`
	Active         bool   `json:"active"`
}

// openapi:schema AccessRequestConnectionTarget
// type: object
// required: [id, name, protocol, environment, folder_id, tags]
// properties:
//   id: { type: string, format: uuid }
//   name: { type: string }
//   protocol: { type: string }
//   environment: { type: string }
//   folder_id: { type: [string, 'null'], format: uuid }
//   tags: { type: array, items: { type: string } }

type accessRequestConnectionTarget struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Protocol    string   `json:"protocol"`
	Environment string   `json:"environment"`
	FolderID    *string  `json:"folder_id"`
	Tags        []string `json:"tags"`
}

// openapi:schema AccessRequestFolderTarget
// type: object
// required: [id, parent_id, name]
// properties:
//   id: { type: string, format: uuid }
//   parent_id: { type: [string, 'null'], format: uuid }
//   name: { type: string }

type accessRequestFolderTarget struct {
	ID       string  `json:"id"`
	ParentID *string `json:"parent_id"`
	Name     string  `json:"name"`
}

// openapi:schema AccessRequestTargets
// type: object
// required: [connections, folders, tags]
// properties:
//   connections: { type: array, items: { $ref: '#/components/schemas/AccessRequestConnectionTarget' } }
//   folders: { type: array, items: { $ref: '#/components/schemas/AccessRequestFolderTarget' } }
//   tags: { type: array, items: { type: string } }

type accessRequestTargetsDTO struct {
	Connections []accessRequestConnectionTarget `json:"connections"`
	Folders     []accessRequestFolderTarget     `json:"folders"`
	Tags        []string                        `json:"tags"`
}

// openapi:schema AccessRequest
// type: object
// required: [id, user_id, user_username, user_display_name, object_type, object_ref, object_name, ticket, can_connect, can_view_recordings, can_upload, can_download, reason, starts_at, ends_at, status, reviewed_by, reviewer_username, reviewed_at, review_comment, created_policy_id, created_at]
// properties:
//   id: { type: string, format: uuid }
//   user_id: { type: string, format: uuid }
//   user_username: { type: string }
//   user_display_name: { type: string }
//   object_type: { type: string, enum: [connection, folder, tag] }
//   object_ref: { type: string }
//   object_name: { type: string }
//   ticket: { type: string, description: 'Optional reference to a ticket or issue ID.' }
//   can_connect: { type: boolean }
//   can_view_recordings: { type: boolean }
//   can_upload: { type: boolean }
//   can_download: { type: boolean }
//   reason: { type: string }
//   starts_at: { type: string, format: date-time }
//   ends_at: { type: string, format: date-time }
//   status: { type: string, enum: [pending, approved, rejected, canceled] }
//   reviewed_by: { type: [string, 'null'], format: uuid }
//   reviewer_username: { type: [string, 'null'] }
//   reviewed_at: { type: [string, 'null'], format: date-time }
//   review_comment: { type: string }
//   created_policy_id: { type: [string, 'null'], format: uuid }
//   created_at: { type: string, format: date-time }

type accessRequestDTO struct {
	ID                string     `json:"id"`
	UserID            string     `json:"user_id"`
	UserUsername      string     `json:"user_username"`
	UserDisplayName   string     `json:"user_display_name"`
	ObjectType        string     `json:"object_type"`
	ObjectRef         string     `json:"object_ref"`
	ObjectName        string     `json:"object_name"`
	Ticket            string     `json:"ticket"`
	CanConnect        bool       `json:"can_connect"`
	CanViewRecordings bool       `json:"can_view_recordings"`
	CanUpload         bool       `json:"can_upload"`
	CanDownload       bool       `json:"can_download"`
	Reason            string     `json:"reason"`
	StartsAt          time.Time  `json:"starts_at"`
	EndsAt            time.Time  `json:"ends_at"`
	Status            string     `json:"status"`
	ReviewedBy        *string    `json:"reviewed_by"`
	ReviewerUsername  *string    `json:"reviewer_username"`
	ReviewedAt        *time.Time `json:"reviewed_at"`
	ReviewComment     string     `json:"review_comment"`
	CreatedPolicyID   *string    `json:"created_policy_id"`
	CreatedAt         time.Time  `json:"created_at"`
}
