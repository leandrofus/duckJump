package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/leandrofus/duckjump/gateway/internal/objstore"
	"github.com/leandrofus/duckjump/gateway/internal/store"
	"github.com/leandrofus/duckjump/gateway/internal/store/db"
)

const RetentionKey = "recordings.retention_days"

var (
	ErrRetentionDaysInvalid    = errors.New("retention_days must be 0-3650")
	ErrRecordingsNotConfigured = errors.New("the gateway runs without -recordings, so it cannot delete recording files")
)

type RecordingObjectStore interface {
	Stat(ctx context.Context, name string) (objstore.Object, error)
	Open(ctx context.Context, key string) (io.ReadCloser, error)
	Delete(ctx context.Context, name string) (int64, error)
	Sizes(ctx context.Context) (map[string]int64, error)
}

type RecordingUsage struct {
	Recordings      int
	Bytes           int64
	Purgeable       int
	PurgeableBytes  int64
	OldestStartedAt *time.Time
}

type RecordingService struct {
	store         *store.Store
	recordingsDir string
	objects       RecordingObjectStore
	dirFn         func() string
	objectsFn     func() RecordingObjectStore
}

func NewRecordingService(st *store.Store, recordingsDir string, objects RecordingObjectStore) *RecordingService {
	return &RecordingService{
		store:         st,
		recordingsDir: recordingsDir,
		objects:       objects,
	}
}

func NewRecordingServiceWithFuncs(st *store.Store, dirFn func() string, objectsFn func() RecordingObjectStore) *RecordingService {
	return &RecordingService{
		store:     st,
		dirFn:     dirFn,
		objectsFn: objectsFn,
	}
}

func (s *RecordingService) dir() string {
	if s.dirFn != nil {
		return s.dirFn()
	}
	return s.recordingsDir
}

func (s *RecordingService) objStore() RecordingObjectStore {
	var o RecordingObjectStore
	if s.objectsFn != nil {
		o = s.objectsFn()
	} else {
		o = s.objects
	}
	if o == nil {
		return nil
	}
	v := reflect.ValueOf(o)
	if v.Kind() == reflect.Ptr && v.IsNil() {
		return nil
	}
	return o
}

func (s *RecordingService) Configured() bool {
	return s.dir() != "" || s.objStore() != nil
}

func (s *RecordingService) RetentionDays(ctx context.Context) (int, error) {
	v, err := s.store.Q.GetSetting(ctx, RetentionKey)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("setting %s: %w", RetentionKey, err)
	}
	return n, nil
}

func (s *RecordingService) retentionCutoff(days int) time.Time {
	return store.Now().Add(-time.Duration(days) * 24 * time.Hour)
}

func (s *RecordingService) RecordingFile(name string) (path string, gz bool, size int64, err error) {
	dir := s.dir()
	if dir == "" {
		return "", false, 0, os.ErrNotExist
	}
	base := filepath.Join(dir, filepath.Base(name))
	for _, ext := range []string{".cast.gz", ".gfx.gz", ".cast", ".gfx"} {
		if fi, err := os.Stat(base + ext); err == nil {
			return base + ext, strings.HasSuffix(ext, ".gz"), fi.Size(), nil
		}
	}
	return "", false, 0, os.ErrNotExist
}

func (s *RecordingService) RecordingSize(ctx context.Context, name string) (int64, error) {
	if _, _, size, err := s.RecordingFile(name); err == nil {
		return size, nil
	}
	objs := s.objStore()
	if objs == nil {
		return 0, os.ErrNotExist
	}
	o, err := objs.Stat(ctx, filepath.Base(name))
	return o.Size, err
}

func (s *RecordingService) Usage(ctx context.Context, days int) (RecordingUsage, error) {
	var u RecordingUsage
	rows, err := s.store.Q.LiveRecordings(ctx)
	if err != nil {
		return u, err
	}
	cutoff := s.retentionCutoff(days)
	var inBucket map[string]int64
	objs := s.objStore()
	if objs != nil {
		if inBucket, err = objs.Sizes(ctx); err != nil {
			return u, err
		}
	}
	for _, r := range rows {
		_, _, size, err := s.RecordingFile(r.Recording.String)
		if err != nil {
			var ok bool
			if size, ok = inBucket[filepath.Base(r.Recording.String)]; !ok {
				continue // neither on disk nor in the bucket
			}
		}
		u.Recordings++
		u.Bytes += size
		if u.OldestStartedAt == nil {
			t := r.StartedAt.UTC()
			u.OldestStartedAt = &t
		}
		if days > 0 && r.EndedAt.Valid && r.EndedAt.Time.Before(cutoff) {
			u.Purgeable++
			u.PurgeableBytes += size
		}
	}
	return u, nil
}

func (s *RecordingService) SetRetention(ctx context.Context, actor store.Actor, userID string, days int) (prevDays int, purgedCount int, purgedBytes int64, err error) {
	if days < 0 || days > 3650 {
		return 0, 0, 0, ErrRetentionDaysInvalid
	}
	if days > 0 && !s.Configured() {
		return 0, 0, 0, ErrRecordingsNotConfigured
	}
	prev, err := s.RetentionDays(ctx)
	if err != nil {
		return 0, 0, 0, err
	}
	val, _ := json.Marshal(days)
	err = s.store.Tx(ctx, func(q *db.Queries) error {
		if err := q.SetSetting(ctx, db.SetSettingParams{
			Key:       RetentionKey,
			Value:     string(val),
			Now:       store.Now(),
			UpdatedBy: store.NullString(userID),
		}); err != nil {
			return err
		}
		return store.Audit(ctx, q, store.Event{
			Actor:      actor,
			Action:     "settings.update",
			ObjectType: "setting",
			ObjectID:   RetentionKey,
			Details:    map[string]any{"from": prev, "to": days},
		})
	})
	if err != nil {
		return 0, 0, 0, err
	}
	n, b, err := s.PurgeRecordings(ctx, actor)
	if err != nil {
		return prev, 0, 0, err
	}
	return prev, n, b, nil
}

func (s *RecordingService) PurgeRecordings(ctx context.Context, actor store.Actor) (int, int64, error) {
	days, err := s.RetentionDays(ctx)
	if err != nil || days == 0 {
		return 0, 0, err
	}
	if !s.Configured() {
		return 0, 0, errors.New("retention is set but the gateway has no -recordings directory or S3 bucket")
	}
	cutoff := s.retentionCutoff(days)
	reason := fmt.Sprintf("retention policy: %d days", days)
	var n int
	var total int64
	objs := s.objStore()
	dir := s.dir()
	for {
		batch, err := s.store.Q.RecordingsEndedBefore(ctx, db.RecordingsEndedBeforeParams{Cutoff: store.TS(cutoff), Lim: 200})
		if err != nil {
			return n, total, err
		}
		if len(batch) == 0 {
			return n, total, nil
		}
		for _, r := range batch {
			var size int64
			if objs != nil {
				freed, err := objs.Delete(ctx, filepath.Base(r.Recording.String))
				if err != nil {
					return n, total, fmt.Errorf("deleting %s from the bucket: %w", r.Recording.String, err)
				}
				size += freed
			}
			base := filepath.Join(dir, filepath.Base(r.Recording.String))
			for _, f := range []string{base + ".cast.gz", base + ".cast", base + ".gfx.gz", base + ".gfx"} {
				if dir == "" {
					break
				}
				fi, err := os.Stat(f)
				if err != nil {
					continue
				}
				if err := os.Remove(f); err != nil {
					return n, total, fmt.Errorf("deleting %s: %w", f, err)
				}
				size += fi.Size()
			}
			err := s.store.Tx(ctx, func(q *db.Queries) error {
				if err := q.InsertRecordingPurge(ctx, db.InsertRecordingPurgeParams{
					SessionID: r.ID,
					Reason:    reason,
					Bytes:     size,
					Now:       store.Now(),
				}); err != nil {
					return err
				}
				return store.Audit(ctx, q, store.Event{
					Actor:      actor,
					Action:     "recording.purged",
					ObjectType: "session",
					ObjectID:   r.ID,
					Details:    map[string]any{"bytes": size, "retention_days": days},
				})
			})
			if err != nil {
				return n, total, err
			}
			n++
			total += size
		}
	}
}

func (s *RecordingService) LiveRecordings(ctx context.Context) ([]db.LiveRecordingsRow, error) {
	return s.store.Q.LiveRecordings(ctx)
}
