// Package objstore reads session recordings that duckjumpd moved to an
// S3-compatible bucket (see duckjumpd/crates/duckjumpd/src/s3.rs).
package objstore

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// Config is the same DUCKJUMP_S3_* settings duckjumpd uses.
type Config struct {
	Endpoint  string // http(s)://host[:port]
	Bucket    string
	Region    string
	Prefix    string
	AccessKey string
	SecretKey string
	PathStyle bool
}

type S3 struct {
	c      *minio.Client
	bucket string
	prefix string
}

// Extensions of finished recordings, as duckjumpd names them.
var finished = []string{".cast.gz", ".gfx.gz"}

func New(cfg Config) (*S3, error) {
	u, err := url.Parse(cfg.Endpoint)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("S3 endpoint %q must be an http(s) URL", cfg.Endpoint)
	}
	if cfg.Bucket == "" || cfg.AccessKey == "" || cfg.SecretKey == "" {
		return nil, errors.New("S3 needs a bucket, an access key and a secret key")
	}
	lookup := minio.BucketLookupDNS
	if cfg.PathStyle {
		lookup = minio.BucketLookupPath
	}
	region := cfg.Region
	if region == "" {
		region = "us-east-1"
	}
	c, err := minio.New(u.Host, &minio.Options{Creds: credentials.NewStaticV4(cfg.AccessKey, cfg.SecretKey, ""),
		Secure: u.Scheme == "https", Region: region, BucketLookup: lookup})
	if err != nil {
		return nil, err
	}
	return &S3{c: c, bucket: cfg.Bucket, prefix: cfg.Prefix}, nil
}

// Check verifies the bucket is reachable with these credentials.
func (s *S3) Check(ctx context.Context) error {
	ok, err := s.c.BucketExists(ctx, s.bucket)
	if err != nil {
		return fmt.Errorf("S3 bucket %s: %w", s.bucket, err)
	}
	if !ok {
		return fmt.Errorf("S3 bucket %s does not exist", s.bucket)
	}
	return nil
}

// Object is a finished recording in the bucket.
type Object struct {
	Key  string
	Size int64
	Gfx  bool // graphical (.gfx.gz) rather than terminal (.cast.gz)
}

func notFound(err error) bool {
	return minio.ToErrorResponse(err).Code == "NoSuchKey"
}

// Stat finds the recording named name (without extension).
func (s *S3) Stat(ctx context.Context, name string) (Object, error) {
	for _, ext := range finished {
		key := s.prefix + name + ext
		info, err := s.c.StatObject(ctx, s.bucket, key, minio.StatObjectOptions{})
		if err == nil {
			return Object{Key: key, Size: info.Size, Gfx: ext == ".gfx.gz"}, nil
		}
		if !notFound(err) {
			return Object{}, err
		}
	}
	return Object{}, ErrNotFound
}

var ErrNotFound = errors.New("recording not in the bucket")

// Open streams an object (gzip-compressed).
func (s *S3) Open(ctx context.Context, key string) (io.ReadCloser, error) {
	return s.c.GetObject(ctx, s.bucket, key, minio.GetObjectOptions{})
}

// Delete removes a recording; it returns the bytes freed (0: not there).
func (s *S3) Delete(ctx context.Context, name string) (int64, error) {
	o, err := s.Stat(ctx, name)
	if errors.Is(err, ErrNotFound) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	if err := s.c.RemoveObject(ctx, s.bucket, o.Key, minio.RemoveObjectOptions{}); err != nil {
		return 0, err
	}
	return o.Size, nil
}

// Sizes lists every finished recording: name -> size.
func (s *S3) Sizes(ctx context.Context) (map[string]int64, error) {
	out := map[string]int64{}
	for o := range s.c.ListObjects(ctx, s.bucket, minio.ListObjectsOptions{Prefix: s.prefix, Recursive: true}) {
		if o.Err != nil {
			return nil, o.Err
		}
		name := strings.TrimPrefix(o.Key, s.prefix)
		for _, ext := range finished {
			if strings.HasSuffix(name, ext) && !strings.Contains(name, "/") {
				out[strings.TrimSuffix(name, ext)] = o.Size
			}
		}
	}
	return out, nil
}

// Put stores a finished recording (duckjumpd does this in production; tests
// and tools use it).
func (s *S3) Put(ctx context.Context, fileName string, body io.Reader, size int64) error {
	_, err := s.c.PutObject(ctx, s.bucket, s.prefix+fileName, body, size, minio.PutObjectOptions{})
	return err
}

// FromEnv reads DUCKJUMP_S3_* (the variables duckjumpd reads too); nil when
// DUCKJUMP_S3_ENDPOINT is unset. secret is the secret key, looked up by the
// caller (environment, file or systemd credential).
func FromEnv(getenv func(string) string, secret string) (*S3, error) {
	if getenv("DUCKJUMP_S3_ENDPOINT") == "" {
		return nil, nil
	}
	prefix := getenv("DUCKJUMP_S3_PREFIX")
	if prefix == "" {
		prefix = "recordings/"
	}
	ps := strings.ToLower(getenv("DUCKJUMP_S3_PATH_STYLE"))
	return New(Config{Endpoint: getenv("DUCKJUMP_S3_ENDPOINT"), Bucket: getenv("DUCKJUMP_S3_BUCKET"), Region: getenv("DUCKJUMP_S3_REGION"),
		Prefix: prefix, AccessKey: getenv("DUCKJUMP_S3_ACCESS_KEY"), SecretKey: secret, PathStyle: ps == "1" || ps == "true" || ps == "yes"})
}

// WithPrefix is the same bucket under another key prefix (e.g. "files/").
func (s *S3) WithPrefix(prefix string) *S3 {
	c := *s
	c.prefix = prefix
	return &c
}

// Key is the full object key of a name under this prefix.
func (s *S3) Key(name string) string { return s.prefix + name }

// RemoveKey deletes one object by its full key.
func (s *S3) RemoveKey(ctx context.Context, key string) error {
	return s.c.RemoveObject(ctx, s.bucket, key, minio.RemoveObjectOptions{})
}
