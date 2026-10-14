package server

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/mojatter/s2"
)

// splitBucketList parses a comma-separated bucket list (used by both the
// S2_SERVER_BUCKETS env var and the -buckets flag). Whitespace around each
// entry is trimmed; empty entries are dropped so "a,,b" becomes ["a","b"]
// and the zero-value "" becomes a nil slice rather than [""].
func splitBucketList(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := parts[:0]
	for _, p := range parts {
		if trimmed := strings.TrimSpace(p); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

const (
	EnvS2ServerConfig          = "S2_SERVER_CONFIG"
	EnvS2ServerListen          = "S2_SERVER_LISTEN"
	EnvS2ServerConsoleListen   = "S2_SERVER_CONSOLE_LISTEN"
	EnvS2ServerHealthPath      = "S2_SERVER_HEALTH_PATH"
	EnvS2ServerType            = "S2_SERVER_TYPE"
	EnvS2ServerRoot            = "S2_SERVER_ROOT"
	EnvS2ServerMaxUploadSize   = "S2_SERVER_MAX_UPLOAD_SIZE"
	EnvS2ServerMaxPreviewSize  = "S2_SERVER_MAX_PREVIEW_SIZE"
	EnvS2ServerMultipartMaxAge = "S2_SERVER_MULTIPART_MAX_AGE"
	EnvS2ServerUser            = "S2_SERVER_USER"
	EnvS2ServerPassword        = "S2_SERVER_PASSWORD" // #nosec G101 -- env var name, not a credential
	EnvS2ServerBuckets         = "S2_SERVER_BUCKETS"
	EnvS2ServerS3Domain        = "S2_SERVER_S3_DOMAIN"
)

// Config is a configuration for the server.
type Config struct {
	s2.Config
	// Listen is the address the S3-compatible API listens on.
	Listen string `json:"listen"`
	// ConsoleListen is the address the Web Console listens on. The
	// console runs on a dedicated listener so the S3 API can own the
	// root path without any prefix. Set to an empty string to disable
	// the console entirely.
	ConsoleListen string `json:"console_listen"`
	// HealthPath is the path the health check endpoint is mounted at on
	// the S3 listener. Its first path segment is reserved and cannot be
	// used as a bucket name (Buckets.Create returns ErrReservedBucketName
	// for that name). The default "/healthz" reserves the bucket name
	// must start with "/" and have at least one segment after it. Set to an
	// empty string to disable the health endpoint entirely.
	HealthPath string `json:"health_path"`
	// S3Domain optionally enables virtual-host-style bucket addressing on
	// the S3 listener: a request to "<bucket>.<S3Domain>:<port>/<key>" is
	// routed with the Host-derived bucket and the wire path as the key, for
	// every bucket, object, copy and multipart operation. The bare domain's
	// root keeps serving ListBuckets and the health endpoint. The value is
	// normalized to a lowercased DNS name (scheme, port, path and a single
	// FQDN trailing dot are stripped). Empty (the default) disables the
	// feature entirely and all requests keep path-style behaviour; Hosts
	// that target the domain with a trailing dot or an illegal bucket label
	// are rejected with 400 instead of being reinterpreted as path-style.
	S3Domain string `json:"s3_domain"`
	// MaxUploadSize is the maximum upload size in bytes. When 0, a backend-specific
	// default is used (see EffectiveMaxUploadSize): 5 GiB for osfs/s3, 16 MiB for
	// memfs. The conservative memfs default protects the host from accidental
	// OOM when a large upload targets the in-memory backend; set an explicit
	// value here to override.
	MaxUploadSize int64 `json:"max_upload_size"`
	// MaxPreviewSize is the maximum file size for text preview in bytes (0 = default 10MB).
	MaxPreviewSize int64 `json:"max_preview_size"`
	// MultipartMaxAge is the upload lifetime in seconds (0 = default, negative = forever).
	MultipartMaxAge int64 `json:"multipart_max_age"`
	// User is the username for authentication (Basic Auth for Web Console, Access Key ID for S3 API).
	// When empty, authentication is disabled.
	User string `json:"user"`
	// Password is the password for authentication (Basic Auth password for Web Console, Secret Access Key for S3 API).
	Password string `json:"password"`
	// Users is a list of additional principals for multi-user auth. SigV4
	// and BasicAuth check these in addition to the legacy single User/
	// Password pair above; each entry's Policy (if set) governs what that
	// principal may do. Config-file only -- there is no environment
	// variable equivalent.
	//
	// An entry whose AccessKeyID is AnonymousAccessKeyID ("*") is the
	// anonymous principal: SigV4 falls back to it for S3 API requests that
	// carry no Authorization header and no presigned-URL query parameters,
	// instead of rejecting them outright. BasicAuth (the Web Console) never
	// consults it -- anonymous browsing of the bucket sidebar is out of
	// scope. See Config.Validate and anonymousAllowedActions for the
	// constraints placed on this entry.
	Users []User `json:"users,omitempty"`
	// Buckets is a list of bucket names to create on startup if they don't already exist.
	Buckets []string `json:"buckets"`
}

const (
	DefaultMaxUploadSize      = 5 << 30  // 5 GiB — default for osfs/s3 backends.
	DefaultMemfsMaxUploadSize = 16 << 20 // 16 MiB — conservative default for the in-memory backend.
	DefaultMaxPreviewSize     = 10 << 20 // 10 MiB
)

// DefaultMultipartMaxAge is the upload lifetime when MultipartMaxAge is 0.
const DefaultMultipartMaxAge = 24 * time.Hour

// DefaultRoot is the default storage root path used by DefaultConfig when
// the user does not supply one via -root, -f, or S2_SERVER_ROOT.
//
// It is intentionally a var (not a const) so that binaries can be built with
// a different default via linker flags, matching the same idiom used for
// version injection:
//
//	cd cmd/s2-server && go build -ldflags "-X github.com/mojatter/s2/server.DefaultRoot=/var/lib/s2" .
//
// This lets the stock "go install" binary default to a relative "data"
// directory (so a new user can run s2-server in any directory and
// immediately see where data lands) while the Docker image is built with
// /var/lib/s2 baked in.
var DefaultRoot = "data"

// EffectiveMaxUploadSize returns the upload size limit to enforce for this
// configuration. When MaxUploadSize is explicitly set (> 0) it is returned
// as-is; otherwise a backend-specific default is chosen so that switching
// Type to memfs does not silently inherit the 5 GiB default.
func (cfg *Config) EffectiveMaxUploadSize() int64 {
	if cfg.MaxUploadSize > 0 {
		return cfg.MaxUploadSize
	}
	if cfg.Type == s2.TypeMemFS {
		return DefaultMemfsMaxUploadSize
	}
	return DefaultMaxUploadSize
}

// EffectiveMultipartMaxAge returns the upload lifetime, or 0 when uploads never expire.
func (cfg *Config) EffectiveMultipartMaxAge() time.Duration {
	if cfg.MultipartMaxAge > 0 {
		return time.Duration(cfg.MultipartMaxAge) * time.Second
	}
	if cfg.MultipartMaxAge < 0 {
		return 0
	}
	return DefaultMultipartMaxAge
}

// Validate checks the configuration for obvious mistakes that would
// otherwise surface as confusing runtime errors. It is called by
// NewServer; callers that build a Config by hand can invoke it
// themselves before passing it in.
func (cfg *Config) Validate() error {
	if cfg.HealthPath != "" {
		if !strings.HasPrefix(cfg.HealthPath, "/") {
			return fmt.Errorf("server: HealthPath %q must start with %q", cfg.HealthPath, "/")
		}
		if cfg.HealthPath == "/" {
			return fmt.Errorf("server: HealthPath %q must have at least one path segment", cfg.HealthPath)
		}
	}

	if cfg.S3Domain != "" {
		d, err := normalizeS3Domain(cfg.S3Domain)
		if err != nil {
			return fmt.Errorf("server: S3Domain: %w", err)
		}
		cfg.S3Domain = d
	}

	if cfg.User == AnonymousAccessKeyID {
		return fmt.Errorf("server: User must not be %q; the anonymous principal is only configurable via a Users entry, which enforces the read-only action restriction", AnonymousAccessKeyID)
	}

	seen := make(map[string]bool, len(cfg.Users)+1)
	if cfg.User != "" {
		seen[cfg.User] = true
	}
	for i, u := range cfg.Users {
		if u.AccessKeyID == "" {
			return fmt.Errorf("server: users[%d]: access_key_id must not be empty", i)
		}
		isAnonymous := u.AccessKeyID == AnonymousAccessKeyID
		if isAnonymous {
			if u.SecretAccessKey != "" {
				return fmt.Errorf("server: users[%d] (%s): secret_access_key must be empty for the anonymous principal", i, u.AccessKeyID)
			}
			if u.Policy == nil {
				return fmt.Errorf("server: users[%d] (%s): policy is required for the anonymous principal", i, u.AccessKeyID)
			}
		} else if u.SecretAccessKey == "" {
			return fmt.Errorf("server: users[%d] (%s): secret_access_key must not be empty", i, u.AccessKeyID)
		}
		if seen[u.AccessKeyID] {
			return fmt.Errorf("server: duplicate access_key_id %q", u.AccessKeyID)
		}
		seen[u.AccessKeyID] = true
		if u.Policy != nil {
			if err := u.Policy.Validate(); err != nil {
				return fmt.Errorf("server: users[%d] (%s): %w", i, u.AccessKeyID, err)
			}
			if isAnonymous {
				if err := validateAnonymousPolicyActions(u.Policy); err != nil {
					return fmt.Errorf("server: users[%d] (%s): %w", i, u.AccessKeyID, err)
				}
			}
		}
	}
	return nil
}

// anonymousAllowedActions is the fixed set of s3:* actions permitted in an
// anonymous principal's policy: read-only object access, listing, and
// s3:ListAllMyBuckets (needed to Deny it -- see the doc comment below).
// Write and delete are never allowed, regardless of what the policy's
// Statement list contains.
var anonymousAllowedActions = map[string]bool{
	ActionGetObject:        true,
	ActionListBucket:       true,
	ActionListAllMyBuckets: true,
}

// validateAnonymousPolicyActions restricts the anonymous principal's policy
// to anonymousAllowedActions, so a "*" entry can only ever grant
// unauthenticated read/list access. Without this, the existing "nil Policy =
// full access" convention combined with a permissive Action wildcard could
// turn a single Users entry into an all-buckets, all-actions public grant.
//
// s3:ListAllMyBuckets is allowed here even though it grants nothing on its
// own (S3Action always defers GET / to FilterBucketNames -- see its doc
// comment) so that an anonymous policy can carry an explicit Deny on it.
// Once s3:ListBucket became grantable to "*", FilterBucketNames -- shared by
// every principal -- started including anonymously-listable buckets in
// unauthenticated GET / (name + creation date), which was previously
// impossible since "*" could never hold s3:ListBucket. A Deny here is the
// same documented escape hatch other principals already have (see
// ExplicitlyDeniedListAllMyBuckets and "Known gaps and quirks" in
// docs/users-policy.md) to hard-block that endpoint while still allowing
// per-bucket listing.
func validateAnonymousPolicyActions(p *Policy) error {
	for i, stmt := range p.Statement {
		for _, action := range stmt.Action {
			if !anonymousAllowedActions[action] {
				return fmt.Errorf("policy: statement[%d]: anonymous principal only supports Action %q, %q, or %q, got %q", i, ActionGetObject, ActionListBucket, ActionListAllMyBuckets, action)
			}
		}
	}
	return nil
}

func DefaultConfig() *Config {
	return &Config{
		Config: s2.Config{
			Type: s2.TypeOSFS,
			Root: DefaultRoot,
		},
		Listen:        ":9000",
		ConsoleListen: ":9001",
		HealthPath:    "/healthz",
		// MaxUploadSize intentionally left 0 — EffectiveMaxUploadSize resolves
		// a backend-appropriate default at request time.
		MaxPreviewSize: DefaultMaxPreviewSize,
	}
}

func (cfg *Config) LoadFile(filename string) error {
	data, err := os.ReadFile(filepath.Clean(filename))
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, cfg); err != nil {
		return err
	}
	return nil
}

func (cfg *Config) LoadEnv() error {
	if listen := os.Getenv(EnvS2ServerListen); listen != "" {
		cfg.Listen = listen
	}
	if v, ok := os.LookupEnv(EnvS2ServerConsoleListen); ok {
		// LookupEnv so the operator can explicitly disable the console
		// listener with an empty value, distinct from "unset".
		cfg.ConsoleListen = v
	}
	if v, ok := os.LookupEnv(EnvS2ServerHealthPath); ok {
		cfg.HealthPath = v
	}
	if v, ok := os.LookupEnv(EnvS2ServerS3Domain); ok {
		cfg.S3Domain = v
	}
	if typ := os.Getenv(EnvS2ServerType); typ != "" {
		cfg.Type = s2.Type(typ)
	}
	if root := os.Getenv(EnvS2ServerRoot); root != "" {
		cfg.Root = root
	}
	if v := os.Getenv(EnvS2ServerMaxUploadSize); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return fmt.Errorf("invalid %s: %w", EnvS2ServerMaxUploadSize, err)
		}
		cfg.MaxUploadSize = n
	}
	if v := os.Getenv(EnvS2ServerMaxPreviewSize); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return fmt.Errorf("invalid %s: %w", EnvS2ServerMaxPreviewSize, err)
		}
		cfg.MaxPreviewSize = n
	}
	if v := os.Getenv(EnvS2ServerMultipartMaxAge); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return fmt.Errorf("invalid %s: %w", EnvS2ServerMultipartMaxAge, err)
		}
		cfg.MultipartMaxAge = n
	}
	if v := os.Getenv(EnvS2ServerUser); v != "" {
		cfg.User = v
	}
	if v := os.Getenv(EnvS2ServerPassword); v != "" {
		cfg.Password = v
	}
	if v := os.Getenv(EnvS2ServerBuckets); v != "" {
		cfg.Buckets = splitBucketList(v)
	}
	return nil
}

// normalizeS3Domain normalizes a configured service domain to a plain
// lowercased DNS name. It accepts the common pasted forms -- an
// "http(s)://" URL with a path, a port, and a single FQDN trailing dot --
// because scheme/port belong to the listener and the trailing dot is
// conventional spelling; the wire Host header itself is never normalized
// (its trailing dot is rejected by matchBucketHost). Each label must be
// non-empty, at most 63 characters of [a-z0-9-], and not start or end
// with a hyphen.
func normalizeS3Domain(in string) (string, error) {
	d := strings.ToLower(strings.TrimSpace(in))
	for _, scheme := range []string{"https://", "http://"} {
		d = strings.TrimPrefix(d, scheme)
	}
	// Keep the host portion of any pasted URL only.
	if i := strings.IndexAny(d, "/?#"); i >= 0 {
		d = d[:i]
	}
	// A port in the config is meaningless; the listener owns it.
	if name, _, err := net.SplitHostPort(d); err == nil {
		d = name
	}
	d = strings.TrimSuffix(d, ".")
	if d == "" {
		return "", fmt.Errorf("must not be empty")
	}
	for _, label := range strings.Split(d, ".") {
		switch {
		case label == "":
			return "", fmt.Errorf("empty DNS label in %q", in)
		case len(label) > 63:
			return "", fmt.Errorf("DNS label %q is longer than 63 characters", label)
		case strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-"):
			return "", fmt.Errorf("DNS label %q must not start or end with a hyphen", label)
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
				return "", fmt.Errorf("DNS label %q contains illegal character %q", label, c)
			}
		}
	}
	return d, nil
}
