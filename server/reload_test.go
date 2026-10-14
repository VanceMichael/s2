package server

import (
	"context"
	"encoding/json"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/mojatter/s2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// configEnvVars are every environment variable consulted by LoadEnv;
// tests clear them so a developer machine or CI cannot change precedence
// results, and restore the original values on cleanup.
var configEnvVars = []string{
	EnvS2ServerConfig,
	EnvS2ServerListen,
	EnvS2ServerConsoleListen,
	EnvS2ServerHealthPath,
	EnvS2ServerType,
	EnvS2ServerRoot,
	EnvS2ServerMaxUploadSize,
	EnvS2ServerMaxPreviewSize,
	EnvS2ServerMultipartMaxAge,
	EnvS2ServerUser,
	EnvS2ServerPassword,
	EnvS2ServerBuckets,
}

func clearConfigEnv(t *testing.T) {
	t.Helper()
	for _, key := range configEnvVars {
		v, ok := os.LookupEnv(key)
		os.Unsetenv(key)
		if ok {
			t.Cleanup(func() { os.Setenv(key, v) })
		}
	}
}

// writeReloadConfig marshals cfg as JSON to path.
func writeReloadConfig(t *testing.T, path string, cfg *Config) {
	t.Helper()
	data, err := json.MarshalIndent(cfg, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, data, 0o644))
}

// reloadTestConfig builds a valid, self-contained config rooted in a temp
// directory with the console disabled; mutable credential fields are
// filled by the caller.
func reloadTestConfig(root string) *Config {
	cfg := DefaultConfig()
	cfg.Root = root
	cfg.Listen = "127.0.0.1:9911"
	cfg.ConsoleListen = ""
	return cfg
}

func TestConfigStoreInitialAndPublish(t *testing.T) {
	first := &Config{User: "u1", Password: "p1"}
	st := newConfigStore(first)

	assert.Equal(t, uint64(InitialGeneration), st.generation())
	assert.Same(t, first, st.current())

	second := &Config{User: "u2", Password: "p2"}
	gen := st.publish(second)
	assert.Equal(t, uint64(2), gen)
	assert.Same(t, second, st.current())

	// The previous generation's pointer stays readable and untouched: a
	// request already holding it finishes against u1/p1.
	assert.Equal(t, "u1", first.User)
	assert.Equal(t, "p1", first.Password)
}

func TestConfigStorePublishMonotonicUnderConcurrency(t *testing.T) {
	st := newConfigStore(&Config{})
	const n = 100

	var wg sync.WaitGroup
	wg.Add(n)
	gens := make(chan uint64, n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			gens <- st.publish(&Config{})
		}()
	}
	wg.Wait()
	close(gens)

	seen := make(map[uint64]bool, n)
	for g := range gens {
		assert.False(t, seen[g], "duplicate generation %d", g)
		seen[g] = true
	}
	assert.Equal(t, uint64(InitialGeneration+n), st.generation())
}

func TestBuildConfigPrecedence(t *testing.T) {
	clearConfigEnv(t)
	root := t.TempDir()
	path := filepath.Join(root, "s2.json")

	fileCfg := reloadTestConfig(root)
	fileCfg.Listen = "127.0.0.1:7001"
	fileCfg.User = "file-user"
	fileCfg.Buckets = []string{"file-bucket"}
	writeReloadConfig(t, path, fileCfg)

	t.Setenv(EnvS2ServerListen, "127.0.0.1:7002")
	t.Setenv(EnvS2ServerUser, "env-user")
	t.Setenv(EnvS2ServerBuckets, "env-bucket")

	flagListen := "127.0.0.1:7003"
	flagBuckets := "flag-bucket"
	f := &Flags{configFile: path, listen: &flagListen, buckets: &flagBuckets}

	cfg, err := buildConfig(f)
	require.NoError(t, err)

	// Explicit flag beats env beats file.
	assert.Equal(t, "127.0.0.1:7003", cfg.Listen)
	assert.Equal(t, "env-user", cfg.User)
	assert.Equal(t, []string{"flag-bucket"}, cfg.Buckets)
	// Non-overridden file fields survive.
	assert.Equal(t, root, cfg.Root)
	assert.Equal(t, "/healthz", cfg.HealthPath)
}

func TestBuildConfigWithoutFile(t *testing.T) {
	clearConfigEnv(t)
	cfg, err := buildConfig(&Flags{})
	require.NoError(t, err)
	assert.Equal(t, DefaultConfig(), cfg)
}

func TestCheckImmutableFields(t *testing.T) {
	readOnlyPolicy := &Policy{Version: "2012-10-17", Statement: []Statement{
		{Effect: "Allow", Action: []string{ActionGetObject}, Resource: []string{"arn:aws:s3:::*"}},
	}}

	base := reloadTestConfig(t.TempDir())
	base.User = "admin"
	base.Password = "secret"
	base.Buckets = []string{"initial"}
	base.Users = []User{
		{AccessKeyID: "ro", SecretAccessKey: "ro-secret", Policy: readOnlyPolicy},
	}

	mutable := map[string]func(*Config){
		"legacy password rotated": func(c *Config) { c.Password = "rotated" },
		"legacy user rotated":     func(c *Config) { c.User = "admin2" },
		"users entry added":       func(c *Config) { c.Users = append(c.Users, User{AccessKeyID: "n2", SecretAccessKey: "s2"}) },
		"users entry removed":     func(c *Config) { c.Users = nil },
		"user secret rotated":     func(c *Config) { c.Users[0].SecretAccessKey = "new-secret" },
		"user policy replaced": func(c *Config) {
			c.Users[0].Policy = &Policy{Version: "2012-10-17", Statement: []Statement{
				{Effect: "Allow", Action: []string{ActionListBucket}, Resource: []string{"arn:aws:s3:::*"}},
			}}
		},
		"auth disabled by empty user": func(c *Config) { c.User, c.Password, c.Users = "", "", nil },
	}
	for name, mutate := range mutable {
		t.Run("mutable/"+name, func(t *testing.T) {
			cand := *base
			mutate(&cand)
			assert.NoError(t, checkImmutableFields(base, &cand))
		})
	}

	immutable := map[string]func(*Config){
		"listen":          func(c *Config) { c.Listen = "127.0.0.1:1" },
		"console_listen":  func(c *Config) { c.ConsoleListen = "127.0.0.1:1" },
		"health_path":     func(c *Config) { c.HealthPath = "/ready" },
		"max_upload_size": func(c *Config) { c.MaxUploadSize = 1234 },
		"max_preview":     func(c *Config) { c.MaxPreviewSize = 4321 },
		"multipart_age":   func(c *Config) { c.MultipartMaxAge = 99 },
		"buckets":         func(c *Config) { c.Buckets = []string{"different"} },
		"storage type":    func(c *Config) { c.Type = s2.TypeMemFS },
		"storage root":    func(c *Config) { c.Root = "/somewhere/else" },
		"signed_url":      func(c *Config) { c.SignedURL = "http://example" },
		"s3 backend":      func(c *Config) { c.S3 = &s2.S3Config{EndpointURL: "http://s3"} },
		"gcs backend":     func(c *Config) { c.GCS = &s2.GCSConfig{CredentialsFile: "/k.json"} },
		"azblob backend":  func(c *Config) { c.Azblob = &s2.AzblobConfig{AccountName: "acct"} },
	}
	for name, mutate := range immutable {
		t.Run("immutable/"+name, func(t *testing.T) {
			cand := *base
			mutate(&cand)
			err := checkImmutableFields(base, &cand)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "changed at runtime")
		})
	}
}

func TestReloadConfigPublishesMutableChanges(t *testing.T) {
	clearConfigEnv(t)
	root := t.TempDir()
	path := filepath.Join(root, "s2.json")

	first := reloadTestConfig(root)
	first.User, first.Password = "user1", "pass1"
	writeReloadConfig(t, path, first)

	f := &Flags{configFile: path}
	cfg, err := buildConfig(f)
	require.NoError(t, err)
	srv, err := NewServer(context.Background(), cfg)
	require.NoError(t, err)
	assert.Equal(t, uint64(1), srv.ConfigGeneration())

	// A request-like reader captures the generation before the reload.
	oldGen := srv.CurrentConfig()

	second := reloadTestConfig(root)
	second.User, second.Password = "user2", "pass2"
	second.Users = []User{
		{AccessKeyID: "ro", SecretAccessKey: "ro-pass", Policy: &Policy{
			Version: "2012-10-17",
			Statement: []Statement{{
				Effect: "Allow", Action: []string{ActionGetObject}, Resource: []string{"arn:aws:s3:::*"},
			}},
		}},
	}
	writeReloadConfig(t, path, second)

	gen, err := srv.ReloadConfig(f)
	require.NoError(t, err)
	assert.Equal(t, uint64(2), gen)

	current := srv.CurrentConfig()
	assert.Equal(t, "user2", current.User)
	assert.Equal(t, "pass2", current.Password)
	require.Len(t, current.Users, 1)
	assert.Equal(t, "ro", current.Users[0].AccessKeyID)

	// The startup Config is untouched and immutable fields stayed equal.
	assert.Equal(t, "user1", srv.Config.User)
	assert.Equal(t, first.Listen, current.Listen)

	// The captured old generation still resolves the old principal with
	// the old secret: an in-flight request that took its snapshot before
	// publish can never observe user2's principal or policy.
	u := oldGen.LookupUser("user1")
	require.NotNil(t, u)
	assert.Equal(t, "pass1", u.SecretAccessKey)
	assert.Nil(t, oldGen.LookupUser("user2"))
	assert.Nil(t, oldGen.LookupUser("ro"))
}

func TestReloadConfigRejectsAndKeepsOldGeneration(t *testing.T) {
	clearConfigEnv(t)
	root := t.TempDir()
	path := filepath.Join(root, "s2.json")

	first := reloadTestConfig(root)
	first.User, first.Password = "user1", "pass1"
	writeReloadConfig(t, path, first)

	f := &Flags{configFile: path}
	cfg, err := buildConfig(f)
	require.NoError(t, err)
	srv, err := NewServer(context.Background(), cfg)
	require.NoError(t, err)

	// A valid rotation first, so later failures can be proven to roll back
	// to this generation rather than the startup one.
	rotated := reloadTestConfig(root)
	rotated.User, rotated.Password = "good2", "good2-pass"
	writeReloadConfig(t, path, rotated)
	gen, err := srv.ReloadConfig(f)
	require.NoError(t, err)
	require.Equal(t, uint64(2), gen)

	rejectAndKeepGen2 := func(t *testing.T, name string, write func(t *testing.T, path string)) {
		t.Helper()
		write(t, path)
		_, err := srv.ReloadConfig(f)
		require.Error(t, err, name)
		assert.Equal(t, uint64(2), srv.ConfigGeneration(), name)
		current := srv.CurrentConfig()
		assert.Equal(t, "good2", current.User, name)
		assert.Equal(t, "good2-pass", current.Password, name)
	}

	t.Run("malformed JSON", func(t *testing.T) {
		rejectAndKeepGen2(t, "malformed JSON", func(t *testing.T, path string) {
			require.NoError(t, os.WriteFile(path, []byte(`{ "user": "broken`), 0o644))
		})
	})

	t.Run("missing file", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "missing.json")
		_, err := srv.ReloadConfig(&Flags{configFile: missing})
		require.Error(t, err)
		assert.Equal(t, uint64(2), srv.ConfigGeneration())
	})

	t.Run("duplicate access key", func(t *testing.T) {
		rejectAndKeepGen2(t, "duplicate access key", func(t *testing.T, path string) {
			bad := reloadTestConfig(root)
			bad.User, bad.Password = "dup", "p"
			bad.Users = []User{
				{AccessKeyID: "dup", SecretAccessKey: "p2"},
			}
			writeReloadConfig(t, path, bad)
		})
	})

	t.Run("invalid policy", func(t *testing.T) {
		rejectAndKeepGen2(t, "invalid policy", func(t *testing.T, path string) {
			bad := reloadTestConfig(root)
			bad.User, bad.Password = "good2", "good2-pass"
			bad.Users = []User{{
				AccessKeyID:     "ro",
				SecretAccessKey: "ro-pass",
				Policy: &Policy{Statement: []Statement{{
					Effect: "Maybe", Action: []string{ActionGetObject}, Resource: []string{"arn:aws:s3:::*"},
				}}},
			}}
			writeReloadConfig(t, path, bad)
		})
	})

	t.Run("immutable field drift", func(t *testing.T) {
		rejectAndKeepGen2(t, "immutable drift", func(t *testing.T, path string) {
			bad := reloadTestConfig(root)
			bad.Listen = "127.0.0.1:4242"
			bad.User, bad.Password = "good2", "good2-pass"
			writeReloadConfig(t, path, bad)
		})
	})

	// Fixing the source and reloading recovers: the generation after the
	// rejected attempts is exactly 3, proving none of them published.
	fixed := reloadTestConfig(root)
	fixed.User, fixed.Password = "good3", "good3-pass"
	writeReloadConfig(t, path, fixed)
	gen, err = srv.ReloadConfig(f)
	require.NoError(t, err)
	assert.Equal(t, uint64(3), gen)
	assert.Equal(t, "good3", srv.CurrentConfig().User)
}

func TestNewReloadSignals(t *testing.T) {
	t.Run("no config file means no SIGHUP handler", func(t *testing.T) {
		assert.Nil(t, newReloadSignals(""))
	})

	t.Run("SIGHUP is delivered until stopped", func(t *testing.T) {
		ch := newReloadSignals(t.Name())
		t.Cleanup(func() { signal.Stop(ch) })

		require.NoError(t, syscall.Kill(syscall.Getpid(), syscall.SIGHUP))
		select {
		case <-ch:
		case <-time.After(500 * time.Millisecond):
			t.Fatal("SIGHUP was not delivered to the reload channel")
		}
	})
}
