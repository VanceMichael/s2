package server

import (
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"reflect"
	"slices"
	"sync/atomic"
	"syscall"
)

// InitialGeneration is the generation number of the configuration the
// server was started with. Every successful SIGHUP reload publishes a new,
// monotonically increasing generation.
const InitialGeneration = 1

// configGeneration pairs one fully validated, immutable Config with its
// generation number. Once published, neither the pointer nor the Config it
// points to is ever mutated: a reload always builds a fresh Config and
// publishes a new configGeneration atomically. Requests that captured the
// old pointer keep using the old generation for their whole lifetime, so a
// secret/principal/policy from one generation can never be mixed with
// another's inside a single request.
type configGeneration struct {
	config     *Config
	generation uint64
}

// configStore holds the active config generation. Swap is the only
// mutation; reads are lock-free.
type configStore struct {
	active atomic.Pointer[configGeneration]
}

func newConfigStore(cfg *Config) *configStore {
	st := &configStore{}
	st.active.Store(&configGeneration{config: cfg, generation: InitialGeneration})
	return st
}

func (st *configStore) current() *Config {
	return st.active.Load().config
}

func (st *configStore) generation() uint64 {
	return st.active.Load().generation
}

// publish installs cfg as the next generation and returns its number. The
// CAS loop makes generation numbers strictly increasing even under
// concurrent callers (SIGHUP reloads themselves are serialized by Run).
func (st *configStore) publish(cfg *Config) uint64 {
	for {
		old := st.active.Load()
		next := &configGeneration{config: cfg, generation: old.generation + 1}
		if st.active.CompareAndSwap(old, next) {
			return next.generation
		}
	}
}

// CurrentConfig returns the configuration of the active generation. The
// returned pointer is shared by concurrent requests and must never be
// mutated; callers that need altered values must copy it first.
func (s *Server) CurrentConfig() *Config {
	if s.configs != nil {
		return s.configs.current()
	}
	// Tolerate Servers constructed by hand (e.g. middleware unit tests
	// that fill only the Config field).
	return s.Config
}

// ConfigGeneration returns the generation number of the active
// configuration, or InitialGeneration for hand-constructed Servers.
func (s *Server) ConfigGeneration() uint64 {
	if s.configs != nil {
		return s.configs.generation()
	}
	return InitialGeneration
}

// buildConfig constructs a candidate configuration using the same sources
// and precedence as startup: defaults < config file < environment
// variables < explicit command-line flags. It performs no validation;
// callers run Config.Validate (and, for reloads, checkImmutableFields) on
// the result.
func buildConfig(f *Flags) (*Config, error) {
	cfg := DefaultConfig()
	if f.configFile != "" {
		if err := cfg.LoadFile(f.configFile); err != nil {
			return nil, err
		}
	}
	if err := cfg.LoadEnv(); err != nil {
		return nil, err
	}
	// Flags have the highest precedence: default < file < env < flag.
	if f.listen != nil {
		cfg.Listen = *f.listen
	}
	if f.root != nil {
		cfg.Root = *f.root
	}
	if f.buckets != nil {
		cfg.Buckets = splitBucketList(*f.buckets)
	}
	return cfg, nil
}

// ReloadConfig rebuilds the configuration from the startup sources with the
// same precedence, validates the whole candidate, and -- when only mutable
// fields (legacy User/Password and Users, each with its credentials and
// policy) changed -- publishes it atomically as the next generation.
//
// On any failure (missing/unreadable file, invalid JSON, invalid policy,
// duplicate access key, or a drifted runtime/resource field) the active
// generation is left untouched and the error is returned; the server keeps
// serving with the previous configuration.
//
// Listeners, storage, and other runtime resources are never rebuilt here,
// so in-flight requests are never interrupted.
func (s *Server) ReloadConfig(f *Flags) (uint64, error) {
	cand, err := buildConfig(f)
	if err != nil {
		return 0, fmt.Errorf("reload: load candidate configuration: %w", err)
	}
	if err := cand.Validate(); err != nil {
		return 0, fmt.Errorf("reload: invalid candidate configuration: %w", err)
	}
	if err := checkImmutableFields(s.CurrentConfig(), cand); err != nil {
		return 0, err
	}
	return s.configs.publish(cand), nil
}

// reloadAndLog runs one reload, recording outcomes that are distinguishable
// in the log stream: successful publishes (Info, new generation) versus
// rejected candidates (Error, kept generation plus the cause).
func (s *Server) reloadAndLog(f *Flags) {
	gen, err := s.ReloadConfig(f)
	if err != nil {
		slog.Error("Configuration reload failed; continuing with previous configuration",
			"error", err, "generation", s.ConfigGeneration())
		return
	}
	cfg := s.CurrentConfig()
	slog.Info("Configuration reloaded",
		"generation", gen, "auth_enabled", cfg.AuthEnabled(), "users", len(cfg.Users))
}

// checkImmutableFields rejects candidates whose runtime/resource fields
// drifted from the running generation. Only Config.User, Config.Password,
// and Config.Users (credentials and policies) may change at runtime;
// everything else requires a restart. The comparison runs after
// Config.Validate, so a candidate reaching here is already a coherent
// configuration -- the rejection is specifically about drift.
func checkImmutableFields(old, cand *Config) error {
	if cand.Listen != old.Listen {
		return immutableFieldError("listen", old.Listen, cand.Listen)
	}
	if cand.ConsoleListen != old.ConsoleListen {
		return immutableFieldError("console_listen", old.ConsoleListen, cand.ConsoleListen)
	}
	if cand.HealthPath != old.HealthPath {
		return immutableFieldError("health_path", old.HealthPath, cand.HealthPath)
	}
	if cand.MaxUploadSize != old.MaxUploadSize {
		return immutableIntFieldError("max_upload_size", old.MaxUploadSize, cand.MaxUploadSize)
	}
	if cand.MaxPreviewSize != old.MaxPreviewSize {
		return immutableIntFieldError("max_preview_size", old.MaxPreviewSize, cand.MaxPreviewSize)
	}
	if cand.MultipartMaxAge != old.MultipartMaxAge {
		return immutableIntFieldError("multipart_max_age", old.MultipartMaxAge, cand.MultipartMaxAge)
	}
	if !slices.Equal(cand.Buckets, old.Buckets) {
		return fmt.Errorf("reload: initial buckets changed at runtime (old=%q new=%q); restart required",
			old.Buckets, cand.Buckets)
	}
	// The embedded s2.Config covers storage Type and Root, SignedURL, and
	// every per-backend block (S3/GCS/Azblob credentials and endpoints).
	if !reflect.DeepEqual(old.Config, cand.Config) {
		return fmt.Errorf("reload: storage configuration (type/root/backend settings) changed at runtime (old type=%q root=%q, new type=%q root=%q); restart required",
			old.Type, old.Root, cand.Type, cand.Root)
	}
	return nil
}

func immutableFieldError(field, oldValue, newValue string) error {
	return fmt.Errorf("reload: %s changed at runtime (old=%q new=%q); restart required", field, oldValue, newValue)
}

func immutableIntFieldError(field string, oldValue, newValue int64) error {
	return fmt.Errorf("reload: %s changed at runtime (old=%d new=%d); restart required", field, oldValue, newValue)
}

// newReloadSignals starts delivering SIGHUP on a buffered channel when the
// server was started with a configuration file. It returns nil for
// deployments without a config file: SIGHUP then stays unregistered and
// such a deployment keeps its original behavior.
//
// The channel buffer is 1. Go's signal delivery is non-blocking, so while
// one SIGHUP is being handled a burst of further signals coalesces into at
// most one queued wake-up (excess signals are dropped by the runtime); and
// because every reload re-reads the file from disk, that single wake-up
// still converges on the latest file contents. Finite signal bursts
// therefore terminate after a bounded number of reloads with no per-signal
// goroutines.
func newReloadSignals(configFile string) chan os.Signal {
	if configFile == "" {
		return nil
	}
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP)
	return ch
}
