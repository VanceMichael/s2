package server_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/mojatter/s2/server"
	"github.com/mojatter/s2/server/middleware"
	"github.com/stretchr/testify/require"
)

// registerReloadProbesOnce installs the routes used by the reload E2E
// suite exactly once per test binary.
var registerReloadProbesOnce sync.Once

// This suite drives a full `server.Run` binary-style lifecycle against a
// config file and exercises credential rotation over real HTTP (SigV4
// header, SigV4 presigned query, anonymous principal, and Console
// BasicAuth) using process-directed SIGHUP/SIGTERM.

var reloadEnvVars = []string{
	"S2_SERVER_CONFIG", "S2_SERVER_LISTEN", "S2_SERVER_CONSOLE_LISTEN",
	"S2_SERVER_HEALTH_PATH", "S2_SERVER_TYPE", "S2_SERVER_ROOT",
	"S2_SERVER_MAX_UPLOAD_SIZE", "S2_SERVER_MAX_PREVIEW_SIZE",
	"S2_SERVER_MULTIPART_MAX_AGE", "S2_SERVER_USER", "S2_SERVER_PASSWORD",
	"S2_SERVER_BUCKETS",
}

func clearReloadEnv(t *testing.T) {
	t.Helper()
	for _, key := range reloadEnvVars {
		v, ok := os.LookupEnv(key)
		os.Unsetenv(key)
		if ok {
			t.Cleanup(func() { os.Setenv(key, v) })
		}
	}
}

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()
	require.NoError(t, ln.Close())
	return addr
}

func writeE2EConfig(t *testing.T, path string, cfg *server.Config) {
	t.Helper()
	data, err := json.MarshalIndent(cfg, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, data, 0o644))
}

func e2EBaseConfig(root, s3Addr, consoleAddr string) *server.Config {
	cfg := server.DefaultConfig()
	cfg.Root = root
	cfg.Listen = s3Addr
	cfg.ConsoleListen = consoleAddr
	return cfg
}

// --- minimal SigV4 signer (GET, empty body), mirroring middleware.sigV4 ---

const emptyPayloadSHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

func sigHMAC(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func awsURIEncode(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
			c == '-' || c == '_' || c == '.' || c == '~' {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

func canonicalQuery(rawQuery string) string {
	if rawQuery == "" {
		return ""
	}
	type kv struct{ k, v string }
	var pairs []kv
	for _, part := range strings.Split(rawQuery, "&") {
		if part == "" {
			continue
		}
		k, v, found := strings.Cut(part, "=")
		if !found {
			v = ""
		}
		kDec, _ := url.QueryUnescape(k)
		vDec, _ := url.QueryUnescape(v)
		pairs = append(pairs, kv{awsURIEncode(kDec), awsURIEncode(vDec)})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].k != pairs[j].k {
			return pairs[i].k < pairs[j].k
		}
		return pairs[i].v < pairs[j].v
	})
	parts := make([]string, len(pairs))
	for i, p := range pairs {
		parts[i] = p.k + "=" + p.v
	}
	return strings.Join(parts, "&")
}

// newSigV4Request builds a GET request authenticated with keyID/secret.
// With presign=false the signature travels in the Authorization header;
// with presign=true it travels in X-Amz-* query parameters.
func newSigV4Request(rawURL, keyID, secret string, presign bool) *http.Request {
	const region, service = "us-east-1", "s3"
	now := time.Now().UTC()
	date := now.Format("20060102")
	datetime := now.Format("20060102T150405Z")
	scope := date + "/" + region + "/" + service + "/aws4_request"

	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		panic(err)
	}
	u := req.URL
	payloadHash := emptyPayloadSHA256
	rawQuery := ""
	if presign {
		q := u.Query()
		q.Set("X-Amz-Algorithm", "AWS4-HMAC-SHA256")
		q.Set("X-Amz-Credential", keyID+"/"+scope)
		q.Set("X-Amz-Date", datetime)
		q.Set("X-Amz-Expires", "300")
		q.Set("X-Amz-SignedHeaders", "host")
		u.RawQuery = q.Encode()
		rawQuery = u.RawQuery
		payloadHash = "UNSIGNED-PAYLOAD"
	}

	canonReq := strings.Join([]string{
		http.MethodGet,
		u.Path,
		canonicalQuery(rawQuery),
		"host:" + u.Host,
		"",
		"host",
		payloadHash,
	}, "\n")
	canonHash := sha256.Sum256([]byte(canonReq))
	stringToSign := "AWS4-HMAC-SHA256\n" + datetime + "\n" + scope + "\n" +
		hex.EncodeToString(canonHash[:])
	kDate := sigHMAC([]byte("AWS4"+secret), []byte(date))
	kRegion := sigHMAC(kDate, []byte(region))
	kService := sigHMAC(kRegion, []byte(service))
	kSigning := sigHMAC(kService, []byte("aws4_request"))
	signature := hex.EncodeToString(sigHMAC(kSigning, []byte(stringToSign)))

	if presign {
		q := u.Query()
		q.Set("X-Amz-Signature", signature)
		u.RawQuery = q.Encode()
	} else {
		req.Header.Set("X-Amz-Date", datetime)
		req.Header.Set("X-Amz-Content-Sha256", emptyPayloadSHA256)
		req.Header.Set("Authorization",
			fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=host, Signature=%s",
				keyID, scope, signature))
	}
	return req
}

// reloadHTTPClient disables keep-alives so polled probes never leave idle
// server connections behind; otherwise graceful Shutdown would have to
// reap them on its own deadline during the SIGTERM phase of the test.
var reloadHTTPClient = &http.Client{
	Transport: &http.Transport{DisableKeepAlives: true},
}

func doStatus(req *http.Request) int {
	resp, err := reloadHTTPClient.Do(req)
	if err != nil {
		return -1
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

func requireStatusEventually(t *testing.T, want int, newReq func() *http.Request) {
	t.Helper()
	require.Eventually(t, func() bool {
		return doStatus(newReq()) == want
	}, 5*time.Second, 20*time.Millisecond)
}

func requireStatusConsistently(t *testing.T, want int, newReq func() *http.Request) {
	t.Helper()
	deadline := time.Now().Add(400 * time.Millisecond)
	for time.Now().Before(deadline) {
		require.Equal(t, want, doStatus(newReq()))
		time.Sleep(20 * time.Millisecond)
	}
}

func selfSignal(t *testing.T, sig syscall.Signal) {
	t.Helper()
	require.NoError(t, syscall.Kill(syscall.Getpid(), sig))
}

func TestRunSIGHUPReload(t *testing.T) {
	clearReloadEnv(t)

	// Hold the process's SIGHUP/SIGINT/SIGTERM notifications open for the
	// whole test. Go resets a signal to its default (terminating)
	// disposition when the last registration stops, and a signal landing
	// inside that Stop window can therefore kill the test process even
	// though Run consumed it. This independent registration keeps the
	// signals "captured" until after Run has fully returned; it is stopped
	// last because cleanups run in reverse registration order. It does not
	// change Run's own delivery (signals are fanned out to every
	// registered channel).
	holdSignals := make(chan os.Signal, 64)
	signal.Notify(holdSignals, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM)
	t.Cleanup(func() { signal.Stop(holdSignals) })

	root := t.TempDir()
	configPath := filepath.Join(root, "s2.json")
	s3Addr := freeAddr(t)
	consoleAddr := freeAddr(t)
	altAddr := freeAddr(t)

	// Unique patterns; no handlers/s3api package is imported by this test
	// binary, so the global registries start empty. Guarded by Once because
	// the registries are process-global and the test may run more than once
	// per binary (-count).
	registerReloadProbesOnce.Do(func() {
		probe := func(_ *server.Server, w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}
		server.RegisterS3HandleFunc("GET /{$}", middleware.SigV4(probe))
		server.RegisterS3HandleFunc("GET /{bucket}/{key...}", middleware.SigV4(probe))
		server.RegisterConsoleHandleFunc("GET /reload-probe", middleware.BasicAuth(probe))
	})

	readOnlyAnonymous := func() *server.Policy {
		return &server.Policy{Version: "2012-10-17", Statement: []server.Statement{{
			Effect:   "Allow",
			Action:   []string{server.ActionGetObject},
			Resource: []string{"arn:aws:s3:::*"},
		}}}
	}

	// Generation 1: single legacy credential.
	cfg := e2EBaseConfig(root, s3Addr, consoleAddr)
	cfg.User, cfg.Password = "ak1", "sk1"
	writeE2EConfig(t, configPath, cfg)

	args := []string{"s2-server", "-f", configPath}
	errCh := make(chan error, 1)
	runDone := make(chan struct{})
	go func() {
		errCh <- server.Run(args)
		close(runDone)
	}()

	// Fallback cleanup if an assertion fails before the explicit shutdown:
	// terminate the still-running server and wait for it to fully exit.
	t.Cleanup(func() {
		select {
		case <-runDone:
			return
		default:
		}
		_ = syscall.Kill(syscall.Getpid(), syscall.SIGTERM)
		select {
		case <-runDone:
		case <-time.After(10 * time.Second):
		}
	})

	require.Eventually(t, func() bool {
		conn, err := net.Dial("tcp", s3Addr)
		if err != nil {
			return false
		}
		_ = conn.Close()
		conn, err = net.Dial("tcp", consoleAddr)
		if err != nil {
			return false
		}
		_ = conn.Close()
		return true
	}, 5*time.Second, 10*time.Millisecond)

	s3ObjectURL := "http://" + s3Addr + "/bucket/key.txt"
	consoleURL := "http://" + consoleAddr + "/reload-probe"
	consoleReq := func(user, pass string) *http.Request {
		req, err := http.NewRequest(http.MethodGet, consoleURL, nil)
		require.NoError(t, err)
		req.SetBasicAuth(user, pass)
		return req
	}

	requireRunning := func(stage string) {
		t.Helper()
		select {
		case err := <-errCh:
			t.Fatalf("server exited during %s: %v", stage, err)
		default:
		}
	}

	// --- generation 1 expectations ---
	require.Equal(t, http.StatusOK, doStatus(newSigV4Request(s3ObjectURL, "ak1", "sk1", false)))
	require.Equal(t, http.StatusOK, doStatus(newSigV4Request(s3ObjectURL, "ak1", "sk1", true)))
	require.Equal(t, http.StatusForbidden, doStatus(newSigV4Request(s3ObjectURL, "ak1", "wrong", false)))
	require.Equal(t, http.StatusForbidden, doStatus(newSigV4Request(s3ObjectURL, "", "", false)))
	require.Equal(t, http.StatusOK, doStatus(consoleReq("ak1", "sk1")))
	require.Equal(t, http.StatusUnauthorized, doStatus(consoleReq("ak2", "sk2")))

	// --- rotate: ak2 legacy, a multi-user entry, and anonymous read ---
	cfg = e2EBaseConfig(root, s3Addr, consoleAddr)
	cfg.User, cfg.Password = "ak2", "sk2"
	cfg.Users = []server.User{
		{AccessKeyID: "mk", SecretAccessKey: "mk-secret"},
		{AccessKeyID: server.AnonymousAccessKeyID, Policy: readOnlyAnonymous()},
	}
	writeE2EConfig(t, configPath, cfg)
	selfSignal(t, syscall.SIGHUP)

	// New requests use the new generation: new secrets work everywhere.
	requireStatusEventually(t, http.StatusOK, func() *http.Request {
		return newSigV4Request(s3ObjectURL, "ak2", "sk2", false)
	})
	require.Equal(t, http.StatusOK, doStatus(newSigV4Request(s3ObjectURL, "ak2", "sk2", true)))
	require.Equal(t, http.StatusOK, doStatus(newSigV4Request(s3ObjectURL, "mk", "mk-secret", false)))
	require.Equal(t, http.StatusOK, doStatus(consoleReq("ak2", "sk2")))
	require.Equal(t, http.StatusOK, doStatus(consoleReq("mk", "mk-secret")))
	// Old generation's secret can no longer authenticate a new request,
	// neither as a header signature nor as a presigned URL.
	require.Equal(t, http.StatusForbidden, doStatus(newSigV4Request(s3ObjectURL, "ak1", "sk1", false)))
	require.Equal(t, http.StatusForbidden, doStatus(newSigV4Request(s3ObjectURL, "ak1", "sk1", true)))
	require.Equal(t, http.StatusUnauthorized, doStatus(consoleReq("ak1", "sk1")))
	// The anonymous principal from the new generation serves unsigned S3
	// requests, but can never be used to log into the console.
	require.Equal(t, http.StatusOK, doStatus(mustGet(s3ObjectURL)))
	require.Equal(t, http.StatusUnauthorized, doStatus(consoleReq(server.AnonymousAccessKeyID, "")))

	// --- invalid file: the service keeps gen 2 ---
	require.NoError(t, os.WriteFile(configPath, []byte(`{ "user": "ak-broken`), 0o644))
	selfSignal(t, syscall.SIGHUP)
	time.Sleep(300 * time.Millisecond) // let the failed reload settle
	requireStatusConsistently(t, http.StatusOK, func() *http.Request {
		return newSigV4Request(s3ObjectURL, "ak2", "sk2", false)
	})
	requireStatusConsistently(t, http.StatusOK, func() *http.Request { return mustGet(s3ObjectURL) })
	requireRunning("invalid config reload")

	// --- fix the file and reload: generation 3 recovers ---
	cfg = e2EBaseConfig(root, s3Addr, consoleAddr)
	cfg.User, cfg.Password = "ak3", "sk3"
	writeE2EConfig(t, configPath, cfg)
	selfSignal(t, syscall.SIGHUP)
	requireStatusEventually(t, http.StatusOK, func() *http.Request {
		return newSigV4Request(s3ObjectURL, "ak3", "sk3", false)
	})
	require.Equal(t, http.StatusForbidden, doStatus(newSigV4Request(s3ObjectURL, "ak2", "sk2", false)))
	// Anonymous principal disappeared with generation 2.
	require.Equal(t, http.StatusForbidden, doStatus(mustGet(s3ObjectURL)))

	// --- immutable drift (listen) is rejected; old listener keeps serving ---
	cfg = e2EBaseConfig(root, altAddr, consoleAddr)
	cfg.User, cfg.Password = "ak3", "sk3"
	writeE2EConfig(t, configPath, cfg)
	selfSignal(t, syscall.SIGHUP)
	time.Sleep(300 * time.Millisecond)
	requireStatusConsistently(t, http.StatusOK, func() *http.Request {
		return newSigV4Request(s3ObjectURL, "ak3", "sk3", false)
	})
	conn, err := net.DialTimeout("tcp", altAddr, 200*time.Millisecond)
	require.Error(t, err)
	if conn != nil {
		_ = conn.Close()
	}
	requireRunning("immutable field drift reload")

	// Recovery after a drift rejection.
	cfg = e2EBaseConfig(root, s3Addr, consoleAddr)
	cfg.User, cfg.Password = "ak4", "sk4"
	writeE2EConfig(t, configPath, cfg)
	selfSignal(t, syscall.SIGHUP)
	requireStatusEventually(t, http.StatusOK, func() *http.Request {
		return newSigV4Request(s3ObjectURL, "ak4", "sk4", false)
	})

	// --- SIGHUP burst: bounded coalescing, service stays up, converges ---
	cfg = e2EBaseConfig(root, s3Addr, consoleAddr)
	cfg.User, cfg.Password = "ak5", "sk5"
	writeE2EConfig(t, configPath, cfg)
	for i := 0; i < 50; i++ {
		selfSignal(t, syscall.SIGHUP)
	}
	requireStatusEventually(t, http.StatusOK, func() *http.Request {
		return newSigV4Request(s3ObjectURL, "ak5", "sk5", false)
	})
	require.Equal(t, http.StatusOK, doStatus(mustGet("http://"+s3Addr+"/healthz")))
	requireRunning("SIGHUP burst")

	// --- disabling auth by removing all credentials also reloads ---
	cfg = e2EBaseConfig(root, s3Addr, consoleAddr)
	writeE2EConfig(t, configPath, cfg)
	selfSignal(t, syscall.SIGHUP)
	requireStatusEventually(t, http.StatusOK, func() *http.Request { return mustGet(s3ObjectURL) })
	require.Equal(t, http.StatusOK, doStatus(mustGet(consoleURL)))
	requireRunning("auth-disabled reload")

	// --- SIGHUPs interleaved with SIGTERM converge into graceful shutdown ---
	cfg = e2EBaseConfig(root, s3Addr, consoleAddr)
	cfg.User, cfg.Password = "ak6", "sk6"
	writeE2EConfig(t, configPath, cfg)
	for i := 0; i < 20; i++ {
		selfSignal(t, syscall.SIGHUP)
	}
	selfSignal(t, syscall.SIGTERM)
	select {
	case err := <-errCh:
		require.NoError(t, err)
	case <-time.After(15 * time.Second):
		t.Fatal("Run did not return after SIGTERM interleaved with SIGHUPs")
	}
	require.Eventually(t, func() bool {
		c, dialErr := net.DialTimeout("tcp", s3Addr, 200*time.Millisecond)
		if c != nil {
			_ = c.Close()
		}
		return dialErr != nil
	}, 3*time.Second, 20*time.Millisecond)
}

func mustGet(rawURL string) *http.Request {
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		panic(err)
	}
	return req
}
