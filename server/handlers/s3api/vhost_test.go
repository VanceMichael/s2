package s3api

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/mojatter/s2"
	"github.com/mojatter/s2/server"
	"github.com/stretchr/testify/require"
)

const (
	vhostTestDomain    = "s3.local.test"
	vhostTestAccessKey = "testak"
	vhostTestSecret    = "testsecret"
	vhostTestRegion    = "us-east-1"
	vhostTestService   = "s3"

	vhostEmptySHA = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

// vhostHarness wires a real listener and server; requests carry arbitrary
// Host headers (set on req.Host) so no DNS is involved.
type vhostHarness struct {
	t      *testing.T
	srv    *server.Server
	ts     *httptest.Server
	client *http.Client
}

func newVhostHarness(t *testing.T, configure func(*server.Config)) *vhostHarness {
	cfg := server.DefaultConfig()
	cfg.Root = t.TempDir()
	cfg.S3Domain = vhostTestDomain
	cfg.User = vhostTestAccessKey
	cfg.Password = vhostTestSecret
	if configure != nil {
		configure(cfg)
	}
	srv, err := server.NewServer(context.Background(), cfg)
	require.NoError(t, err)
	ts := httptest.NewServer(srv.S3Handler())
	t.Cleanup(ts.Close)
	return &vhostHarness{
		t:      t,
		srv:    srv,
		ts:     ts,
		client: &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
	}
}

func (h *vhostHarness) request(method, host, target string, body []byte) *http.Request {
	h.t.Helper()
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, h.ts.URL+target, rdr)
	require.NoError(h.t, err)
	if host != "" {
		req.Host = host
	}
	return req
}

func (h *vhostHarness) do(req *http.Request) (*http.Response, string) {
	h.t.Helper()
	resp, err := h.client.Do(req)
	require.NoError(h.t, err)
	b, err := io.ReadAll(resp.Body)
	require.NoError(h.t, err)
	require.NoError(h.t, resp.Body.Close())
	return resp, string(b)
}

func (h *vhostHarness) seedObject(bucket, key, content string) {
	h.t.Helper()
	ctx := context.Background()
	if ok, _ := h.srv.Buckets.Exists(ctx, bucket); !ok {
		require.NoError(h.t, h.srv.Buckets.Create(ctx, bucket))
	}
	strg, err := h.srv.Buckets.Get(ctx, bucket)
	require.NoError(h.t, err)
	require.NoError(h.t, strg.Put(ctx, s2.NewObjectBytes(key, []byte(content))))
}

// ---------------------------------------------------------------------------
// Test-side SigV4 implementation, mirroring server/middleware semantics so a
// signature produced here is exactly what the AWS SDK would produce.
// ---------------------------------------------------------------------------

func vhostSHA256(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func vhostHMAC(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func vhostSigningKey(secret, date string) []byte {
	kDate := vhostHMAC([]byte("AWS4"+secret), []byte(date))
	kRegion := vhostHMAC(kDate, []byte(vhostTestRegion))
	kService := vhostHMAC(kRegion, []byte(vhostTestService))
	return vhostHMAC(kService, []byte("aws4_request"))
}

func vhostURIEncode(s string) string {
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

func vhostCanonicalURI(r *http.Request) string {
	if r.URL.Path == "" {
		return "/"
	}
	segments := strings.Split(r.URL.Path, "/")
	for i, seg := range segments {
		segments[i] = vhostURIEncode(seg)
	}
	return strings.Join(segments, "/")
}

func vhostCanonicalQuery(rawQuery string) string {
	if rawQuery == "" {
		return ""
	}
	type kv struct{ k, v string }
	var pairs []kv
	for _, part := range strings.Split(rawQuery, "&") {
		if part == "" {
			continue
		}
		idx := strings.IndexByte(part, '=')
		var k, v string
		if idx < 0 {
			k = part
		} else {
			k, v = part[:idx], part[idx+1:]
		}
		kDec, _ := url.QueryUnescape(k)
		vDec, _ := url.QueryUnescape(v)
		pairs = append(pairs, kv{vhostURIEncode(kDec), vhostURIEncode(vDec)})
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

func vhostHeaderValue(r *http.Request, name string) string {
	if name == "host" {
		if r.Host != "" {
			return r.Host
		}
		return r.URL.Host
	}
	return strings.TrimSpace(r.Header.Get(name))
}

func vhostCanonicalRequest(r *http.Request, headers []string, rawQuery, payloadHash string) string {
	sorted := append([]string(nil), headers...)
	sort.Strings(sorted)
	var b strings.Builder
	b.WriteString(r.Method)
	b.WriteByte('\n')
	b.WriteString(vhostCanonicalURI(r))
	b.WriteByte('\n')
	b.WriteString(vhostCanonicalQuery(rawQuery))
	b.WriteByte('\n')
	for _, name := range sorted {
		b.WriteString(name)
		b.WriteByte(':')
		b.WriteString(vhostHeaderValue(r, name))
		b.WriteByte('\n')
	}
	b.WriteByte('\n')
	b.WriteString(strings.Join(sorted, ";"))
	b.WriteByte('\n')
	b.WriteString(payloadHash)
	return b.String()
}

// vhostSignHeader adds an Authorization-header signature. Every present
// x-amz-* header plus host is signed, like the AWS SDK.
func vhostSignHeader(r *http.Request, accessKey, secret string, now time.Time) {
	date := now.Format("20060102")
	datetime := now.Format("20060102T150405Z")
	if r.Header.Get("X-Amz-Content-Sha256") == "" {
		r.Header.Set("X-Amz-Content-Sha256", vhostEmptySHA)
	}
	payloadHash := r.Header.Get("X-Amz-Content-Sha256")
	r.Header.Set("X-Amz-Date", datetime)

	seen := map[string]bool{"host": true}
	var headers []string
	for name := range r.Header {
		lname := strings.ToLower(name)
		if strings.HasPrefix(lname, "x-amz-") && !seen[lname] {
			seen[lname] = true
			headers = append(headers, lname)
		}
	}
	headers = append(headers, "host")
	sort.Strings(headers)

	scope := date + "/" + vhostTestRegion + "/" + vhostTestService + "/aws4_request"
	canon := vhostCanonicalRequest(r, headers, r.URL.RawQuery, payloadHash)
	sts := "AWS4-HMAC-SHA256\n" + datetime + "\n" + scope + "\n" + vhostSHA256([]byte(canon))
	sig := hex.EncodeToString(vhostHMAC(vhostSigningKey(secret, date), []byte(sts)))
	r.Header.Set("Authorization", fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		accessKey, scope, strings.Join(headers, ";"), sig))
}

// vhostPresign rewrites RawQuery into a presigned URL.
func vhostPresign(r *http.Request, accessKey, secret string, expires int, now time.Time) {
	date := now.Format("20060102")
	datetime := now.Format("20060102T150405Z")
	if r.Host == "" {
		r.Host = vhostTestDomain
	}
	scope := date + "/" + vhostTestRegion + "/" + vhostTestService + "/aws4_request"

	q := r.URL.Query()
	q.Set("X-Amz-Algorithm", "AWS4-HMAC-SHA256")
	q.Set("X-Amz-Credential", accessKey+"/"+scope)
	q.Set("X-Amz-Date", datetime)
	q.Set("X-Amz-Expires", fmt.Sprintf("%d", expires))
	q.Set("X-Amz-SignedHeaders", "host")
	r.URL.RawQuery = q.Encode()

	canon := vhostCanonicalRequest(r, []string{"host"}, r.URL.RawQuery, "UNSIGNED-PAYLOAD")
	sts := "AWS4-HMAC-SHA256\n" + datetime + "\n" + scope + "\n" + vhostSHA256([]byte(canon))
	sig := hex.EncodeToString(vhostHMAC(vhostSigningKey(secret, date), []byte(sts)))

	q.Set("X-Amz-Signature", sig)
	r.URL.RawQuery = q.Encode()
}

// ---------------------------------------------------------------------------
// Routing: object with an encoded space, all operations
// ---------------------------------------------------------------------------

func TestVHostObjectWithEncodedSpace(t *testing.T) {
	h := newVhostHarness(t, nil)
	h.seedObject("photos", "dir/a b.txt", "hello-space")

	req := h.request(http.MethodGet, "photos."+vhostTestDomain, "/dir/a%20b.txt", nil)
	vhostSignHeader(req, vhostTestAccessKey, vhostTestSecret, time.Now().UTC())
	resp, body := h.do(req)

	require.Equal(t, http.StatusOK, resp.StatusCode, body)
	require.Equal(t, "hello-space", body)
}

func TestVHostObjectPortStripped(t *testing.T) {
	h := newVhostHarness(t, nil)
	h.seedObject("photos", "dir/a b.txt", "hello-port")

	// Host carries the listener port; it is stripped for classification but
	// stays part of the signed Host header value.
	req := h.request(http.MethodGet, "photos."+vhostTestDomain+":9000", "/dir/a%20b.txt", nil)
	vhostSignHeader(req, vhostTestAccessKey, vhostTestSecret, time.Now().UTC())
	resp, body := h.do(req)

	require.Equal(t, http.StatusOK, resp.StatusCode, body)
	require.Equal(t, "hello-port", body)
}

// ---------------------------------------------------------------------------
// Signature tampering: Host, path, query each independently signed
// ---------------------------------------------------------------------------

func TestVHostSignedHostTamperRejected(t *testing.T) {
	h := newVhostHarness(t, nil)
	h.seedObject("photos", "dir/a b.txt", "x")
	h.seedObject("otherbucket", "secret.txt", "y")

	req := h.request(http.MethodGet, "photos."+vhostTestDomain, "/dir/a%20b.txt", nil)
	vhostSignHeader(req, vhostTestAccessKey, vhostTestSecret, time.Now().UTC())
	// Resign nothing; just present the signed request to another bucket host.
	req.Host = "otherbucket." + vhostTestDomain
	resp, body := h.do(req)

	require.Equal(t, http.StatusForbidden, resp.StatusCode, body)
	require.Contains(t, body, "SignatureDoesNotMatch")
}

func TestVHostSignedPathTamperRejected(t *testing.T) {
	h := newVhostHarness(t, nil)
	h.seedObject("photos", "dir/a b.txt", "x")
	h.seedObject("photos", "dir/c.txt", "leaked")

	signed := h.request(http.MethodGet, "photos."+vhostTestDomain, "/dir/a%20b.txt", nil)
	vhostSignHeader(signed, vhostTestAccessKey, vhostTestSecret, time.Now().UTC())

	tampered := h.request(http.MethodGet, "photos."+vhostTestDomain, "/dir/c.txt", nil)
	tampered.Header = signed.Header.Clone()
	resp, body := h.do(tampered)

	require.Equal(t, http.StatusForbidden, resp.StatusCode, body)
	require.Contains(t, body, "SignatureDoesNotMatch")
}

func TestVHostSignedQueryTamperRejected(t *testing.T) {
	h := newVhostHarness(t, nil)
	h.seedObject("photos", "dir/a b.txt", "x")

	req := h.request(http.MethodGet, "photos."+vhostTestDomain, "/dir/a%20b.txt", nil)
	vhostSignHeader(req, vhostTestAccessKey, vhostTestSecret, time.Now().UTC())
	req.URL.RawQuery += "&tampered=1"
	resp, body := h.do(req)

	require.Equal(t, http.StatusForbidden, resp.StatusCode, body)
	require.Contains(t, body, "SignatureDoesNotMatch")
}

// ---------------------------------------------------------------------------
// Presigned URLs
// ---------------------------------------------------------------------------

func TestVHostPresignedURL(t *testing.T) {
	h := newVhostHarness(t, nil)
	h.seedObject("photos", "dir/a b.txt", "presigned-body")

	req := h.request(http.MethodGet, "photos."+vhostTestDomain, "/dir/a%20b.txt", nil)
	vhostPresign(req, vhostTestAccessKey, vhostTestSecret, 300, time.Now().UTC())
	resp, body := h.do(req)
	require.Equal(t, http.StatusOK, resp.StatusCode, body)
	require.Equal(t, "presigned-body", body)
}

func TestVHostPresignedURLQueryTamperRejected(t *testing.T) {
	h := newVhostHarness(t, nil)
	h.seedObject("photos", "dir/a b.txt", "x")

	req := h.request(http.MethodGet, "photos."+vhostTestDomain, "/dir/a%20b.txt", nil)
	vhostPresign(req, vhostTestAccessKey, vhostTestSecret, 300, time.Now().UTC())
	req.URL.RawQuery += "&tampered=1"
	resp, body := h.do(req)
	require.Equal(t, http.StatusForbidden, resp.StatusCode, body)
	require.Contains(t, body, "SignatureDoesNotMatch")
}

func TestVHostPresignedURLExpiredRejected(t *testing.T) {
	h := newVhostHarness(t, nil)
	h.seedObject("photos", "dir/a b.txt", "x")

	req := h.request(http.MethodGet, "photos."+vhostTestDomain, "/dir/a%20b.txt", nil)
	vhostPresign(req, vhostTestAccessKey, vhostTestSecret, 300, time.Now().Add(-10*time.Minute).UTC())
	resp, body := h.do(req)
	require.Equal(t, http.StatusForbidden, resp.StatusCode, body)
	require.Contains(t, body, "SignatureDoesNotMatch")
}

// ---------------------------------------------------------------------------
// Principal policy is evaluated against the same logical (Host) resource
// ---------------------------------------------------------------------------

func TestVHostPolicyScopedToBucket(t *testing.T) {
	const limitedAK, limitedSecret = "limited", "limited-secret"
	h := newVhostHarness(t, func(cfg *server.Config) {
		cfg.Users = []server.User{{
			AccessKeyID:     limitedAK,
			SecretAccessKey: limitedSecret,
			Policy: &server.Policy{
				Version: "2012-10-17",
				Statement: []server.Statement{{
					Effect:   "Allow",
					Action:   []string{"s3:GetObject"},
					Resource: []string{"arn:aws:s3:::photos/*"},
				}},
			},
		}}
	})
	h.seedObject("photos", "dir/a b.txt", "allowed")
	h.seedObject("otherbucket", "secret.txt", "secret")

	// Allowed: same logical bucket/key the policy names.
	req := h.request(http.MethodGet, "photos."+vhostTestDomain, "/dir/a%20b.txt", nil)
	vhostSignHeader(req, limitedAK, limitedSecret, time.Now().UTC())
	resp, body := h.do(req)
	require.Equal(t, http.StatusOK, resp.StatusCode, body)
	require.Equal(t, "allowed", body)

	// Denied: Host bucket otherbucket is a distinct resource.
	req = h.request(http.MethodGet, "otherbucket."+vhostTestDomain, "/secret.txt", nil)
	vhostSignHeader(req, limitedAK, limitedSecret, time.Now().UTC())
	resp, body = h.do(req)
	require.Equal(t, http.StatusForbidden, resp.StatusCode, body)
	require.Contains(t, body, "AccessDenied")

	// Denied: PutObject not in the policy, same bucket.
	req = h.request(http.MethodPut, "photos."+vhostTestDomain, "/new.txt", []byte("data"))
	req.Header.Set("X-Amz-Content-Sha256", vhostSHA256([]byte("data")))
	vhostSignHeader(req, limitedAK, limitedSecret, time.Now().UTC())
	resp, body = h.do(req)
	require.Equal(t, http.StatusForbidden, resp.StatusCode, body)
	require.Contains(t, body, "AccessDenied")

	// Denied: ListBucket not granted.
	req = h.request(http.MethodGet, "photos."+vhostTestDomain, "/", nil)
	vhostSignHeader(req, limitedAK, limitedSecret, time.Now().UTC())
	resp, body = h.do(req)
	require.Equal(t, http.StatusForbidden, resp.StatusCode, body)
	require.Contains(t, body, "AccessDenied")
}

func TestVHostPolicyExactKeyWithSpace(t *testing.T) {
	const limitedAK, limitedSecret = "exact", "exact-secret"
	h := newVhostHarness(t, func(cfg *server.Config) {
		cfg.Users = []server.User{{
			AccessKeyID:     limitedAK,
			SecretAccessKey: limitedSecret,
			Policy: &server.Policy{
				Version: "2012-10-17",
				Statement: []server.Statement{{
					Effect:   "Allow",
					Action:   []string{"s3:GetObject"},
					Resource: []string{"arn:aws:s3:::photos/dir/a b.txt"},
				}},
			},
		}}
	})
	h.seedObject("photos", "dir/a b.txt", "exact")
	h.seedObject("photos", "dir/c.txt", "other")

	req := h.request(http.MethodGet, "photos."+vhostTestDomain, "/dir/a%20b.txt", nil)
	vhostSignHeader(req, limitedAK, limitedSecret, time.Now().UTC())
	resp, body := h.do(req)
	require.Equal(t, http.StatusOK, resp.StatusCode, body)

	req = h.request(http.MethodGet, "photos."+vhostTestDomain, "/dir/c.txt", nil)
	vhostSignHeader(req, limitedAK, limitedSecret, time.Now().UTC())
	resp, body = h.do(req)
	require.Equal(t, http.StatusForbidden, resp.StatusCode, body)
	require.Contains(t, body, "AccessDenied")
}

// ---------------------------------------------------------------------------
// Service root: ListBuckets and health on the bare domain; path-style still
// works on the root and on unknown hosts.
// ---------------------------------------------------------------------------

func TestVHostServiceRootListBucketsAndHealth(t *testing.T) {
	h := newVhostHarness(t, nil)
	h.seedObject("photos", "dir/a b.txt", "x")
	h.seedObject("otherbucket", "k.txt", "y")

	// ListBuckets on the bare domain.
	req := h.request(http.MethodGet, vhostTestDomain, "/", nil)
	vhostSignHeader(req, vhostTestAccessKey, vhostTestSecret, time.Now().UTC())
	resp, body := h.do(req)
	require.Equal(t, http.StatusOK, resp.StatusCode, body)
	var result ListAllMyBucketsResult
	require.NoError(t, xml.Unmarshal([]byte(body), &result))
	names := make(map[string]bool)
	for _, b := range result.Buckets {
		names[b.Name] = true
	}
	require.True(t, names["photos"])
	require.True(t, names["otherbucket"])

	// Health on the bare domain.
	req = h.request(http.MethodGet, vhostTestDomain, "/healthz", nil)
	resp, body = h.do(req)
	require.Equal(t, http.StatusOK, resp.StatusCode, body)
	require.Equal(t, "ok", body)

	// Path-style on the bare domain keeps working.
	req = h.request(http.MethodGet, vhostTestDomain, "/photos/dir/a%20b.txt", nil)
	vhostSignHeader(req, vhostTestAccessKey, vhostTestSecret, time.Now().UTC())
	resp, body = h.do(req)
	require.Equal(t, http.StatusOK, resp.StatusCode, body)
	require.Equal(t, "x", body)

	// Path-style on an unknown host keeps working (local SDK setups).
	req = h.request(http.MethodGet, "localhost:9000", "/photos/dir/a%20b.txt", nil)
	vhostSignHeader(req, vhostTestAccessKey, vhostTestSecret, time.Now().UTC())
	resp, body = h.do(req)
	require.Equal(t, http.StatusOK, resp.StatusCode, body)

	// Health on an unknown host keeps the previous behaviour.
	req = h.request(http.MethodGet, "127.0.0.1:9000", "/healthz", nil)
	resp, body = h.do(req)
	require.Equal(t, http.StatusOK, resp.StatusCode, body)
	require.Equal(t, "ok", body)
}

func TestVHostHealthNamedKeyIsObject(t *testing.T) {
	h := newVhostHarness(t, nil)
	h.seedObject("photos", "healthz", "object-health")

	// On the bucket host, /healthz is the object key.
	req := h.request(http.MethodGet, "photos."+vhostTestDomain, "/healthz", nil)
	vhostSignHeader(req, vhostTestAccessKey, vhostTestSecret, time.Now().UTC())
	resp, body := h.do(req)
	require.Equal(t, http.StatusOK, resp.StatusCode, body)
	require.Equal(t, "object-health", body)

	// On the bare domain, /healthz remains the health endpoint.
	req = h.request(http.MethodGet, vhostTestDomain, "/healthz", nil)
	resp, body = h.do(req)
	require.Equal(t, http.StatusOK, resp.StatusCode, body)
	require.Equal(t, "ok", body)
}

// Bucket host "/" is ListObjects, not ListBuckets.
func TestVHostBucketRootListObjects(t *testing.T) {
	h := newVhostHarness(t, nil)
	h.seedObject("photos", "dir/a b.txt", "listed")

	req := h.request(http.MethodGet, "photos."+vhostTestDomain, "/?prefix=dir/", nil)
	vhostSignHeader(req, vhostTestAccessKey, vhostTestSecret, time.Now().UTC())
	resp, body := h.do(req)
	require.Equal(t, http.StatusOK, resp.StatusCode, body)
	var result ListBucketResult
	require.NoError(t, xml.Unmarshal([]byte(body), &result))
	require.Equal(t, "photos", result.Name)
	var keys []string
	for _, c := range result.Contents {
		keys = append(keys, c.Key)
	}
	require.Contains(t, keys, "dir/a b.txt")
}

// ---------------------------------------------------------------------------
// Bucket-root operations: HEAD, DELETE (empty/nonempty), PUT to create
// ---------------------------------------------------------------------------

func TestVHostBucketRootHeadDeleteCreate(t *testing.T) {
	h := newVhostHarness(t, nil)
	h.seedObject("photos", "k.txt", "data")

	// HEAD existing bucket.
	req := h.request(http.MethodHead, "photos."+vhostTestDomain, "/", nil)
	vhostSignHeader(req, vhostTestAccessKey, vhostTestSecret, time.Now().UTC())
	resp, _ := h.do(req)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// DELETE nonempty -> BucketNotEmpty.
	req = h.request(http.MethodDelete, "photos."+vhostTestDomain, "/", nil)
	vhostSignHeader(req, vhostTestAccessKey, vhostTestSecret, time.Now().UTC())
	resp, body := h.do(req)
	require.Equal(t, http.StatusConflict, resp.StatusCode, body)
	require.Contains(t, body, "BucketNotEmpty")

	// DELETE an empty bucket via its host.
	require.NoError(t, h.srv.Buckets.Create(context.Background(), "empty-bucket"))
	req = h.request(http.MethodDelete, "empty-bucket."+vhostTestDomain, "/", nil)
	vhostSignHeader(req, vhostTestAccessKey, vhostTestSecret, time.Now().UTC())
	resp, _ = h.do(req)
	require.Equal(t, http.StatusNoContent, resp.StatusCode)
	exists, err := h.srv.Buckets.Exists(context.Background(), "empty-bucket")
	require.NoError(t, err)
	require.False(t, exists)

	// PUT to a not-yet-existing bucket's host creates it.
	req = h.request(http.MethodPut, "brand-new."+vhostTestDomain, "/", nil)
	vhostSignHeader(req, vhostTestAccessKey, vhostTestSecret, time.Now().UTC())
	resp, _ = h.do(req)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	exists, err = h.srv.Buckets.Exists(context.Background(), "brand-new")
	require.NoError(t, err)
	require.True(t, exists)
}

// ---------------------------------------------------------------------------
// DeleteObjects on the bucket host (POST /?delete)
// ---------------------------------------------------------------------------

func TestVHostDeleteObjects(t *testing.T) {
	h := newVhostHarness(t, nil)
	h.seedObject("photos", "dir/a b.txt", "x")

	xmlBody := []byte(`<Delete><Object><Key>dir/a b.txt</Key></Object></Delete>`)
	req := h.request(http.MethodPost, "photos."+vhostTestDomain, "/?delete", xmlBody)
	req.Header.Set("Content-Type", "application/xml")
	req.Header.Set("X-Amz-Content-Sha256", vhostSHA256(xmlBody))
	vhostSignHeader(req, vhostTestAccessKey, vhostTestSecret, time.Now().UTC())
	resp, bodyStr := h.do(req)
	require.Equal(t, http.StatusOK, resp.StatusCode, bodyStr)

	strg, err := h.srv.Buckets.Get(context.Background(), "photos")
	require.NoError(t, err)
	_, err = strg.Get(context.Background(), "dir/a b.txt")
	require.ErrorIs(t, err, s2.ErrNotExist)
}

// ---------------------------------------------------------------------------
// Multipart lifecycle fully signed on the bucket host
// ---------------------------------------------------------------------------

func TestVHostMultipartLifecycle(t *testing.T) {
	h := newVhostHarness(t, nil)
	require.NoError(t, h.srv.Buckets.Create(context.Background(), "photos"))

	// Initiate.
	req := h.request(http.MethodPost, "photos."+vhostTestDomain, "/big.bin?uploads", nil)
	vhostSignHeader(req, vhostTestAccessKey, vhostTestSecret, time.Now().UTC())
	resp, body := h.do(req)
	require.Equal(t, http.StatusOK, resp.StatusCode, body)
	var initiated InitiateMultipartUploadResult
	require.NoError(t, xml.Unmarshal([]byte(body), &initiated))
	require.Equal(t, "photos", initiated.Bucket)
	uploadID := initiated.UploadID

	// Parts.
	part1 := []byte("part1-")
	req = h.request(http.MethodPut, "photos."+vhostTestDomain, "/big.bin?partNumber=1&uploadId="+uploadID, part1)
	req.Header.Set("X-Amz-Content-Sha256", vhostSHA256(part1))
	vhostSignHeader(req, vhostTestAccessKey, vhostTestSecret, time.Now().UTC())
	resp, _ = h.do(req)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	etag1 := resp.Header.Get("ETag")

	part2 := []byte("part2")
	req = h.request(http.MethodPut, "photos."+vhostTestDomain, "/big.bin?partNumber=2&uploadId="+uploadID, part2)
	req.Header.Set("X-Amz-Content-Sha256", vhostSHA256(part2))
	vhostSignHeader(req, vhostTestAccessKey, vhostTestSecret, time.Now().UTC())
	resp, _ = h.do(req)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	etag2 := resp.Header.Get("ETag")

	// Complete.
	complete := fmt.Sprintf(
		`<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>%s</ETag></Part>`+
			`<Part><PartNumber>2</PartNumber><ETag>%s</ETag></Part></CompleteMultipartUpload>`, etag1, etag2)
	req = h.request(http.MethodPost, "photos."+vhostTestDomain, "/big.bin?uploadId="+uploadID, []byte(complete))
	req.Header.Set("Content-Type", "application/xml")
	req.Header.Set("X-Amz-Content-Sha256", vhostSHA256([]byte(complete)))
	vhostSignHeader(req, vhostTestAccessKey, vhostTestSecret, time.Now().UTC())
	resp, body = h.do(req)
	require.Equal(t, http.StatusOK, resp.StatusCode, body)

	// Assembled object.
	req = h.request(http.MethodGet, "photos."+vhostTestDomain, "/big.bin", nil)
	vhostSignHeader(req, vhostTestAccessKey, vhostTestSecret, time.Now().UTC())
	resp, body = h.do(req)
	require.Equal(t, http.StatusOK, resp.StatusCode, body)
	require.Equal(t, "part1-part2", body)

	// Abort a second upload.
	req = h.request(http.MethodPost, "photos."+vhostTestDomain, "/abort.bin?uploads", nil)
	vhostSignHeader(req, vhostTestAccessKey, vhostTestSecret, time.Now().UTC())
	_, body = h.do(req)
	var aborted InitiateMultipartUploadResult
	require.NoError(t, xml.Unmarshal([]byte(body), &aborted))

	req = h.request(http.MethodDelete, "photos."+vhostTestDomain, "/abort.bin?uploadId="+aborted.UploadID, nil)
	vhostSignHeader(req, vhostTestAccessKey, vhostTestSecret, time.Now().UTC())
	resp, _ = h.do(req)
	require.Equal(t, http.StatusNoContent, resp.StatusCode)
}

// ---------------------------------------------------------------------------
// CopyObject fully signed, source via the copy-source header
// ---------------------------------------------------------------------------

func TestVHostCopyObject(t *testing.T) {
	h := newVhostHarness(t, nil)
	h.seedObject("otherbucket", "src.txt", "copy-source")
	require.NoError(t, h.srv.Buckets.Create(context.Background(), "photos"))

	req := h.request(http.MethodPut, "photos."+vhostTestDomain, "/copied.txt", nil)
	req.Header.Set("X-Amz-Copy-Source", "/otherbucket/src.txt")
	vhostSignHeader(req, vhostTestAccessKey, vhostTestSecret, time.Now().UTC())
	resp, body := h.do(req)
	require.Equal(t, http.StatusOK, resp.StatusCode, body)

	req = h.request(http.MethodGet, "photos."+vhostTestDomain, "/copied.txt", nil)
	vhostSignHeader(req, vhostTestAccessKey, vhostTestSecret, time.Now().UTC())
	resp, body = h.do(req)
	require.Equal(t, http.StatusOK, resp.StatusCode, body)
	require.Equal(t, "copy-source", body)
}

// ---------------------------------------------------------------------------
// Invalid hosts: deterministic 400 XML, CORS still applied
// ---------------------------------------------------------------------------

func TestVHostInvalidHosts(t *testing.T) {
	h := newVhostHarness(t, nil)

	invalidHosts := []string{
		"photos." + vhostTestDomain + ".",          // trailing dot bucket
		"photos." + vhostTestDomain + ".:9000",     // trailing dot with port
		vhostTestDomain + ".",                      // trailing dot root
		"Photos." + vhostTestDomain,                // uppercase
		"ab." + vhostTestDomain,                    // too short
		"my.photos." + vhostTestDomain,             // dotted prefix
		"my_photos." + vhostTestDomain,             // underscore
	}
	for _, host := range invalidHosts {
		req := h.request(http.MethodGet, host, "/dir/a%20b.txt", nil)
		resp, body := h.do(req)
		require.Equal(t, http.StatusBadRequest, resp.StatusCode, "host %q", host)
		require.Contains(t, body, "<Code>InvalidArgument</Code>", "host %q", host)
		// CORS still applies.
		require.Equal(t, "*", resp.Header.Get("Access-Control-Allow-Origin"), "host %q", host)
	}

	// OPTIONS preflight to a bucket host short-circuits unchanged.
	req := h.request(http.MethodOptions, "photos."+vhostTestDomain, "/dir/a%20b.txt", nil)
	resp, _ := h.do(req)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, "*", resp.Header.Get("Access-Control-Allow-Origin"))
}

// ---------------------------------------------------------------------------
// Feature disabled: wire Host is ignored entirely; path-style for all.
// ---------------------------------------------------------------------------

func TestVHostDisabledKeepsPathStyle(t *testing.T) {
	cfg := server.DefaultConfig()
	cfg.Root = t.TempDir()
	// No S3Domain, no auth.
	srv, err := server.NewServer(context.Background(), cfg)
	require.NoError(t, err)
	ts := httptest.NewServer(srv.S3Handler())
	defer ts.Close()

	ctx := context.Background()
	require.NoError(t, srv.Buckets.Create(ctx, "photos"))
	strg, err := srv.Buckets.Get(ctx, "photos")
	require.NoError(t, err)
	require.NoError(t, strg.Put(ctx, s2.NewObjectBytes("dir/a b.txt", []byte("plain"))))

	doHost := func(host, target string) (*http.Response, string) {
		req, err := http.NewRequest(http.MethodGet, ts.URL+target, nil)
		require.NoError(t, err)
		req.Host = host
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		b, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())
		return resp, string(b)
	}

	// Path-style works regardless of the Host.
	resp, body := doHost("photos."+vhostTestDomain, "/photos/dir/a%20b.txt")
	require.Equal(t, http.StatusOK, resp.StatusCode, body)
	require.Equal(t, "plain", body)

	// A virtual-host-shaped path is NOT reinterpreted: first path segment is
	// the bucket ("dir"), which does not exist.
	resp, body = doHost("photos."+vhostTestDomain, "/dir/a%20b.txt")
	require.Equal(t, http.StatusNotFound, resp.StatusCode, body)
	require.Contains(t, body, "NoSuchBucket")
}
