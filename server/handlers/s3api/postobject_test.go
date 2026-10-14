package s3api

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mojatter/s2"
	"github.com/mojatter/s2/server"
	"github.com/stretchr/testify/require"
)

const (
	postTestBucket = "post-bucket"
	postTestAK     = "postkey"
	postTestSK     = "postsecret"
)

// --- test infrastructure ---------------------------------------------------

// newPostServer builds an authenticated osfs server with one bucket and a
// live HTTP listener. mutate may tweak the config before NewServer.
func newPostServer(t *testing.T, mutate func(cfg *server.Config)) (*server.Server, *httptest.Server) {
	t.Helper()
	cfg := server.DefaultConfig()
	cfg.Root = t.TempDir()
	cfg.User = postTestAK
	cfg.Password = postTestSK
	if mutate != nil {
		mutate(cfg)
	}
	srv, err := server.NewServer(context.Background(), cfg)
	require.NoError(t, err)
	require.NoError(t, srv.Buckets.Create(context.Background(), postTestBucket))
	ts := httptest.NewServer(srv.S3Handler())
	// Preserve 303 redirects from success_action_redirect for assertions.
	ts.Client().CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	t.Cleanup(ts.Close)
	return srv, ts
}

// postSigningFields computes the five SigV4 form fields the way an
// application server hands them to the browser: sign the exact base64
// policy with the credential-scope signing key.
func postSigningFields(t *testing.T, accessKey, secretKey, policyB64, amzDate string) map[string]string {
	t.Helper()
	date := amzDate[:8]
	h := func(key []byte, data string) []byte {
		m := hmac.New(sha256.New, key)
		m.Write([]byte(data))
		return m.Sum(nil)
	}
	kDate := h([]byte("AWS4"+secretKey), date)
	kRegion := h(kDate, s2Region)
	kService := h(kRegion, "s3")
	signingKey := h(kService, "aws4_request")
	sig := hex.EncodeToString(h(signingKey, policyB64))
	return map[string]string{
		"x-amz-algorithm": "AWS4-HMAC-SHA256",
		"x-amz-credential": fmt.Sprintf("%s/%s/%s/s3/aws4_request", accessKey, date, s2Region),
		"x-amz-date":       amzDate,
		"policy":           policyB64,
		"x-amz-signature":  sig,
	}
}

// postFormBuilder assembles a multipart/form-data POST body.
type postFormBuilder struct {
	buf bytes.Buffer
	mw  *multipart.Writer
}

func newPostFormBuilder() *postFormBuilder {
	b := &postFormBuilder{}
	b.mw = multipart.NewWriter(&b.buf)
	return b
}

func (b *postFormBuilder) field(name, value string) {
	if err := b.mw.WriteField(name, value); err != nil {
		panic(err)
	}
}

// lastWrittenField duplicates the most recent field by writing it again,
// without a duplicate map key (multipart allows it; the handler must not).
func (b *postFormBuilder) fieldRaw(name, value string) {
	if err := b.mw.WriteField(name, value); err != nil {
		panic(err)
	}
}

func (b *postFormBuilder) sign(t *testing.T, policyB64, amzDate, ak, sk string) {
	t.Helper()
	for name, value := range postSigningFields(t, ak, sk, policyB64, amzDate) {
		b.field(name, value)
	}
}

// signWith writes the supplied signing fields verbatim (for malformed cases).
func (b *postFormBuilder) signWith(fields map[string]string) {
	for name, value := range fields {
		b.field(name, value)
	}
}

func (b *postFormBuilder) file(filename, contentType string, content []byte) {
	h := make(textproto.MIMEHeader)
	h.Set("Content-Disposition", fmt.Sprintf(`form-data; name="%s"; filename="%s"`, fileFieldName, filename))
	if contentType != "" {
		h.Set("Content-Type", contentType)
	}
	w, err := b.mw.CreatePart(h)
	if err != nil {
		panic(err)
	}
	if _, err := w.Write(content); err != nil {
		panic(err)
	}
}

// fieldAfterFile writes another field after the file; the handler must
// reject it because the file part has to be the form's last field.
func (b *postFormBuilder) fieldAfterFile(name, value string) {
	b.fieldRaw(name, value)
}

func (b *postFormBuilder) finish() ([]byte, string) {
	if err := b.mw.Close(); err != nil {
		panic(err)
	}
	return b.buf.Bytes(), b.mw.FormDataContentType()
}

// postPolicy builds and base64-encodes a policy document.
func postPolicy(t *testing.T, expiration time.Time, conditions []any) string {
	t.Helper()
	doc := map[string]any{
		"expiration": expiration.Format(time.RFC3339),
		"conditions": conditions,
	}
	data, err := json.Marshal(doc)
	require.NoError(t, err)
	return base64.StdEncoding.EncodeToString(data)
}

// postDo sends the form and returns the finished response.
func postDo(t *testing.T, ts *httptest.Server, target, contentType string, body []byte) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, ts.URL+target, bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", contentType)
	resp, err := ts.Client().Do(req)
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func readResp(t *testing.T, resp *http.Response) string {
	t.Helper()
	data, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return string(data)
}

func s3ErrorBody(t *testing.T, resp *http.Response) (code, message string) {
	var doc struct {
		Code    string `xml:"Code"`
		Message string `xml:"Message"`
	}
	require.NoError(t, xml.Unmarshal([]byte(readResp(t, resp)), &doc))
	return doc.Code, doc.Message
}

// getObjectViaAPI GETs an object with a header SigV4 signature and returns
// its status, body, Content-Type and full headers.
func getObjectViaAPI(t *testing.T, ts *httptest.Server, bucket, key string) (status int, body, contentType string, headers http.Header) {
	t.Helper()
	segments := strings.Split(key, "/")
	for i, seg := range segments {
		segments[i] = url.PathEscape(seg)
	}
	u := ts.URL + "/" + bucket + "/" + strings.Join(segments, "/")
	req, err := http.NewRequest(http.MethodGet, u, nil)
	require.NoError(t, err)
	signS3Get(t, req, postTestAK, postTestSK)
	resp, err := ts.Client().Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, string(data), resp.Header.Get("Content-Type"), resp.Header
}

// signS3Get adds a minimal header SigV4 signature (signed host header) to a
// GET request.
func signS3Get(t *testing.T, req *http.Request, accessKey, secretKey string) {
	t.Helper()
	now := time.Now().UTC()
	amzDate := now.Format("20060102T150405Z")
	date := now.Format("20060102")
	scope := fmt.Sprintf("%s/%s/s3/aws4_request", date, s2Region)
	// r.URL.Path is the decoded path; the server's canonicalizer re-encodes
	// each segment itself.
	segments := strings.Split(req.URL.Path, "/")
	for i, seg := range segments {
		segments[i] = awsURIEncodeForTest(seg)
	}
	canonPath := strings.Join(segments, "/")
	canonReq := "GET\n" + canonPath + "\n\n" +
		"host:" + req.URL.Host + "\n\n" +
		"host\n" + emptySHA256
	h := func(key []byte, data string) []byte {
		m := hmac.New(sha256.New, key)
		m.Write([]byte(data))
		return m.Sum(nil)
	}
	canonHash := sha256.Sum256([]byte(canonReq))
	stringToSign := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + hex.EncodeToString(canonHash[:])
	kDate := h([]byte("AWS4"+secretKey), date)
	kRegion := h(kDate, s2Region)
	kService := h(kRegion, "s3")
	signingKey := h(kService, "aws4_request")
	sig := hex.EncodeToString(h(signingKey, stringToSign))
	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("Authorization", fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=host, Signature=%s", accessKey, scope, sig))
}

// awsURIEncodeForTest mirrors the server's SigV4 path encoding for the test
// signer.
func awsURIEncodeForTest(s string) string {
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

// emptySHA256 is the hex SHA-256 of the empty string (an unsigned GET body).
const emptySHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// --- happy paths ------------------------------------------------------------

func TestPostObjectSuccess(t *testing.T) {
	srv, ts := newPostServer(t, nil)
	now := time.Now().UTC()
	content := []byte("hello post world")

	t.Run("default 204 stores body, type and metadata", func(t *testing.T) {
		key := "default/object.txt"
		conds := []any{
			map[string]string{"bucket": postTestBucket},
			[]string{"eq", "$key", key},
			[]string{"eq", "$Content-Type", "text/plain"},
			[]string{"eq", "$x-amz-meta-author", "alice"},
			[]any{"content-length-range", 1, 1024},
		}
		b := newPostFormBuilder()
		b.field("key", key)
		b.field("Content-Type", "text/plain")
		b.field("x-amz-meta-author", "alice")
		b.sign(t, postPolicy(t, now.Add(time.Hour), conds), now.Format("20060102T150405Z"), postTestAK, postTestSK)
		b.file("object.txt", "text/plain", content)
		body, ct := b.finish()

		resp := postDo(t, ts, "/"+postTestBucket, ct, body)
		require.Equal(t, http.StatusNoContent, resp.StatusCode, readResp(t, resp))
		require.NotEmpty(t, resp.Header.Get("ETag"))

		status, got, gotCT, gotHeaders := getObjectViaAPI(t, ts, postTestBucket, key)
		require.Equal(t, http.StatusOK, status)
		require.Equal(t, string(content), got)
		require.Equal(t, "text/plain", gotCT)
		require.Equal(t, "alice", gotHeaders.Get("X-Amz-Meta-Author"))
	})

	t.Run("success_action_status 201 returns PostResponse", func(t *testing.T) {
		key := "created/photo.png"
		conds := []any{
			map[string]string{"bucket": postTestBucket},
			[]string{"starts-with", "$key", "created/"},
			[]string{"starts-with", "$Content-Type", "image/"},
			[]any{"content-length-range", 1, 1024},
		}
		b := newPostFormBuilder()
		b.field("key", key)
		b.field("Content-Type", "image/png")
		b.field("success_action_status", "201")
		b.sign(t, postPolicy(t, now.Add(time.Hour), conds), now.Format("20060102T150405Z"), postTestAK, postTestSK)
		b.file("photo.png", "image/png", content)
		body, ct := b.finish()

		resp := postDo(t, ts, "/"+postTestBucket, ct, body)
		require.Equal(t, http.StatusCreated, resp.StatusCode)
		var pr PostResponse
		require.NoError(t, xml.Unmarshal([]byte(readResp(t, resp)), &pr))
		require.Equal(t, postTestBucket, pr.Bucket)
		require.Equal(t, key, pr.Key)
		require.NotEmpty(t, pr.ETag)
		require.Equal(t, ts.URL+"/"+postTestBucket+"/created/photo.png", pr.Location)
	})

	t.Run("success_action_status 200 and 204", func(t *testing.T) {
		for _, status := range []string{"200", "204"} {
			key := "status/" + status + ".bin"
			conds := []any{
				map[string]string{"bucket": postTestBucket},
				[]string{"eq", "$key", key},
				[]any{"content-length-range", 1, 1024},
			}
			b := newPostFormBuilder()
			b.field("key", key)
			b.field("success_action_status", status)
			b.sign(t, postPolicy(t, now.Add(time.Hour), conds), now.Format("20060102T150405Z"), postTestAK, postTestSK)
			b.file("f.bin", "application/octet-stream", content)
			body, ct := b.finish()

			resp := postDo(t, ts, "/"+postTestBucket, ct, body)
			require.Equal(t, map[string]int{"200": http.StatusOK, "204": http.StatusNoContent}[status], resp.StatusCode)
			require.Empty(t, readResp(t, resp))
		}
	})

	t.Run("success_action_redirect 303 with ${filename} substitution", func(t *testing.T) {
		key := "dl/${filename}"
		redirect := "https://example.com/done?name=${filename}&x=1"
		conds := []any{
			map[string]string{"bucket": postTestBucket},
			[]string{"starts-with", "$key", "dl/"},
			[]any{"content-length-range", 1, 1024},
		}
		b := newPostFormBuilder()
		b.field("key", key)
		b.field("success_action_redirect", redirect)
		b.sign(t, postPolicy(t, now.Add(time.Hour), conds), now.Format("20060102T150405Z"), postTestAK, postTestSK)
		b.file("report 1.pdf", "application/pdf", content)
		body, ct := b.finish()

		resp := postDo(t, ts, "/"+postTestBucket, ct, body)
		require.Equal(t, http.StatusSeeOther, resp.StatusCode)
		loc, err := url.Parse(resp.Header.Get("Location"))
		require.NoError(t, err)
		require.Equal(t, "https", loc.Scheme)
		require.Equal(t, "example.com", loc.Host)
		require.Equal(t, "report 1.pdf", loc.Query().Get("name"))
		require.Equal(t, "1", loc.Query().Get("x"))
		require.Equal(t, postTestBucket, loc.Query().Get("bucket"))
		require.Equal(t, "dl/report 1.pdf", loc.Query().Get("key"))
		require.True(t, strings.HasPrefix(loc.Query().Get("etag"), `"`))

		status, got, _, _ := getObjectViaAPI(t, ts, postTestBucket, "dl/report 1.pdf")
		require.Equal(t, http.StatusOK, status)
		require.Equal(t, string(content), got)
	})

	t.Run("${filename} expansion and trailing-slash bucket URL", func(t *testing.T) {
		conds := []any{
			map[string]string{"bucket": postTestBucket},
			[]string{"starts-with", "$key", "up/"},
			[]any{"content-length-range", 1, 1024},
		}
		b := newPostFormBuilder()
		b.field("key", "up/${filename}")
		b.sign(t, postPolicy(t, now.Add(time.Hour), conds), now.Format("20060102T150405Z"), postTestAK, postTestSK)
		b.file("a b.png", "image/png", content)
		body, ct := b.finish()

		resp := postDo(t, ts, "/"+postTestBucket+"/", ct, body)
		require.Equal(t, http.StatusNoContent, resp.StatusCode, readResp(t, resp))
		status, got, _, _ := getObjectViaAPI(t, ts, postTestBucket, "up/a b.png")
		require.Equal(t, http.StatusOK, status)
		require.Equal(t, string(content), got)
	})

	t.Run("no Content-Type field is left unstored", func(t *testing.T) {
		key := "noct/file.bin"
		conds := []any{
			map[string]string{"bucket": postTestBucket},
			[]string{"eq", "$key", key},
			[]any{"content-length-range", 1, 1024},
		}
		b := newPostFormBuilder()
		b.field("key", key)
		b.sign(t, postPolicy(t, now.Add(time.Hour), conds), now.Format("20060102T150405Z"), postTestAK, postTestSK)
		b.file("file.bin", "application/octet-stream", content)
		body, ct := b.finish()

		resp := postDo(t, ts, "/"+postTestBucket, ct, body)
		require.Equal(t, http.StatusNoContent, resp.StatusCode, readResp(t, resp))

		// Nothing is stored as Content-Type; readers resolve it. Verify the
		// sidecar rather than the HTTP header, whose resolution varies with
		// the host's MIME database.
		strg, err := srv.Buckets.Get(context.Background(), postTestBucket)
		require.NoError(t, err)
		obj, err := strg.Get(context.Background(), key)
		require.NoError(t, err)
		require.Empty(t, obj.ContentType())
		_, _, gotCT, _ := getObjectViaAPI(t, ts, postTestBucket, key)
		require.Equal(t, server.ResolveContentType(obj, key), gotCT)
	})

	t.Run("file size counts the file, not the whole multipart body", func(t *testing.T) {
		key := "exact/sized.bin"
		fileContent := bytes.Repeat([]byte("z"), 321)
		conds := []any{
			map[string]string{"bucket": postTestBucket},
			[]string{"eq", "$key", key},
			[]any{"content-length-range", json.Number("321"), json.Number("321")},
		}
		b := newPostFormBuilder()
		b.field("key", key)
		b.sign(t, postPolicy(t, now.Add(time.Hour), conds), now.Format("20060102T150405Z"), postTestAK, postTestSK)
		b.file("sized.bin", "application/octet-stream", fileContent)
		body, ct := b.finish()
		require.Greater(t, len(body), len(fileContent)) // framing/fields add bytes

		resp := postDo(t, ts, "/"+postTestBucket, ct, body)
		require.Equal(t, http.StatusNoContent, resp.StatusCode, readResp(t, resp))
	})
}

// --- signature and identity -------------------------------------------------

func TestPostObjectSignature(t *testing.T) {
	_, ts := newPostServer(t, nil)
	now := time.Now().UTC()
	amzDate := now.Format("20060102T150405Z")
	content := []byte("data")
	key := "sig/k"
	conds := []any{
		map[string]string{"bucket": postTestBucket},
		[]string{"eq", "$key", key},
		[]any{"content-length-range", 1, 1024},
	}

	build := func(t *testing.T, mutateFields func(map[string]string), expiration time.Time) ([]byte, string) {
		pb := postPolicy(t, expiration, conds)
		fields := postSigningFields(t, postTestAK, postTestSK, pb, amzDate)
		if mutateFields != nil {
			mutateFields(fields)
		}
		b := newPostFormBuilder()
		b.field("key", key)
		b.signWith(fields)
		b.file("k", "application/octet-stream", content)
		return b.finish()
	}

	// wrong secret
	t.Run("wrong secret", func(t *testing.T) {
		pb := postPolicy(t, now.Add(time.Hour), conds)
		fields := postSigningFields(t, postTestAK, "wrong-secret", pb, amzDate)
		b := newPostFormBuilder()
		b.field("key", key)
		b.signWith(fields)
		b.file("k", "application/octet-stream", content)
		body, ct := b.finish()
		resp := postDo(t, ts, "/"+postTestBucket, ct, body)
		require.Equal(t, http.StatusForbidden, resp.StatusCode)
		code, _ := s3ErrorBody(t, resp)
		require.Equal(t, "SignatureDoesNotMatch", code)
	})

	// tampered policy after signing
	t.Run("tampered policy", func(t *testing.T) {
		body, ct := build(t, func(f map[string]string) {
			f["policy"] = base64.StdEncoding.EncodeToString([]byte(`{"expiration":"` + now.Add(time.Hour).Format(time.RFC3339) + `","conditions":[{"bucket":"other"}]}`))
		}, now.Add(time.Hour))
		resp := postDo(t, ts, "/"+postTestBucket, ct, body)
		require.Equal(t, http.StatusForbidden, resp.StatusCode)
		code, _ := s3ErrorBody(t, resp)
		require.Equal(t, "SignatureDoesNotMatch", code)
	})

	t.Run("unknown access key", func(t *testing.T) {
		pb := postPolicy(t, now.Add(time.Hour), conds)
		fields := postSigningFields(t, "ghost", postTestSK, pb, amzDate)
		b := newPostFormBuilder()
		b.field("key", key)
		b.signWith(fields)
		b.file("k", "application/octet-stream", content)
		body, ct := b.finish()
		resp := postDo(t, ts, "/"+postTestBucket, ct, body)
		require.Equal(t, http.StatusForbidden, resp.StatusCode)
		code, _ := s3ErrorBody(t, resp)
		require.Equal(t, "SignatureDoesNotMatch", code)
	})

	t.Run("credential date differs from x-amz-date", func(t *testing.T) {
		pb := postPolicy(t, now.Add(time.Hour), conds)
		fields := postSigningFields(t, postTestAK, postTestSK, pb, amzDate)
		fields["x-amz-credential"] = fmt.Sprintf("%s/%s/%s/s3/aws4_request", postTestAK, now.AddDate(0, 0, -1).Format("20060102"), s2Region)
		b := newPostFormBuilder()
		b.field("key", key)
		b.signWith(fields)
		b.file("k", "application/octet-stream", content)
		body, ct := b.finish()
		resp := postDo(t, ts, "/"+postTestBucket, ct, body)
		require.Equal(t, http.StatusForbidden, resp.StatusCode)
		code, _ := s3ErrorBody(t, resp)
		require.Equal(t, "SignatureDoesNotMatch", code)
	})

	t.Run("malformed x-amz-date", func(t *testing.T) {
		pb := postPolicy(t, now.Add(time.Hour), conds)
		fields := postSigningFields(t, postTestAK, postTestSK, pb, amzDate)
		fields["x-amz-date"] = "yesterday"
		b := newPostFormBuilder()
		b.field("key", key)
		b.signWith(fields)
		b.file("k", "application/octet-stream", content)
		body, ct := b.finish()
		resp := postDo(t, ts, "/"+postTestBucket, ct, body)
		require.Equal(t, http.StatusForbidden, resp.StatusCode)
		code, _ := s3ErrorBody(t, resp)
		require.Equal(t, "SignatureDoesNotMatch", code)
	})

	t.Run("expired policy", func(t *testing.T) {
		body, ct := build(t, nil, now.Add(-time.Minute))
		resp := postDo(t, ts, "/"+postTestBucket, ct, body)
		require.Equal(t, http.StatusForbidden, resp.StatusCode)
		code, msg := s3ErrorBody(t, resp)
		require.Equal(t, "AccessDenied", code)
		require.Contains(t, msg, "Policy expired")
	})

	t.Run("missing policy", func(t *testing.T) {
		b := newPostFormBuilder()
		b.field("key", key)
		b.signWith(map[string]string{
			"x-amz-algorithm":  "AWS4-HMAC-SHA256",
			"x-amz-credential": fmt.Sprintf("%s/%s/%s/s3/aws4_request", postTestAK, amzDate[:8], s2Region),
			"x-amz-date":       amzDate,
			"x-amz-signature":  strings.Repeat("0", 64),
		})
		b.file("k", "application/octet-stream", content)
		body, ct := b.finish()
		resp := postDo(t, ts, "/"+postTestBucket, ct, body)
		require.Equal(t, http.StatusForbidden, resp.StatusCode)
		code, _ := s3ErrorBody(t, resp)
		require.Equal(t, "AccessDenied", code)
	})

	t.Run("malformed base64 policy", func(t *testing.T) {
		b := newPostFormBuilder()
		b.field("key", key)
		b.field("policy", "%%%not-base64")
		b.signWith(map[string]string{
			"x-amz-algorithm":  "AWS4-HMAC-SHA256",
			"x-amz-credential": fmt.Sprintf("%s/%s/%s/s3/aws4_request", postTestAK, amzDate[:8], s2Region),
			"x-amz-date":       amzDate,
			"x-amz-signature":  strings.Repeat("0", 64),
		})
		b.file("k", "application/octet-stream", content)
		body, ct := b.finish()
		resp := postDo(t, ts, "/"+postTestBucket, ct, body)
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
		code, _ := s3ErrorBody(t, resp)
		require.Equal(t, "InvalidArgument", code)
	})

	t.Run("not multipart/form-data keeps SigV4 behavior", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, ts.URL+"/"+postTestBucket, strings.NewReader("{}"))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")
		resp, err := ts.Client().Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		require.Equal(t, http.StatusForbidden, resp.StatusCode) // missing Authorization header
	})
}

// --- policy conditions ------------------------------------------------------

func TestPostObjectPolicyConditions(t *testing.T) {
	_, ts := newPostServer(t, nil)
	now := time.Now().UTC().Add(time.Hour)
	amzDate := time.Now().UTC().Format("20060102T150405Z")
	content := []byte("condition-body")

	type formField struct{ name, value string }

	build := func(t *testing.T, conds []any, fields []formField, keyField, filename string) ([]byte, string) {
		pb := postPolicy(t, now, conds)
		sf := postSigningFields(t, postTestAK, postTestSK, pb, amzDate)
		b := newPostFormBuilder()
		b.field("key", keyField)
		for _, f := range fields {
			b.field(f.name, f.value)
		}
		b.signWith(sf)
		b.file(filename, "application/octet-stream", content)
		return b.finish()
	}

	baseConds := func(extra ...any) []any {
		return append([]any{
			map[string]string{"bucket": postTestBucket},
			[]string{"eq", "$key", "k"},
			[]any{"content-length-range", 1, 1024},
		}, extra...)
	}

	t.Run("bucket mismatch denied", func(t *testing.T) {
		conds := []any{
			map[string]string{"bucket": "some-other-bucket"},
			[]string{"eq", "$key", "k"},
			[]any{"content-length-range", 1, 1024},
		}
		body, ct := build(t, conds, nil, "k", "f")
		resp := postDo(t, ts, "/"+postTestBucket, ct, body)
		require.Equal(t, http.StatusForbidden, resp.StatusCode)
		code, _ := s3ErrorBody(t, resp)
		require.Equal(t, "AccessDenied", code)
	})

	t.Run("missing bucket condition invalid", func(t *testing.T) {
		conds := []any{
			[]string{"eq", "$key", "k"},
			[]any{"content-length-range", 1, 1024},
		}
		body, ct := build(t, conds, nil, "k", "f")
		resp := postDo(t, ts, "/"+postTestBucket, ct, body)
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
		code, _ := s3ErrorBody(t, resp)
		require.Equal(t, "InvalidArgument", code)
	})

	t.Run("exact key mismatch denied", func(t *testing.T) {
		body, ct := build(t, baseConds(), nil, "different", "f")
		resp := postDo(t, ts, "/"+postTestBucket, ct, body)
		require.Equal(t, http.StatusForbidden, resp.StatusCode)
		code, _ := s3ErrorBody(t, resp)
		require.Equal(t, "AccessDenied", code)
	})

	t.Run("content type exact and starts-with", func(t *testing.T) {
		conds := baseConds([]string{"eq", "$Content-Type", "image/png"})
		body, ct := build(t, conds, []formField{{"Content-Type", "image/png"}}, "k", "f")
		resp := postDo(t, ts, "/"+postTestBucket, ct, body)
		require.Equal(t, http.StatusNoContent, resp.StatusCode, readResp(t, resp))

		conds = baseConds([]string{"starts-with", "$Content-Type", "image/"})
		body, ct = build(t, conds, []formField{{"Content-Type", "text/plain"}}, "k", "f")
		resp = postDo(t, ts, "/"+postTestBucket, ct, body)
		require.Equal(t, http.StatusForbidden, resp.StatusCode)
		code, _ := s3ErrorBody(t, resp)
		require.Equal(t, "AccessDenied", code)
	})

	t.Run("condition for missing field denied", func(t *testing.T) {
		conds := baseConds([]string{"eq", "$x-amz-meta-team", "infra"})
		body, ct := build(t, conds, nil, "k", "f")
		resp := postDo(t, ts, "/"+postTestBucket, ct, body)
		require.Equal(t, http.StatusForbidden, resp.StatusCode)
		code, _ := s3ErrorBody(t, resp)
		require.Equal(t, "AccessDenied", code)
	})

	t.Run("metadata exact match stored", func(t *testing.T) {
		conds := baseConds(
			[]string{"eq", "$x-amz-meta-team", "infra"},
			[]string{"starts-with", "$x-amz-meta-tag", "release-"},
		)
		body, ct := build(t, conds, []formField{
			{"x-amz-meta-team", "infra"},
			{"x-amz-meta-tag", "release-2026"},
		}, "k", "f")
		resp := postDo(t, ts, "/"+postTestBucket, ct, body)
		require.Equal(t, http.StatusNoContent, resp.StatusCode, readResp(t, resp))
		_, _, _, h := getObjectViaAPI(t, ts, postTestBucket, "k")
		require.Equal(t, "infra", h.Get("X-Amz-Meta-Team"))
		require.Equal(t, "release-2026", h.Get("X-Amz-Meta-Tag"))
	})

	t.Run("unconstrained extra field denied", func(t *testing.T) {
		body, ct := build(t, baseConds(), []formField{{"x-amz-meta-team", "rogue"}}, "k", "f")
		resp := postDo(t, ts, "/"+postTestBucket, ct, body)
		require.Equal(t, http.StatusForbidden, resp.StatusCode)
		code, msg := s3ErrorBody(t, resp)
		require.Equal(t, "AccessDenied", code)
		require.Contains(t, msg, "x-amz-meta-team")
	})

	t.Run("unsupported condition field invalid", func(t *testing.T) {
		conds := baseConds([]string{"eq", "$acl", "private"})
		body, ct := build(t, conds, []formField{{"acl", "private"}}, "k", "f")
		resp := postDo(t, ts, "/"+postTestBucket, ct, body)
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
		code, _ := s3ErrorBody(t, resp)
		require.Equal(t, "InvalidArgument", code)
	})

	t.Run("unsupported operator invalid", func(t *testing.T) {
		conds := baseConds([]string{"less-than", "$x-amz-meta-n", "5"})
		body, ct := build(t, conds, []formField{{"x-amz-meta-n", "1"}}, "k", "f")
		resp := postDo(t, ts, "/"+postTestBucket, ct, body)
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
		code, _ := s3ErrorBody(t, resp)
		require.Equal(t, "InvalidArgument", code)
	})

	t.Run("contradictory content-length-range denied", func(t *testing.T) {
		conds := baseConds(
			[]any{"content-length-range", json.Number("100"), json.Number("200")},
			[]any{"content-length-range", json.Number("300"), json.Number("400")},
		)
		body, ct := build(t, conds, nil, "k", "f")
		resp := postDo(t, ts, "/"+postTestBucket, ct, body)
		require.Equal(t, http.StatusForbidden, resp.StatusCode)
		code, _ := s3ErrorBody(t, resp)
		require.Equal(t, "AccessDenied", code)
	})

	t.Run("malformed range invalid", func(t *testing.T) {
		conds := []any{
			map[string]string{"bucket": postTestBucket},
			[]string{"eq", "$key", "k"},
			[]any{"content-length-range", json.Number("500"), json.Number("100")},
		}
		body, ct := build(t, conds, nil, "k", "f")
		resp := postDo(t, ts, "/"+postTestBucket, ct, body)
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
		code, _ := s3ErrorBody(t, resp)
		require.Equal(t, "InvalidArgument", code)
	})
}

// --- size limits ------------------------------------------------------------

func TestPostObjectSizeLimits(t *testing.T) {
	t.Run("policy max enforced", func(t *testing.T) {
		_, ts := newPostServer(t, nil)
		amzDate := time.Now().UTC().Format("20060102T150405Z")
		exp := time.Now().UTC().Add(time.Hour)
		content := bytes.Repeat([]byte("a"), 50)
		key := "lim/max"
		conds := []any{
			map[string]string{"bucket": postTestBucket},
			[]string{"eq", "$key", key},
			[]any{"content-length-range", json.Number("1"), json.Number("10")},
		}
		b := newPostFormBuilder()
		b.field("key", key)
		b.sign(t, postPolicy(t, exp, conds), amzDate, postTestAK, postTestSK)
		b.file("f", "application/octet-stream", content)
		body, ct := b.finish()
		resp := postDo(t, ts, "/"+postTestBucket, ct, body)
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
		code, _ := s3ErrorBody(t, resp)
		require.Equal(t, "EntityTooLarge", code)
	})

	t.Run("policy min enforced", func(t *testing.T) {
		_, ts := newPostServer(t, nil)
		amzDate := time.Now().UTC().Format("20060102T150405Z")
		exp := time.Now().UTC().Add(time.Hour)
		content := []byte("tiny")
		key := "lim/min"
		conds := []any{
			map[string]string{"bucket": postTestBucket},
			[]string{"eq", "$key", key},
			[]any{"content-length-range", json.Number("100"), json.Number("1000")},
		}
		b := newPostFormBuilder()
		b.field("key", key)
		b.sign(t, postPolicy(t, exp, conds), amzDate, postTestAK, postTestSK)
		b.file("f", "application/octet-stream", content)
		body, ct := b.finish()
		resp := postDo(t, ts, "/"+postTestBucket, ct, body)
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
		code, _ := s3ErrorBody(t, resp)
		require.Equal(t, "EntityTooSmall", code)
	})

	t.Run("server upload limit enforced even without policy range", func(t *testing.T) {
		_, ts := newPostServer(t, func(cfg *server.Config) { cfg.MaxUploadSize = 32 })
		amzDate := time.Now().UTC().Format("20060102T150405Z")
		exp := time.Now().UTC().Add(time.Hour)
		content := bytes.Repeat([]byte("a"), 64)
		key := "lim/server"
		conds := []any{
			map[string]string{"bucket": postTestBucket},
			[]string{"eq", "$key", key},
		}
		b := newPostFormBuilder()
		b.field("key", key)
		b.sign(t, postPolicy(t, exp, conds), amzDate, postTestAK, postTestSK)
		b.file("f", "application/octet-stream", content)
		body, ct := b.finish()
		resp := postDo(t, ts, "/"+postTestBucket, ct, body)
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
		code, _ := s3ErrorBody(t, resp)
		require.Equal(t, "EntityTooLarge", code)
	})
}

// --- malformed forms --------------------------------------------------------

func TestPostObjectMalformedForm(t *testing.T) {
	_, ts := newPostServer(t, nil)
	amzDate := time.Now().UTC().Format("20060102T150405Z")
	exp := time.Now().UTC().Add(time.Hour)
	conds := []any{
		map[string]string{"bucket": postTestBucket},
		[]string{"starts-with", "$key", "f/"},
		[]any{"content-length-range", 1, 1024},
	}
	pb := postPolicy(t, exp, conds)
	signed := postSigningFields(t, postTestAK, postTestSK, pb, amzDate)

	t.Run("missing key", func(t *testing.T) {
		b := newPostFormBuilder()
		b.signWith(signed)
		b.file("f.bin", "application/octet-stream", []byte("x"))
		body, ct := b.finish()
		resp := postDo(t, ts, "/"+postTestBucket, ct, body)
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
		code, _ := s3ErrorBody(t, resp)
		require.Equal(t, "InvalidArgument", code)
	})

	t.Run("missing file", func(t *testing.T) {
		b := newPostFormBuilder()
		b.field("key", "f/x")
		b.signWith(signed)
		body, ct := b.finish()
		resp := postDo(t, ts, "/"+postTestBucket, ct, body)
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
		code, _ := s3ErrorBody(t, resp)
		require.Equal(t, "InvalidArgument", code)
	})

	t.Run("duplicate field rejected", func(t *testing.T) {
		b := newPostFormBuilder()
		b.field("key", "f/x")
		b.fieldRaw("key", "f/y")
		b.signWith(signed)
		b.file("x", "application/octet-stream", []byte("x"))
		body, ct := b.finish()
		resp := postDo(t, ts, "/"+postTestBucket, ct, body)
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
		code, msg := s3ErrorBody(t, resp)
		require.Equal(t, "InvalidArgument", code)
		require.Contains(t, msg, "Duplicate")
	})

	t.Run("field after file rejected", func(t *testing.T) {
		b := newPostFormBuilder()
		b.field("key", "f/x")
		b.signWith(signed)
		b.file("x", "application/octet-stream", []byte("x"))
		b.fieldAfterFile("x-amz-meta-late", "1")
		body, ct := b.finish()
		resp := postDo(t, ts, "/"+postTestBucket, ct, body)
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
		code, _ := s3ErrorBody(t, resp)
		require.Equal(t, "InvalidArgument", code)
	})

	t.Run("invalid success_action_status", func(t *testing.T) {
		b := newPostFormBuilder()
		b.field("key", "f/x")
		b.field("success_action_status", "418")
		b.signWith(signed)
		b.file("x", "application/octet-stream", []byte("x"))
		body, ct := b.finish()
		resp := postDo(t, ts, "/"+postTestBucket, ct, body)
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
		code, _ := s3ErrorBody(t, resp)
		require.Equal(t, "InvalidArgument", code)
	})

	t.Run("invalid redirect URL", func(t *testing.T) {
		b := newPostFormBuilder()
		b.field("key", "f/x")
		b.field("success_action_redirect", "/relative/path")
		b.signWith(signed)
		b.file("x", "application/octet-stream", []byte("x"))
		body, ct := b.finish()
		resp := postDo(t, ts, "/"+postTestBucket, ct, body)
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
		code, _ := s3ErrorBody(t, resp)
		require.Equal(t, "InvalidArgument", code)
	})

	t.Run("invalid key rejected before policy evaluation", func(t *testing.T) {
		b := newPostFormBuilder()
		b.field("key", "../escape.txt")
		b.signWith(signed)
		b.file("x", "text/plain", []byte("x"))
		body, ct := b.finish()
		resp := postDo(t, ts, "/"+postTestBucket, ct, body)
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
		code, _ := s3ErrorBody(t, resp)
		require.Equal(t, "InvalidArgument", code)
	})

	t.Run("truncated stream is incomplete", func(t *testing.T) {
		fileContent := bytes.Repeat([]byte("x"), 4000)
		b := newPostFormBuilder()
		b.field("key", "f/x")
		b.signWith(signed)
		b.file("x", "application/octet-stream", fileContent)
		full, ct := b.finish()
		// Cut deterministically inside the file part, well past every text
		// field but before the file's closing boundary.
		marker := bytes.Repeat([]byte("x"), 200)
		fileStart := bytes.Index(full, marker)
		require.Greater(t, fileStart, 0)
		cut := fileStart + 100
		req, err := http.NewRequest(http.MethodPost, ts.URL+"/"+postTestBucket, bytes.NewReader(full[:cut]))
		require.NoError(t, err)
		req.Header.Set("Content-Type", ct)
		resp, err := ts.Client().Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
		code, _ := s3ErrorBody(t, resp)
		require.Equal(t, "IncompleteBody", code)
	})

	t.Run("no such bucket", func(t *testing.T) {
		ghostConds := []any{
			map[string]string{"bucket": "ghost-bucket"},
			[]string{"eq", "$key", "f/x"},
			[]any{"content-length-range", json.Number("1"), json.Number("1024")},
		}
		ghostSigned := postSigningFields(t, postTestAK, postTestSK, postPolicy(t, time.Now().UTC().Add(time.Hour), ghostConds), amzDate)
		b := newPostFormBuilder()
		b.field("key", "f/x")
		b.signWith(ghostSigned)
		b.file("x", "application/octet-stream", []byte("x"))
		body, ct := b.finish()
		resp := postDo(t, ts, "/ghost-bucket", ct, body)
		require.Equal(t, http.StatusNotFound, resp.StatusCode)
		code, _ := s3ErrorBody(t, resp)
		require.Equal(t, "NoSuchBucket", code)
	})
}

// --- failure atomicity: old object and temp cleanup -------------------------

func TestPostObjectFailureKeepsOldObject(t *testing.T) {
	srv, ts := newPostServer(t, nil)
	ctx := context.Background()
	strg, err := srv.Buckets.Get(ctx, postTestBucket)
	require.NoError(t, err)

	const key = "atomic/key.txt"
	original := []byte("ORIGINAL-BODY")
	require.NoError(t, strg.Put(ctx, s2.NewObjectBytes(key, original,
		s2.WithContentType("text/original"), s2.WithMetadata(s2.Metadata{"author": "original"}))))

	amzDate := time.Now().UTC().Format("20060102T150405Z")
	exp := time.Now().UTC().Add(time.Hour)

	submit := func(t *testing.T, conds []any, content []byte, sign func(map[string]string), mutateBody func([]byte, string) ([]byte, string)) {
		pb := postPolicy(t, exp, conds)
		fields := postSigningFields(t, postTestAK, postTestSK, pb, amzDate)
		if sign != nil {
			sign(fields)
		}
		b := newPostFormBuilder()
		b.field("key", key)
		b.signWith(fields)
		b.file("key.txt", "text/new", content)
		body, ct := b.finish()
		if mutateBody != nil {
			body, ct = mutateBody(body, ct)
		}
		resp := postDo(t, ts, "/"+postTestBucket, ct, body)
		require.NotEqual(t, http.StatusNoContent, resp.StatusCode)
		require.NotEqual(t, http.StatusCreated, resp.StatusCode)
	}

	rangeConds := []any{
		map[string]string{"bucket": postTestBucket},
		[]string{"eq", "$key", key},
		[]any{"content-length-range", json.Number("1"), json.Number("10")},
	}

	t.Run("oversized upload", func(t *testing.T) {
		submit(t, rangeConds, bytes.Repeat([]byte("n"), 50), nil, nil)
	})
	t.Run("undersized upload", func(t *testing.T) {
		minConds := []any{
			map[string]string{"bucket": postTestBucket},
			[]string{"eq", "$key", key},
			[]any{"content-length-range", json.Number("1000"), json.Number("2000")},
		}
		submit(t, minConds, []byte("small"), nil, nil)
	})
	t.Run("bad signature", func(t *testing.T) {
		submit(t, rangeConds, []byte("new"), func(f map[string]string) {
			f["x-amz-signature"] = strings.Repeat("f", 64)
		}, nil)
	})
	t.Run("condition mismatch", func(t *testing.T) {
		otherConds := []any{
			map[string]string{"bucket": postTestBucket},
			[]string{"eq", "$key", key + "/other"},
			[]any{"content-length-range", json.Number("1"), json.Number("10")},
		}
		submit(t, otherConds, []byte("new"), nil, nil)
	})
	t.Run("truncated stream", func(t *testing.T) {
		wideConds := []any{
			map[string]string{"bucket": postTestBucket},
			[]string{"eq", "$key", key},
			[]any{"content-length-range", json.Number("1"), json.Number("100000")},
		}
		submit(t, wideConds, bytes.Repeat([]byte("n"), 4000), nil, func(body []byte, ct string) ([]byte, string) {
			marker := bytes.Repeat([]byte("n"), 200)
			fileStart := bytes.Index(body, marker)
			require.Greater(t, fileStart, 0)
			return body[:fileStart+100], ct
		})
	})

	// Every failure above must leave the original body, type and metadata.
	obj, err := strg.Get(ctx, key)
	require.NoError(t, err)
	rc, err := obj.Open()
	require.NoError(t, err)
	defer func() { _ = rc.Close() }()
	got, err := io.ReadAll(rc)
	require.NoError(t, err)
	require.Equal(t, original, got)
	require.Equal(t, "text/original", obj.ContentType())
	require.Equal(t, "original", obj.Metadata()["author"])

	// All spool temp files are removed once the request is answered.
	leftovers, err := filepath.Glob(filepath.Join(os.TempDir(), "s2-post-*.tmp"))
	require.NoError(t, err)
	require.Empty(t, leftovers)
}

// --- IAM policy on the resolved resource ------------------------------------

func TestPostObjectIAMPolicy(t *testing.T) {
	policyJSON := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": "s3:PutObject",
			"Resource": "arn:aws:s3:::` + postTestBucket + `/allowed/*"
		}]
	}`
	var policy server.Policy
	require.NoError(t, json.Unmarshal([]byte(policyJSON), &policy))

	_, ts := newPostServer(t, func(cfg *server.Config) {
		cfg.Users = []server.User{{
			AccessKeyID:     "limited",
			SecretAccessKey: "limited-secret",
			Policy:          &policy,
		}}
	})
	amzDate := time.Now().UTC().Format("20060102T150405Z")
	exp := time.Now().UTC().Add(time.Hour)

	submit := func(t *testing.T, key string) *http.Response {
		conds := []any{
			map[string]string{"bucket": postTestBucket},
			[]string{"starts-with", "$key", ""},
			[]any{"content-length-range", 1, 1024},
		}
		b := newPostFormBuilder()
		b.field("key", key)
		b.sign(t, postPolicy(t, exp, conds), amzDate, "limited", "limited-secret")
		b.file("f", "application/octet-stream", []byte("payload"))
		body, ct := b.finish()
		return postDo(t, ts, "/"+postTestBucket, ct, body)
	}

	t.Run("prefix within grant", func(t *testing.T) {
		resp := submit(t, "allowed/a.txt")
		require.Equal(t, http.StatusNoContent, resp.StatusCode, readResp(t, resp))
	})
	t.Run("prefix outside grant denied", func(t *testing.T) {
		resp := submit(t, "forbidden/b.txt")
		require.Equal(t, http.StatusForbidden, resp.StatusCode)
		code, _ := s3ErrorBody(t, resp)
		require.Equal(t, "AccessDenied", code)
	})
}

// --- auth disabled -----------------------------------------------------------

func TestPostObjectAuthDisabled(t *testing.T) {
	_, ts := newPostServer(t, func(cfg *server.Config) {
		cfg.User = ""
		cfg.Password = ""
	})

	t.Run("unsigned form without policy accepted", func(t *testing.T) {
		b := newPostFormBuilder()
		b.field("key", "open/x.txt")
		b.file("x.txt", "text/plain", []byte("open"))
		body, ct := b.finish()
		resp := postDo(t, ts, "/"+postTestBucket, ct, body)
		require.Equal(t, http.StatusNoContent, resp.StatusCode, readResp(t, resp))
	})

	t.Run("supplied policy still enforced", func(t *testing.T) {
		exp := time.Now().UTC().Add(time.Hour)
		conds := []any{
			map[string]string{"bucket": postTestBucket},
			[]string{"eq", "$key", "open/pinned.txt"},
			[]string{"eq", "$Content-Type", "text/plain"},
		}
		b := newPostFormBuilder()
		b.field("key", "open/different.txt")
		b.field("Content-Type", "text/plain")
		b.field("policy", postPolicy(t, exp, conds))
		b.file("pinned.txt", "text/plain", []byte("x"))
		body, ct := b.finish()
		resp := postDo(t, ts, "/"+postTestBucket, ct, body)
		require.Equal(t, http.StatusForbidden, resp.StatusCode)
		code, _ := s3ErrorBody(t, resp)
		require.Equal(t, "AccessDenied", code)
	})
}

// --- DeleteObjects regression -----------------------------------------------

func TestPostDeleteObjectsDispatchUnchanged(t *testing.T) {
	_, ts := newPostServer(t, nil)
	// An UNSIGNED DeleteObjects must be rejected by the header/query SigV4
	// path, proving the presigned-POST dispatcher did not swallow ?delete.
	body := `<Delete><Object><Key>whatever</Key></Object></Delete>`
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/"+postTestBucket+"?delete", strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/xml")
	resp, err := ts.Client().Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusForbidden, resp.StatusCode)
	code, _ := s3ErrorBody(t, resp)
	require.Equal(t, "SignatureDoesNotMatch", code)

	// A non-multipart, unsigned bucket POST without ?delete also stays on
	// the SigV4 path (and is never treated as a presigned POST).
	req2, err := http.NewRequest(http.MethodPost, ts.URL+"/"+postTestBucket, strings.NewReader("{}"))
	require.NoError(t, err)
	req2.Header.Set("Content-Type", "application/json")
	resp2, err := ts.Client().Do(req2)
	require.NoError(t, err)
	defer func() { _ = resp2.Body.Close() }()
	require.Equal(t, http.StatusForbidden, resp2.StatusCode)
}
