package s3api

// Browser-based presigned POST uploads: POST /{bucket} with an
// AWS SigV4 multipart/form-data form. Unlike DeleteObjects on the same
// route, these carry no Authorization header: the signature is a form
// field computed over the base64 policy, the identity is the form's
// x-amz-credential, and every other field must be pinned by a policy
// condition. See handlePostObject for the full verification order.

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/mojatter/s2"
	"github.com/mojatter/s2/server"
	"github.com/mojatter/s2/server/middleware"
)

const (
	// postFormOverhead bounds what multipart framing, the signing fields and
	// every other text field may add on top of the file itself when capping
	// the whole request body.
	postFormOverhead = 1 << 20
	// maxPostFieldBytes caps a single non-file form value. A POST policy is
	// limited by S3 to roughly 20 KiB before base64, so 64 KiB is generous
	// without letting an unconstrained field grow memory.
	maxPostFieldBytes = 64 << 10
	// maxPostFields bounds the number of distinct text fields, independently
	// of their size.
	maxPostFields = 256

	contentTypeField = "Content-Type"
	metaFieldPrefix  = "x-amz-meta-"
	fileFieldName    = "file"
	filenameVar      = "${filename}"
)

// postExemptFields names form fields that never need a policy condition:
// the key, the SigV4 signing fields, STS tokens (s2 has no STS but accepts
// and ignores the field rather than failing an SDK that sends one), and the
// success-action selectors. "file" is not a text field at all.
var postExemptFields = map[string]bool{
	"key":                     true,
	"policy":                  true,
	"x-amz-algorithm":         true,
	"x-amz-credential":        true,
	"x-amz-date":              true,
	"x-amz-signature":         true,
	"x-amz-security-token":    true,
	"success_action_redirect": true,
	"success_action_status":   true,
}

// postError is a failed presigned POST with the exact S3 error shape the
// client must receive.
type postError struct {
	code   string
	msg    string
	status int
}

func (e *postError) Error() string { return e.code + ": " + e.msg }

func postInvalid(format string, args ...any) *postError {
	return &postError{"InvalidArgument", fmt.Sprintf(format, args...), http.StatusBadRequest}
}

func postDenied(msg string) *postError {
	return &postError{"AccessDenied", msg, http.StatusForbidden}
}

// isPresignedPostUpload reports whether a bucket-level POST request is a
// browser-style presigned POST rather than a SigV4-authenticated bucket
// operation (DeleteObjects). The signature lives inside the multipart body,
// so any Authorization header or presigned-URL query parameter keeps the
// request on the header/query SigV4 path unchanged.
func isPresignedPostUpload(r *http.Request) bool {
	if r.URL.Query().Has("delete") {
		return false
	}
	if r.Header.Get("Authorization") != "" || r.URL.Query().Get("X-Amz-Algorithm") != "" {
		return false
	}
	mediaType, _, err := mime.ParseMediaType(requestContentType(r))
	return err == nil && mediaType == "multipart/form-data"
}

// bucketPOSTWithSigV4 is the unchanged SigV4-wrapped bucket POST handler
// (DeleteObjects and the NotImplemented fallback); hoisted so the
// dispatcher does not rebuild the wrapper on every request.
var bucketPOSTWithSigV4 = middleware.SigV4(handleBucketPOST)

// handleBucketPOSTEntry is the registered bucket-level POST dispatcher. It
// routes presigned POST uploads to their form-based authentication and all
// other bucket POSTs (today: DeleteObjects) through the unchanged SigV4
// middleware.
func handleBucketPOSTEntry(s *server.Server, w http.ResponseWriter, r *http.Request) {
	if isPresignedPostUpload(r) {
		handlePostObject(s, w, r)
		return
	}
	bucketPOSTWithSigV4(s, w, r)
}

// canonicalPostField canonicalizes a form field or policy condition name:
// the MIME type is spelled "Content-Type" regardless of client casing, and
// every x-amz-meta-* name is lowercased (matching how PutObject stores
// metadata). Other names keep their exact spelling.
func canonicalPostField(name string) string {
	if strings.EqualFold(name, contentTypeField) {
		return contentTypeField
	}
	if len(name) > len(metaFieldPrefix) && strings.EqualFold(name[:len(metaFieldPrefix)], metaFieldPrefix) {
		return metaFieldPrefix + strings.ToLower(name[len(metaFieldPrefix):])
	}
	return name
}

// readPostForm streams the multipart body up to (but not including) the file
// part. Text field values are collected in full; duplicates are rejected.
// The caller keeps mr to spool the file body and to confirm the file is the
// form's last part.
func readPostForm(mr *multipart.Reader) (fields map[string]string, file *multipart.Part, perr *postError) {
	fields = make(map[string]string)
	for {
		part, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			return fields, nil, nil
		}
		if err != nil {
			if isRequestBodyTooLarge(err) {
				return nil, nil, &postError{"EntityTooLarge", "Your proposed upload exceeds the maximum allowed size", http.StatusBadRequest}
			}
			return nil, nil, postInvalid("Malformed multipart/form-data POST request: %v", err)
		}
		if part.FormName() == fileFieldName {
			return fields, part, nil
		}
		data, err := io.ReadAll(io.LimitReader(part, maxPostFieldBytes+1))
		_ = part.Close()
		if err != nil {
			return nil, nil, postInvalid("Malformed multipart/form-data POST request: %v", err)
		}
		if len(data) > maxPostFieldBytes {
			return nil, nil, postInvalid("Form field %q exceeds the maximum size of %d bytes", part.FormName(), maxPostFieldBytes)
		}
		name := canonicalPostField(part.FormName())
		if _, dup := fields[name]; dup {
			return nil, nil, postInvalid("Duplicate form field %q", name)
		}
		if len(fields) >= maxPostFields {
			return nil, nil, postInvalid("POST form carries more than %d fields", maxPostFields)
		}
		fields[name] = string(data)
	}
}

func isRequestBodyTooLarge(err error) bool {
	var maxErr *http.MaxBytesError
	return errors.As(err, &maxErr) || strings.Contains(err.Error(), "http: request body too large")
}

// postPolicyDoc is the decoded POST policy.
type postPolicyDoc struct {
	Expiration string            `json:"expiration"`
	Conditions []json.RawMessage `json:"conditions"`
}

// postCondition is one validated policy condition.
type postCondition struct {
	op      string // "eq", "starts-with", "content-length-range"
	field   string // canonical field name ("bucket", "key", "Content-Type", "x-amz-meta-*")
	value   string // eq / starts-with
	minSize int64  // content-length-range
	maxSize int64
}

// parsePostPolicy base64-decodes and JSON-parses the policy field exactly as
// submitted (the signature was computed over that exact base64 string).
func parsePostPolicy(policyB64 string) (*postPolicyDoc, *postError) {
	raw, err := base64.StdEncoding.DecodeString(policyB64)
	if err != nil {
		return nil, postInvalid("Policy is not valid base64: %v", err)
	}
	var doc postPolicyDoc
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return nil, postInvalid("Policy is not valid JSON: %v", err)
	}
	if doc.Expiration == "" {
		return nil, postInvalid("Policy is missing the expiration element")
	}
	if len(doc.Conditions) == 0 {
		return nil, postInvalid("Policy is missing the conditions element")
	}
	return &doc, nil
}

// parsePostConditions turns the raw JSON conditions into validated
// postCondition values.
func parsePostConditions(doc *postPolicyDoc) ([]postCondition, *postError) {
	conds := make([]postCondition, 0, len(doc.Conditions))
	for i, raw := range doc.Conditions {
		// Short form: {"bucket": "name"}.
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(raw, &obj); err == nil {
			if len(obj) != 1 {
				return nil, postInvalid("Policy conditions[%d] must name exactly one field", i)
			}
			var name, value string
			for k, v := range obj {
				name = k
				if err := json.Unmarshal(v, &value); err != nil {
					return nil, postInvalid("Policy conditions[%d]: %v", i, err)
				}
			}
			cond, perr := newMatchCondition(i, "eq", "$"+name, value)
			if perr != nil {
				return nil, perr
			}
			conds = append(conds, cond)
			continue
		}
		var arr []json.RawMessage
		if err := json.Unmarshal(raw, &arr); err != nil {
			return nil, postInvalid("Policy conditions[%d] must be an array or an object", i)
		}
		if len(arr) == 0 {
			return nil, postInvalid("Policy conditions[%d] is empty", i)
		}
		var op string
		if err := json.Unmarshal(arr[0], &op); err != nil {
			return nil, postInvalid("Policy conditions[%d]: %v", i, err)
		}
		switch op {
		case "eq", "starts-with":
			if len(arr) != 3 {
				return nil, postInvalid("Policy conditions[%d]: %q requires a field reference and a value", i, op)
			}
			var ref, value string
			if err := json.Unmarshal(arr[1], &ref); err != nil {
				return nil, postInvalid("Policy conditions[%d]: %v", i, err)
			}
			if err := json.Unmarshal(arr[2], &value); err != nil {
				return nil, postInvalid("Policy conditions[%d]: %v", i, err)
			}
			cond, perr := newMatchCondition(i, op, ref, value)
			if perr != nil {
				return nil, perr
			}
			conds = append(conds, cond)
		case "content-length-range":
			if len(arr) != 3 {
				return nil, postInvalid("Policy conditions[%d]: content-length-range requires a minimum and maximum", i)
			}
			minSize, err := jsonNumberInt64(arr[1])
			if err != nil {
				return nil, postInvalid("Policy conditions[%d]: invalid range minimum: %v", i, err)
			}
			maxSize, err := jsonNumberInt64(arr[2])
			if err != nil {
				return nil, postInvalid("Policy conditions[%d]: invalid range maximum: %v", i, err)
			}
			if minSize < 0 || maxSize < 0 || minSize > maxSize {
				return nil, postInvalid("Policy conditions[%d]: invalid content-length-range %d-%d", i, minSize, maxSize)
			}
			conds = append(conds, postCondition{op: op, minSize: minSize, maxSize: maxSize})
		default:
			return nil, postInvalid("Policy conditions[%d]: unsupported operator %q", i, op)
		}
	}
	return conds, nil
}

// newMatchCondition validates one eq/starts-with condition: the reference
// must name a field s2 evaluates, and must use the "$field" form.
func newMatchCondition(i int, op, ref, value string) (postCondition, *postError) {
	if !strings.HasPrefix(ref, "$") || ref == "$" {
		return postCondition{}, postInvalid("Policy conditions[%d]: field reference %q must start with %q", i, ref, "$")
	}
	field := canonicalPostField(strings.TrimPrefix(ref, "$"))
	switch {
	case field == "bucket" || field == "key" || field == contentTypeField:
	case strings.HasPrefix(field, metaFieldPrefix):
	default:
		return postCondition{}, postInvalid("Policy conditions[%d]: unsupported field %q", i, ref)
	}
	return postCondition{op: op, field: field, value: value}, nil
}

func jsonNumberInt64(raw json.RawMessage) (int64, error) {
	var n json.Number
	if err := json.Unmarshal(raw, &n); err != nil {
		return 0, err
	}
	return n.Int64()
}

// evaluatedPolicy holds the size bounds the conditions pin down.
type evaluatedPolicy struct {
	minSize int64 // 0 = no lower bound
	maxSize int64 // math.MaxInt64 = no upper bound
}

// evaluatePostPolicy checks every condition against the actual submitted
// values and the expanded key, and guarantees every non-exempt submitted
// field is pinned by at least one condition. The file size itself is
// checked by the caller after spooling; only the bounds are resolved here.
func evaluatePostPolicy(conds []postCondition, fields map[string]string, bucket, key string) (*evaluatedPolicy, *postError) {
	hasBucketCondition := false
	covered := make(map[string]bool)
	ev := &evaluatedPolicy{minSize: 0, maxSize: math.MaxInt64}

	for i, cond := range conds {
		if cond.op == "content-length-range" {
			// All ranges must contain the actual size; intersect them. A
			// pair that leaves no possible size is a contradiction, not a
			// condition the upload can satisfy.
			ev.minSize = max(ev.minSize, cond.minSize)
			ev.maxSize = min(ev.maxSize, cond.maxSize)
			if ev.minSize > ev.maxSize {
				return nil, postDenied(fmt.Sprintf("Invalid according to Policy: Policy Condition failed at conditions[%d]: contradictory content-length-range", i))
			}
			continue
		}

		covered[cond.field] = true
		var actual string
		switch cond.field {
		case "bucket":
			hasBucketCondition = true
			actual = bucket
		case "key":
			actual = key
		default:
			var present bool
			actual, present = fields[cond.field]
			if !present {
				return nil, postDenied(fmt.Sprintf("Invalid according to Policy: Policy Condition failed at conditions[%d]: field %q is missing from the POST", i, cond.field))
			}
		}
		if !matchPostCondition(cond, actual) {
			return nil, postDenied(fmt.Sprintf("Invalid according to Policy: Policy Condition failed at conditions[%d]: %s %q", i, cond.op, cond.value))
		}
	}

	if !hasBucketCondition {
		return nil, postInvalid("Policy must contain a condition that pins the bucket")
	}

	// Every submitted field other than the exempt signing/control fields and
	// the file must be constrained; an extra field can never widen an upload.
	for name := range fields {
		if postExemptFields[name] || covered[name] {
			continue
		}
		return nil, postDenied(fmt.Sprintf("Invalid according to Policy: Extra input field not allowed: [%s]", name))
	}

	return ev, nil
}

func matchPostCondition(cond postCondition, actual string) bool {
	switch cond.op {
	case "eq":
		return actual == cond.value
	case "starts-with":
		return strings.HasPrefix(actual, cond.value)
	default:
		return false
	}
}

// parsePostExpiration parses S3's ISO-8601 policy expiration.
func parsePostExpiration(s string) (time.Time, error) {
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05.000Z"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("invalid expiration %q", s)
}

func handlePostObject(s *server.Server, w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	bucket := r.PathValue("bucket")
	serverMaxSize := s.Config.EffectiveMaxUploadSize()

	_, params, err := mime.ParseMediaType(requestContentType(r))
	if err != nil || params["boundary"] == "" {
		writeError(w, r, "InvalidArgument", "POST uploads must use multipart/form-data with a boundary", http.StatusBadRequest)
		return
	}

	// The whole-request backstop counts framing too; the file itself is
	// capped separately by its own byte count below.
	totalLimit := serverMaxSize + min(postFormOverhead, math.MaxInt64-serverMaxSize)
	if r.ContentLength > totalLimit {
		writeEntityTooLarge(w, r, serverMaxSize)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, totalLimit)

	mr := multipart.NewReader(r.Body, params["boundary"])
	fields, filePart, perr := readPostForm(mr)
	if perr != nil {
		writeError(w, r, perr.code, perr.msg, perr.status)
		return
	}
	if filePart == nil {
		writeError(w, r, "InvalidArgument", "POST requires a file upload in the %q field", http.StatusBadRequest)
		return
	}
	filename := filePart.FileName()

	rawKey := fields["key"]
	if rawKey == "" {
		writeError(w, r, "InvalidArgument", "Key field missing in POST", http.StatusBadRequest)
		return
	}
	// ${filename} is the only variable, and only the upload's file name may
	// replace it; every other ${...} token stays literal.
	key := strings.ReplaceAll(rawKey, filenameVar, filename)
	if err := s2.ValidateName(key); err != nil {
		writeError(w, r, "InvalidArgument", err.Error(), http.StatusBadRequest)
		return
	}

	if perr := validateSuccessAction(fields); perr != nil {
		writeError(w, r, perr.code, perr.msg, perr.status)
		return
	}
	if _, ok := fields[metaFieldPrefix+reservedETagKey]; ok {
		writeError(w, r, "InvalidArgument", "Metadata key %q is reserved", http.StatusBadRequest)
		return
	}

	authEnabled := s.Config.AuthEnabled()
	var user *server.User
	var policy *postPolicyDoc

	if policyB64, signed := fields["policy"]; signed || authEnabled {
		if policyB64 == "" {
			writeError(w, r, "AccessDenied", "Invalid according to Policy: Policy missing in the form post", http.StatusForbidden)
			return
		}
		doc, perr := parsePostPolicy(policyB64)
		if perr != nil {
			writeError(w, r, perr.code, perr.msg, perr.status)
			return
		}
		if authEnabled {
			lookup := func(accessKeyID string) (*server.User, bool) {
				u := s.Config.LookupUser(accessKeyID)
				return u, u != nil
			}
			matched, verr := middleware.VerifyPostPolicyV4(lookup, middleware.PostPolicyFields{
				Algorithm:  fields["x-amz-algorithm"],
				Credential: fields["x-amz-credential"],
				Date:       fields["x-amz-date"],
				Policy:     policyB64,
				Signature:  fields["x-amz-signature"],
			})
			if verr != nil {
				writeError(w, r, "SignatureDoesNotMatch", verr.Error(), http.StatusForbidden)
				return
			}
			user = matched
		}
		expiration, err := parsePostExpiration(doc.Expiration)
		if err != nil {
			writeError(w, r, "InvalidArgument", err.Error(), http.StatusBadRequest)
			return
		}
		if time.Now().UTC().After(expiration) {
			writeError(w, r, "AccessDenied", "Invalid according to Policy: Policy expired", http.StatusForbidden)
			return
		}
		policy = doc
	}

	var eval *evaluatedPolicy
	if policy != nil {
		conds, perr := parsePostConditions(policy)
		if perr != nil {
			writeError(w, r, perr.code, perr.msg, perr.status)
			return
		}
		eval, perr = evaluatePostPolicy(conds, fields, bucket, key)
		if perr != nil {
			writeError(w, r, perr.code, perr.msg, perr.status)
			return
		}
	} else {
		// Auth disabled and no policy supplied: no conditions, the server
		// upload limit still bounds the file.
		eval = &evaluatedPolicy{minSize: 0, maxSize: math.MaxInt64}
	}

	// Authenticate the principal against the finally-expanded resource, like
	// header/query SigV4 does for PutObject.
	if !server.AllowedS3Action(user, server.ActionPutObject, bucket, key) {
		writeError(w, r, "AccessDenied", "Access Denied", http.StatusForbidden)
		return
	}

	strg, err := s.Buckets.Get(ctx, bucket)
	if err != nil {
		code, msg, status := s2ErrorToS3Error(err)
		writeError(w, r, code, msg, status)
		return
	}

	// The server-wide upload limit always applies on top of any policy range.
	fileCap := min(serverMaxSize, eval.maxSize)
	tmp, size, perr := spoolPostFile(filePart, fileCap)
	if perr != nil {
		writeError(w, r, perr.code, perr.msg, perr.status)
		return
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	defer func() { _ = tmp.Close() }()

	if size < eval.minSize {
		writeError(w, r, "EntityTooSmall", fmt.Sprintf("Your proposed upload is smaller than the minimum allowed size (%d bytes)", eval.minSize), http.StatusBadRequest)
		return
	}

	// The file must be the form's last part: anything after it is ignored by
	// a lenient parser and must not widen the request.
	switch trailing, terr := mr.NextPart(); {
	case terr == nil:
		_ = trailing.Close()
		writeError(w, r, "InvalidArgument", "The %q field must be the last field in the POST form", http.StatusBadRequest)
		return
	case errors.Is(terr, io.EOF):
	default:
		if isRequestBodyTooLarge(terr) {
			writeEntityTooLarge(w, r, serverMaxSize)
			return
		}
		writeError(w, r, "IncompleteBody", "The request body terminated before the multipart closing boundary", http.StatusBadRequest)
		return
	}

	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		writeError(w, r, "InternalError", err.Error(), http.StatusInternalServerError)
		return
	}

	obj := s2.NewObjectReader(key, tmp, s2.MustUint64(size),
		s2.WithContentType(fields[contentTypeField]), s2.WithMetadata(postMetadata(fields)))
	res, err := s2.Upload(ctx, strg, obj, s2.UploadOptions{})
	if err != nil {
		code, msg, status := uploadErrorToS3Error(err)
		writeError(w, r, code, msg, status)
		return
	}

	writePostSuccess(w, r, fields, bucket, key, filename, res.ETag)
}

// validateSuccessAction validates the optional success_action_* selectors up
// front, so a bad value fails before any byte is stored.
func validateSuccessAction(fields map[string]string) *postError {
	if status := fields["success_action_status"]; status != "" {
		if !slices.Contains([]string{"200", "201", "204"}, status) {
			return postInvalid("success_action_status must be 200, 201, or 204, got %q", status)
		}
	}
	if redirect := fields["success_action_redirect"]; redirect != "" {
		u, err := url.Parse(redirect)
		if err != nil || !u.IsAbs() || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return postInvalid("success_action_redirect must be an absolute http(s) URL, got %q", redirect)
		}
	}
	return nil
}

// postMetadata gathers the submitted x-amz-meta-* fields as object metadata.
// The reserved s2-etag key has already been rejected.
func postMetadata(fields map[string]string) s2.Metadata {
	md := make(s2.Metadata)
	for name, value := range fields {
		if strings.HasPrefix(name, metaFieldPrefix) {
			md[name[len(metaFieldPrefix):]] = value
		}
	}
	return md
}

// spoolPostFile copies the file part into a temp file, enforcing cap. The
// storage write never starts until the whole file has been received and
// measured, so a truncated or oversized stream cannot touch an existing
// object; the caller removes the temp file after the write.
func spoolPostFile(part *multipart.Part, cap int64) (*os.File, int64, *postError) {
	tmp, err := os.CreateTemp("", "s2-post-*.tmp")
	if err != nil {
		return nil, 0, &postError{"InternalError", err.Error(), http.StatusInternalServerError}
	}
	n, err := io.Copy(tmp, io.LimitReader(part, cap+1))
	if err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		if isRequestBodyTooLarge(err) {
			return nil, 0, &postError{"EntityTooLarge", "Your proposed upload exceeds the maximum allowed size", http.StatusBadRequest}
		}
		return nil, 0, &postError{"IncompleteBody", "The file upload ended before its multipart boundary: " + err.Error(), http.StatusBadRequest}
	}
	if n > cap {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return nil, 0, &postError{"EntityTooLarge", "Your proposed upload exceeds the maximum allowed size", http.StatusBadRequest}
	}
	return tmp, n, nil
}

// writePostSuccess answers the upload per its success_action_* fields: a
// redirect (303) wins over success_action_status; 201 returns the
// PostResponse document; 200 and the default 204 return an empty body.
func writePostSuccess(w http.ResponseWriter, r *http.Request, fields map[string]string, bucket, key, filename, etag string) {
	if redirect := fields["success_action_redirect"]; redirect != "" {
		loc := strings.ReplaceAll(redirect, filenameVar, filename)
		u, err := url.Parse(loc)
		if err != nil {
			writeError(w, r, "InvalidArgument", err.Error(), http.StatusBadRequest)
			return
		}
		q := u.Query()
		q.Set("bucket", bucket)
		q.Set("key", key)
		if etag != "" {
			q.Set("etag", etag)
		}
		u.RawQuery = q.Encode()
		w.Header().Set("Location", u.String())
		w.WriteHeader(http.StatusSeeOther)
		return
	}

	if etag != "" {
		w.Header().Set("ETag", etag)
	}
	switch fields["success_action_status"] {
	case "201":
		writeXML(w, http.StatusCreated, PostResponse{
			Location: postObjectLocation(r, bucket, key),
			Bucket:   bucket,
			Key:      key,
			ETag:     etag,
		})
	case "200":
		w.WriteHeader(http.StatusOK)
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

// postObjectLocation builds the object's externally visible URL from the
// request, honoring X-Forwarded-Proto behind a TLS-terminating proxy.
func postObjectLocation(r *http.Request, bucket, key string) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if xfp := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Proto"), ",")[0]); xfp != "" {
		scheme = xfp
	}
	segments := strings.Split(key, "/")
	for i, seg := range segments {
		segments[i] = url.PathEscape(seg)
	}
	return (&url.URL{Scheme: scheme, Host: r.Host, Path: "/" + bucket + "/" + strings.Join(segments, "/")}).String()
}
