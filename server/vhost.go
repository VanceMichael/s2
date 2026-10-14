package server

import (
	"context"
	"net"
	"net/http"
	"strings"
)

// vhostMode is the result of classifying a request Host against the
// configured virtual-host-style service domain.
type vhostMode int

const (
	// vhostPathStyle: the Host does not address the configured service
	// domain; the request keeps existing path-style behaviour. This is also
	// the only mode when no domain is configured.
	vhostPathStyle vhostMode = iota
	// vhostServiceRoot: the Host is the bare configured domain (e.g.
	// "s3.local.test:9000"); its root keeps serving ListBuckets and the
	// health endpoint, and in-path bucket names stay path-style.
	vhostServiceRoot
	// vhostBucket: the Host is "<bucket>.<domain>" with a legal single
	// bucket label; the request is routed with the Host-derived bucket and
	// the wire path verbatim as the key.
	vhostBucket
	// vhostInvalid: the Host clearly targets the configured domain (or its
	// FQDN form with a trailing dot) but its suffix match or bucket prefix
	// is malformed. The request is rejected outright instead of being
	// reinterpreted as a path-style resource, which could land it silently
	// in the bucket named by the first path segment.
	vhostInvalid
)

// matchBucketHost classifies host against the configured domain.
//
// Matching is exact and case-sensitive after the config's normalization:
//   - a port suffix is stripped first (it belongs to the listener, not the
//     DNS name) and never affects the result;
//   - only a Host that ends with "."+domain and whose remaining prefix is a
//     single legal bucket label (no dots, 3-63 chars, [a-z0-9-]) is
//     virtual-host addressing;
//   - the bare domain is the service root;
//   - any FQDN trailing dot (on the bucket host or the root) and any other
//     malformed prefix that still sits directly on the domain is invalid;
//   - anything else (IP literals, localhost, look-alike names such as
//     "evils3.local.test") is plain path-style.
func matchBucketHost(host, domain string) (bucket string, mode vhostMode) {
	if domain == "" {
		return "", vhostPathStyle
	}
	h := host
	// SplitHostPort errors on a bare name without a port; in that case keep host as-is.
	if name, _, err := net.SplitHostPort(h); err == nil {
		h = name
	}
	switch {
	case h == domain:
		return "", vhostServiceRoot
	case strings.HasSuffix(h, "."+domain):
		prefix := h[:len(h)-len("."+domain)]
		if isVHostBucketLabel(prefix) {
			return prefix, vhostBucket
		}
		return "", vhostInvalid
	case h == domain+".":
		// Bare service root spelled as an FQDN; exact match is required, so it is not silently the root.
		return "", vhostInvalid
	case strings.HasSuffix(h, "."+domain+"."):
		// Bucket host (or a deeper name) with an FQDN trailing dot; never falls through to path-style.
		return "", vhostInvalid
	default:
		return "", vhostPathStyle
	}
}

// isVHostBucketLabel reports whether s is a legal bucket name consisting of
// a single DNS label. S3 bucket names may carry dots, but a dotted prefix
// over the configured suffix cannot be distinguished from an unrelated
// deeper hostname, so virtual-host addressing intentionally requires one
// label only.
func isVHostBucketLabel(s string) bool {
	if strings.ContainsAny(s, "./") {
		return false
	}
	return isValidBucketName(s)
}

// vhostBucketKeyType carries the bucket name the outer classifier extracted
// from the Host header, from the router to the vhost mux's dispatch shim.
type vhostBucketKeyType struct{}

func withVHostBucket(ctx context.Context, bucket string) context.Context {
	return context.WithValue(ctx, vhostBucketKeyType{}, bucket)
}

func vhostBucketFromContext(ctx context.Context) string {
	bucket, _ := ctx.Value(vhostBucketKeyType{}).(string)
	return bucket
}

// s3VHostHandlers holds the routes for virtual-host-style bucket requests,
// served alongside the path-style s3Handlers. Patterns name only the key
// (plus "/{$}" for bucket-root operations); the bucket itself is derived
// from the Host header.
var s3VHostHandlers = map[string]HandlerFunc{}

// RegisterS3VHostHandleFunc registers a handler for virtual-host-style
// requests. Patterns use Go 1.22 ServeMux syntax with no "{bucket}"
// wildcard.
func RegisterS3VHostHandleFunc(pattern string, handler HandlerFunc) {
	registerHandler(s3VHostHandlers, "S3 virtual-host ", pattern, handler)
}

// buildVHostMux composes the vhost registry into an http.ServeMux. The mux
// populates its own path values (the "{key...}" wildcard); each dispatch
// shim then adds the bucket the outer classifier extracted from the Host.
// The wire URL is never rewritten, so signature verification keeps seeing
// the exact Host/path/query the client signed. cleanPath is applied with
// the same traversal rules as the path-style mux; the health endpoint is
// intentionally absent -- on a bucket host, a key equal to the health
// path (e.g. "/healthz") is an object.
func (s *Server) buildVHostMux(registry map[string]HandlerFunc, reject http.HandlerFunc) http.Handler {
	mux := http.NewServeMux()
	for pattern, handler := range registry {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			r.SetPathValue("bucket", vhostBucketFromContext(r.Context()))
			handler(s, w, r)
		})
	}
	return cleanPathHandler(reject)(mux)
}

// virtualHostRouter routes each request according to matchBucketHost:
// bucket hosts go to bucketHost, invalid hosts get a 400 S3 error, and the
// service root plus unknown hosts keep the existing path-style chain.
func virtualHostRouter(domain string, pathStyle, bucketHost http.Handler) http.Handler {
	if domain == "" {
		return pathStyle
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bucket, mode := matchBucketHost(r.Host, domain)
		switch mode {
		case vhostBucket:
			bucketHost.ServeHTTP(w, r.WithContext(withVHostBucket(r.Context(), bucket)))
		case vhostInvalid:
			WriteS3Error(w, r, "InvalidArgument",
				"The bucket name encoded in the Host header is not valid; virtual-host-style addressing requires a single legal bucket label immediately before "+domain,
				http.StatusBadRequest)
		default:
			pathStyle.ServeHTTP(w, r)
		}
	})
}
