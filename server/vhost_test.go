package server

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMatchBucketHost(t *testing.T) {
	const domain = "s3.local.test"

	testCases := []struct {
		caseName string
		host     string
		domain   string
		want     vhostMode
		bucket   string
	}{
		// Feature disabled: every Host is path-style.
		{caseName: "no domain configured", host: "photos." + domain, domain: "", want: vhostPathStyle},

		// Bucket hosts: port never matters.
		{caseName: "bucket host", host: "photos." + domain, domain: domain, want: vhostBucket, bucket: "photos"},
		{caseName: "bucket host with port", host: "photos." + domain + ":9000", domain: domain, want: vhostBucket, bucket: "photos"},
		{caseName: "bucket host with other port", host: "photos." + domain + ":12345", domain: domain, want: vhostBucket, bucket: "photos"},
		{caseName: "bucket host empty port", host: "photos." + domain + ":", domain: domain, want: vhostBucket, bucket: "photos"},
		{caseName: "bucket with hyphen", host: "my-photos." + domain, domain: domain, want: vhostBucket, bucket: "my-photos"},

		// Service root.
		{caseName: "bare domain", host: domain, domain: domain, want: vhostServiceRoot},
		{caseName: "bare domain with port", host: domain + ":9000", domain: domain, want: vhostServiceRoot},

		// Trailing dots: never accepted, never path-style.
		{caseName: "bucket host trailing dot", host: "photos." + domain + ".", domain: domain, want: vhostInvalid},
		{caseName: "bucket host trailing dot with port", host: "photos." + domain + ".:9000", domain: domain, want: vhostInvalid},
		{caseName: "bare domain trailing dot", host: domain + ".", domain: domain, want: vhostInvalid},
		{caseName: "bare domain trailing dot with port", host: domain + ".:9000", domain: domain, want: vhostInvalid},
		{caseName: "deeper name trailing dot", host: "a.photos." + domain + ".", domain: domain, want: vhostInvalid},

		// Illegal bucket labels.
		{caseName: "uppercase label", host: "Photos." + domain, domain: domain, want: vhostInvalid},
		{caseName: "label too short", host: "a." + domain, domain: domain, want: vhostInvalid},
		{caseName: "label two chars", host: "ab." + domain, domain: domain, want: vhostInvalid},
		{caseName: "leading hyphen", host: "-photos." + domain, domain: domain, want: vhostInvalid},
		{caseName: "dotted prefix", host: "my.photos." + domain, domain: domain, want: vhostInvalid},
		{caseName: "double dot prefix", host: "ph..otos." + domain, domain: domain, want: vhostInvalid},
		{caseName: "underscore label", host: "my_photos." + domain, domain: domain, want: vhostInvalid},
		{caseName: "label too long", host: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa." + domain, domain: domain, want: vhostInvalid},

		// Unknown hosts: deterministic path-style, bucket comes from the path.
		{caseName: "lookalike without dot separator", host: "evils3.local.test", domain: domain, want: vhostPathStyle},
		{caseName: "lookalike deeper name", host: "photos.s3.local.test.evil.com", domain: domain, want: vhostPathStyle},
		{caseName: "domain as suffix of other domain", host: "s3.local.test.evil.com", domain: domain, want: vhostPathStyle},
		{caseName: "localhost", host: "localhost:9000", domain: domain, want: vhostPathStyle},
		{caseName: "ipv4", host: "127.0.0.1:9000", domain: domain, want: vhostPathStyle},
		{caseName: "ipv6", host: "[::1]:9000", domain: domain, want: vhostPathStyle},
		{caseName: "unrelated host", host: "evil.example.com", domain: domain, want: vhostPathStyle},
	}
	for _, tc := range testCases {
		t.Run(tc.caseName, func(t *testing.T) {
			bucket, mode := matchBucketHost(tc.host, tc.domain)
			assert.Equal(t, tc.want, mode)
			assert.Equal(t, tc.bucket, bucket)
		})
	}
}

func TestMatchBucketHostSingleLabelDomain(t *testing.T) {
	testCases := []struct {
		caseName string
		host     string
		want     vhostMode
		bucket   string
	}{
		{caseName: "bucket host", host: "photos.s3", want: vhostBucket, bucket: "photos"},
		{caseName: "bare root", host: "s3", want: vhostServiceRoot},
		{caseName: "lookalike name", host: "evils3", want: vhostPathStyle},
		{caseName: "trailing dot bucket", host: "photos.s3.", want: vhostInvalid},
		{caseName: "trailing dot root", host: "s3.", want: vhostInvalid},
	}
	for _, tc := range testCases {
		t.Run(tc.caseName, func(t *testing.T) {
			bucket, mode := matchBucketHost(tc.host, "s3")
			assert.Equal(t, tc.want, mode)
			assert.Equal(t, tc.bucket, bucket)
		})
	}
}
