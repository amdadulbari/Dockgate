package policy

import "testing"

func TestImageAllowed(t *testing.T) {
	cases := []struct {
		image    string
		patterns []string
		want     bool
	}{
		// Bare name matches any tag of that repository.
		{"nginx:1.25", []string{"nginx"}, true},
		{"nginx", []string{"nginx"}, true},
		{"nginx:latest", []string{"nginx"}, true},
		{"nginxinc/nginx", []string{"nginx"}, false},
		// Explicit tag wildcard.
		{"redis:7", []string{"redis:*"}, true},
		{"redis", []string{"redis:*"}, false}, // no tag, pattern requires one
		// Registry/org wildcard.
		{"ghcr.io/acme/api:v1", []string{"ghcr.io/*"}, true},
		{"docker.io/library/nginx", []string{"ghcr.io/*"}, false},
		// Digest match via bare-name convenience.
		{"nginx@sha256:abc", []string{"nginx"}, true},
		// Multiple patterns.
		{"alpine:3.20", []string{"nginx", "alpine:*"}, true},
		// No match.
		{"ubuntu:22.04", []string{"nginx", "redis:*"}, false},
		// Exact full reference.
		{"nginx:1.25", []string{"nginx:1.25"}, true},
		{"nginx:1.26", []string{"nginx:1.25"}, false},
	}
	for _, c := range cases {
		if got := imageAllowed(c.image, c.patterns); got != c.want {
			t.Errorf("imageAllowed(%q, %v) = %v, want %v", c.image, c.patterns, got, c.want)
		}
	}
}

func TestGlobMatch(t *testing.T) {
	cases := []struct {
		pattern, s string
		want       bool
	}{
		{"nginx", "nginx", true},
		{"nginx", "nginx:1", false},
		{"nginx:*", "nginx:1.25", true},
		{"*", "anything", true},
		{"ghcr.io/*/api:*", "ghcr.io/acme/api:v1", true},
		{"ghcr.io/*/api:*", "ghcr.io/acme/web:v1", false},
		{"a*b*c", "axxbyyc", true},
		{"a*b*c", "axxc", false},
	}
	for _, c := range cases {
		if got := globMatch(c.pattern, c.s); got != c.want {
			t.Errorf("globMatch(%q, %q) = %v, want %v", c.pattern, c.s, got, c.want)
		}
	}
}
