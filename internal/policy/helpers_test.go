package policy

import "testing"

func TestGlobMatchEmptyMiddleSegments(t *testing.T) {
	// Consecutive wildcards produce empty middle segments that must be skipped.
	if !globMatch("a**b", "aXYZb") {
		t.Error(`"a**b" should match "aXYZb"`)
	}
	if !globMatch("**", "anything") {
		t.Error(`"**" should match anything`)
	}
	if globMatch("a*b", "aX") {
		t.Error(`"a*b" should not match "aX" (missing suffix)`)
	}
}

func TestHasTagOrDigest(t *testing.T) {
	cases := map[string]bool{
		"nginx":                  false,
		"nginx:1.25":             true,
		"nginx@sha256:abc":       true,
		"localhost:5000/nginx":   false, // colon is in the host, not a tag
		"localhost:5000/nginx:1": true,
	}
	for ref, want := range cases {
		if got := hasTagOrDigest(ref); got != want {
			t.Errorf("hasTagOrDigest(%q) = %v, want %v", ref, got, want)
		}
	}
}

func TestImageAllowedSkipsEmptyPatterns(t *testing.T) {
	// Empty/whitespace patterns in the list must be ignored, not match everything.
	if imageAllowed("nginx", []string{"", "  "}) {
		t.Error("empty patterns should not match")
	}
	if !imageAllowed("nginx", []string{"", "nginx"}) {
		t.Error("a valid pattern alongside empty ones should still match")
	}
}

func TestQuote(t *testing.T) {
	if quote("") != "(unnamed)" {
		t.Errorf(`quote("") = %q`, quote(""))
	}
	if quote("read") != `"read"` {
		t.Errorf(`quote("read") = %q`, quote("read"))
	}
}
