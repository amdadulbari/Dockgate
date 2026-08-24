package policy

import "strings"

// imageAllowed reports whether an image reference matches any of the given glob
// patterns. Patterns support "*" (matches any run of characters, including
// none). As a convenience, a pattern with no tag and no wildcard (e.g. "nginx"
// or "ghcr.io/acme/api") also matches any tag or digest of that repository.
func imageAllowed(image string, patterns []string) bool {
	image = strings.TrimSpace(image)
	for _, pat := range patterns {
		pat = strings.TrimSpace(pat)
		if pat == "" {
			continue
		}
		if globMatch(pat, image) {
			return true
		}
		// Bare repository name (no tag/digest, no wildcard) -> match any tag.
		if !strings.ContainsAny(pat, "*") && !hasTagOrDigest(pat) {
			if globMatch(pat+":*", image) || globMatch(pat+"@*", image) {
				return true
			}
		}
	}
	return false
}

// hasTagOrDigest reports whether a reference already carries a ":tag" or
// "@digest". A ":" in a registry host:port prefix is not counted as a tag.
func hasTagOrDigest(ref string) bool {
	if strings.Contains(ref, "@") {
		return true
	}
	// Only consider a colon in the final path component as a tag separator.
	lastSlash := strings.LastIndexByte(ref, '/')
	last := ref[lastSlash+1:]
	return strings.Contains(last, ":")
}

// globMatch reports whether pattern (with "*" wildcards) matches s in full.
// The match is anchored at both ends. It is a small, allocation-light matcher
// rather than path.Match so that "/" and ":" are treated as ordinary literals.
func globMatch(pattern, s string) bool {
	// Fast path: no wildcards means exact comparison.
	if !strings.Contains(pattern, "*") {
		return pattern == s
	}

	parts := strings.Split(pattern, "*")
	// Anchor the first segment.
	if first := parts[0]; first != "" {
		if !strings.HasPrefix(s, first) {
			return false
		}
		s = s[len(first):]
	}
	// Anchor the last segment.
	if last := parts[len(parts)-1]; last != "" {
		if !strings.HasSuffix(s, last) {
			return false
		}
		s = s[:len(s)-len(last)]
	}
	// Middle segments must appear in order.
	for _, mid := range parts[1 : len(parts)-1] {
		if mid == "" {
			continue
		}
		i := strings.Index(s, mid)
		if i < 0 {
			return false
		}
		s = s[i+len(mid):]
	}
	return true
}
