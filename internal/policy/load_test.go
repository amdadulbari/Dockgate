package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadFromFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte("default_action: allow\nrules: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if p.DefaultAction != Allow {
		t.Errorf("DefaultAction = %q", p.DefaultAction)
	}
}

func TestLoadMissingFile(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "nope.yaml")); err == nil {
		t.Error("expected error loading a missing policy file")
	}
}

func TestLoadInvalidYAML(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.yaml")
	os.WriteFile(path, []byte("default_action: [not-a-scalar]\n"), 0o644)
	if _, err := Load(path); err == nil {
		t.Error("expected error loading malformed policy")
	}
}

func TestParseRejectsInvalidRuleEffect(t *testing.T) {
	src := "rules:\n  - name: x\n    effect: sometimes\n    actions: [container.list]\n"
	if _, err := Parse([]byte(src)); err == nil {
		t.Error("expected error for invalid rule effect")
	}
}

func TestParseUnnamedInvalidRuleReportsIndex(t *testing.T) {
	// An invalid rule with no name should be reported by its position.
	src := "rules:\n  - effect: allow\n    actions: []\n"
	_, err := Parse([]byte(src))
	if err == nil {
		t.Fatal("expected error for rule with no actions")
	}
	if want := "#1"; !strings.Contains(err.Error(), want) {
		t.Errorf("error %q should reference rule %s", err.Error(), want)
	}
}
