package policy

import (
	"strings"
	"testing"

	"github.com/amdadulbari/dockgate/internal/dockerapi"
)

func evalA(p *Policy, action string, spec dockerapi.CreateSpec) Decision {
	return p.Evaluate(Request{Action: dockerapi.Action(action), Spec: spec})
}

func TestStarWildcardMatchesEverything(t *testing.T) {
	p := mustPolicy(t, "rules:\n  - name: all\n    effect: allow\n    actions: ['*']")
	for _, a := range []string{"container.create", "swarm.init", "unknown", "volume.remove"} {
		if d := evalA(p, a, dockerapi.CreateSpec{}); !d.Allowed {
			t.Errorf("'*' should allow %s, got %+v", a, d)
		}
	}
}

func TestFirstMatchWins_DenyBeforeAllow(t *testing.T) {
	src := `
rules:
  - name: block-exec
    effect: deny
    actions: [container.exec]
  - name: allow-all-container
    effect: allow
    actions: [container.*]
`
	p := mustPolicy(t, src)
	if d := evalA(p, "container.exec", dockerapi.CreateSpec{}); d.Allowed {
		t.Errorf("earlier deny rule must win, got %+v", d)
	}
	if d := evalA(p, "container.list", dockerapi.CreateSpec{}); !d.Allowed {
		t.Errorf("container.list should hit the allow rule, got %+v", d)
	}
}

func TestConstraintsIgnoredForNonCreateActions(t *testing.T) {
	// A single allow rule with create-style constraints also covering start.
	// The constraints must NOT block a non-create action.
	src := `
rules:
  - name: mixed
    effect: allow
    actions: [container.start, container.create]
    allowed_images: [nginx]
    deny_privileged: true
`
	p := mustPolicy(t, src)
	if d := evalA(p, "container.start", dockerapi.CreateSpec{}); !d.Allowed {
		t.Errorf("start should be allowed regardless of create constraints, got %+v", d)
	}
	// But create with a bad image is still blocked.
	if d := evalA(p, "container.create", dockerapi.CreateSpec{Image: "ubuntu"}); d.Allowed {
		t.Errorf("create with disallowed image should be denied, got %+v", d)
	}
}

func TestDenyRuleIgnoresConstraints(t *testing.T) {
	// A deny rule denies outright even if a create would satisfy constraints.
	src := `
rules:
  - name: no-create
    effect: deny
    actions: [container.create]
    allowed_images: [nginx]
`
	p := mustPolicy(t, src)
	d := evalA(p, "container.create", dockerapi.CreateSpec{Image: "nginx"})
	if d.Allowed {
		t.Errorf("deny rule must deny even a compliant create, got %+v", d)
	}
	if d.Rule != "no-create" {
		t.Errorf("expected denial attributed to the deny rule, got %q", d.Rule)
	}
}

func TestHostPidAndIpcDenied(t *testing.T) {
	src := `
rules:
  - name: create
    effect: allow
    actions: [container.create]
    deny_host_pid: true
    deny_host_ipc: true
`
	p := mustPolicy(t, src)
	if d := evalA(p, "container.create", dockerapi.CreateSpec{Image: "x", PidMode: "host"}); d.Allowed {
		t.Errorf("host PID should be denied, got %+v", d)
	}
	if d := evalA(p, "container.create", dockerapi.CreateSpec{Image: "x", IpcMode: "host"}); d.Allowed {
		t.Errorf("host IPC should be denied, got %+v", d)
	}
	// A container using neither is fine.
	if d := evalA(p, "container.create", dockerapi.CreateSpec{Image: "x", PidMode: "container:abc"}); !d.Allowed {
		t.Errorf("non-host PID mode should be allowed, got %+v", d)
	}
}

func TestDeniedCapabilitySpecificAndAll(t *testing.T) {
	src := `
rules:
  - name: create
    effect: allow
    actions: [container.create]
    denied_capabilities: [NET_ADMIN]
`
	p := mustPolicy(t, src)
	// Specific denied cap blocks.
	if d := evalA(p, "container.create", dockerapi.CreateSpec{Image: "x", CapAdd: []string{"NET_ADMIN"}}); d.Allowed {
		t.Errorf("NET_ADMIN should be denied, got %+v", d)
	}
	// A different cap is allowed.
	if d := evalA(p, "container.create", dockerapi.CreateSpec{Image: "x", CapAdd: []string{"CHOWN"}}); !d.Allowed {
		t.Errorf("CHOWN should be allowed, got %+v", d)
	}
	// Requesting ALL is always blocked when any deny list is set.
	if d := evalA(p, "container.create", dockerapi.CreateSpec{Image: "x", CapAdd: []string{"ALL"}}); d.Allowed {
		t.Errorf("CapAdd ALL should be denied, got %+v", d)
	}
}

func TestUnnamedRuleDenialReason(t *testing.T) {
	src := "rules:\n  - effect: deny\n    actions: [container.exec]"
	p := mustPolicy(t, src)
	d := evalA(p, "container.exec", dockerapi.CreateSpec{})
	if d.Allowed {
		t.Fatalf("should be denied")
	}
	if d.Rule != "#1" {
		t.Errorf("unnamed rule should display as #1, got %q", d.Rule)
	}
	if !strings.Contains(d.Reason, "#1") {
		t.Errorf("reason should reference the rule, got %q", d.Reason)
	}
}

func TestEmptyImageWithAllowList(t *testing.T) {
	src := "rules:\n  - effect: allow\n    actions: [container.create]\n    allowed_images: [nginx]"
	p := mustPolicy(t, src)
	// A create with no image cannot satisfy an allow-list.
	if d := evalA(p, "container.create", dockerapi.CreateSpec{Image: ""}); d.Allowed {
		t.Errorf("empty image should not match an allow-list, got %+v", d)
	}
}

func TestImageAllowedRegistryPortConvenience(t *testing.T) {
	// A registry host:port in the pattern must not be mistaken for a tag, so the
	// bare-name convenience still applies.
	if !imageAllowed("localhost:5000/nginx:1.2", []string{"localhost:5000/nginx"}) {
		t.Error("localhost:5000/nginx should match any tag of that repo")
	}
	if imageAllowed("localhost:5000/redis:1", []string{"localhost:5000/nginx"}) {
		t.Error("different repo should not match")
	}
}

func TestNoRulesMatchFallsThroughToDefault(t *testing.T) {
	src := "default_action: allow\nrules:\n  - name: deny-exec\n    effect: deny\n    actions: [container.exec]"
	p := mustPolicy(t, src)
	// container.list matches no rule -> default allow.
	if d := evalA(p, "container.list", dockerapi.CreateSpec{}); !d.Allowed {
		t.Errorf("unmatched action should hit default allow, got %+v", d)
	}
	// container.exec is explicitly denied even under default allow.
	if d := evalA(p, "container.exec", dockerapi.CreateSpec{}); d.Allowed {
		t.Errorf("explicit deny should override default allow, got %+v", d)
	}
}
