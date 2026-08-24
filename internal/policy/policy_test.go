package policy

import (
	"testing"

	"github.com/amdadulbari/dockgate/internal/dockerapi"
)

const samplePolicy = `
default_action: deny
rules:
  - name: "read only"
    effect: allow
    actions:
      - system.*
      - container.list
      - container.inspect
  - name: "lifecycle"
    effect: allow
    actions: [container.start, container.stop]
  - name: "hardened create"
    effect: allow
    actions: [container.create]
    allowed_images: ["nginx", "redis:*"]
    deny_privileged: true
    deny_host_network: true
    deny_bind_mounts: true
    denied_capabilities: [ALL]
  - name: "no exec"
    effect: deny
    actions: [container.exec, exec.start]
`

func mustPolicy(t *testing.T, src string) *Policy {
	t.Helper()
	p, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return p
}

func eval(p *Policy, action string, spec dockerapi.CreateSpec) Decision {
	return p.Evaluate(Request{Action: dockerapi.Action(action), Spec: spec})
}

func TestDefaultDeny(t *testing.T) {
	p := mustPolicy(t, samplePolicy)
	d := eval(p, "network.create", dockerapi.CreateSpec{})
	if d.Allowed {
		t.Errorf("network.create should be denied by default, got %+v", d)
	}
}

func TestCategoryWildcard(t *testing.T) {
	p := mustPolicy(t, samplePolicy)
	if d := eval(p, "system.info", dockerapi.CreateSpec{}); !d.Allowed {
		t.Errorf("system.info should match system.*, got %+v", d)
	}
}

func TestExplicitDenyWins(t *testing.T) {
	p := mustPolicy(t, samplePolicy)
	if d := eval(p, "container.exec", dockerapi.CreateSpec{}); d.Allowed {
		t.Errorf("container.exec should be denied, got %+v", d)
	}
}

func TestCreateAllowed(t *testing.T) {
	p := mustPolicy(t, samplePolicy)
	d := eval(p, "container.create", dockerapi.CreateSpec{Image: "nginx:1.25"})
	if !d.Allowed {
		t.Errorf("nginx create should be allowed, got %+v", d)
	}
}

func TestCreateImageNotAllowed(t *testing.T) {
	p := mustPolicy(t, samplePolicy)
	d := eval(p, "container.create", dockerapi.CreateSpec{Image: "ubuntu:latest"})
	if d.Allowed {
		t.Errorf("ubuntu create should be denied, got %+v", d)
	}
	if d.Rule != "hardened create" {
		t.Errorf("expected denial attributed to the create rule, got rule=%q", d.Rule)
	}
}

func TestCreatePrivilegedDenied(t *testing.T) {
	p := mustPolicy(t, samplePolicy)
	d := eval(p, "container.create", dockerapi.CreateSpec{Image: "nginx", Privileged: true})
	if d.Allowed {
		t.Errorf("privileged create should be denied, got %+v", d)
	}
}

func TestCreateHostNetworkDenied(t *testing.T) {
	p := mustPolicy(t, samplePolicy)
	d := eval(p, "container.create", dockerapi.CreateSpec{Image: "nginx", NetworkMode: "host"})
	if d.Allowed {
		t.Errorf("host-network create should be denied, got %+v", d)
	}
}

func TestCreateBindMountDenied(t *testing.T) {
	p := mustPolicy(t, samplePolicy)
	d := eval(p, "container.create", dockerapi.CreateSpec{Image: "nginx", BindMounts: []string{"/var/run/docker.sock"}})
	if d.Allowed {
		t.Errorf("bind-mount create should be denied, got %+v", d)
	}
}

func TestCreateCapabilityDenied(t *testing.T) {
	p := mustPolicy(t, samplePolicy)
	d := eval(p, "container.create", dockerapi.CreateSpec{Image: "nginx", CapAdd: []string{"SYS_ADMIN"}})
	if d.Allowed {
		t.Errorf("added capability should be denied by ALL, got %+v", d)
	}
}

func TestDefaultActionDefaultsToDeny(t *testing.T) {
	p := mustPolicy(t, "rules: []")
	if p.DefaultAction != Deny {
		t.Errorf("default_action should default to deny, got %q", p.DefaultAction)
	}
	if d := eval(p, "container.list", dockerapi.CreateSpec{}); d.Allowed {
		t.Errorf("empty policy should deny everything, got %+v", d)
	}
}

func TestAllowAllDefault(t *testing.T) {
	p := mustPolicy(t, "default_action: allow\nrules: []")
	if d := eval(p, "container.remove", dockerapi.CreateSpec{}); !d.Allowed {
		t.Errorf("default_action allow should permit unmatched actions, got %+v", d)
	}
}

func TestParseRejectsUnknownKeys(t *testing.T) {
	_, err := Parse([]byte("default_action: deny\nbogus_key: true\n"))
	if err == nil {
		t.Error("expected error for unknown top-level key")
	}
}

func TestParseRejectsBadDefault(t *testing.T) {
	if _, err := Parse([]byte("default_action: maybe\n")); err == nil {
		t.Error("expected error for invalid default_action")
	}
}

func TestParseRejectsRuleWithoutActions(t *testing.T) {
	src := "rules:\n  - name: x\n    effect: allow\n"
	if _, err := Parse([]byte(src)); err == nil {
		t.Error("expected error for rule with no actions")
	}
}
