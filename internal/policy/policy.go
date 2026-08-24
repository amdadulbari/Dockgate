// Package policy loads and evaluates DockGate's security policy. A policy is a
// default action plus an ordered list of rules. Evaluation is deterministic and
// fail-closed: the first rule whose actions match the request decides the
// outcome, and if that rule allows the action its optional constraints must all
// pass or the request is denied.
package policy

import (
	"fmt"
	"os"
	"strings"

	"github.com/amdadulbari/dockgate/internal/dockerapi"
	"gopkg.in/yaml.v3"
)

// Effect is a rule's disposition.
type Effect string

const (
	Allow Effect = "allow"
	Deny  Effect = "deny"
)

// Policy is the top-level configuration DockGate enforces.
type Policy struct {
	// DefaultAction applies when no rule matches a request. Defaults to Deny.
	DefaultAction Effect `yaml:"default_action"`
	// Rules are evaluated top-to-bottom; the first match wins.
	Rules []Rule `yaml:"rules"`
}

// Rule matches one or more actions and, when it allows them, may impose
// constraints on container-create requests.
type Rule struct {
	// Name is a human-readable label surfaced in audit logs and denial messages.
	Name string `yaml:"name"`
	// Actions is a list of action patterns. Each entry is either an exact action
	// ("container.create"), a category wildcard ("container.*"), or "*" for any
	// action.
	Actions []string `yaml:"actions"`
	// Effect is "allow" or "deny". Defaults to "allow" when omitted.
	Effect Effect `yaml:"effect"`

	// The fields below constrain "allow" rules for container.create. They are
	// ignored for other actions and for deny rules.

	// AllowedImages, when non-empty, restricts the container image to references
	// matching one of these glob patterns (e.g. "nginx", "redis:*",
	// "ghcr.io/acme/*"). A bare name with no tag or wildcard also matches any
	// tag of that repository.
	AllowedImages []string `yaml:"allowed_images"`
	// DeniedCapabilities lists Linux capabilities that may not be added
	// (e.g. "SYS_ADMIN", "NET_ADMIN", or "ALL").
	DeniedCapabilities []string `yaml:"denied_capabilities"`
	// DenyPrivileged rejects privileged containers.
	DenyPrivileged bool `yaml:"deny_privileged"`
	// DenyHostNetwork rejects containers using the host network namespace.
	DenyHostNetwork bool `yaml:"deny_host_network"`
	// DenyHostPID rejects containers sharing the host PID namespace.
	DenyHostPID bool `yaml:"deny_host_pid"`
	// DenyHostIPC rejects containers sharing the host IPC namespace.
	DenyHostIPC bool `yaml:"deny_host_ipc"`
	// DenyBindMounts rejects containers mounting host paths.
	DenyBindMounts bool `yaml:"deny_bind_mounts"`
}

// Request is the classified operation handed to the policy engine. Spec is only
// populated for actions that carry an inspectable body (container.create).
type Request struct {
	Action dockerapi.Action
	Spec   dockerapi.CreateSpec
}

// Decision is the result of evaluating a Request against a Policy.
type Decision struct {
	Allowed bool
	// Rule is the name of the matching rule, or "" when the default action
	// decided the outcome.
	Rule string
	// Reason is a short human-readable explanation, always set.
	Reason string
}

// Load reads, parses and validates a policy from a YAML file.
func Load(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy: %w", err)
	}
	return Parse(data)
}

// Parse decodes and validates a policy from YAML bytes.
func Parse(data []byte) (*Policy, error) {
	var p Policy
	// Reject unknown keys so typos in a security policy fail loudly.
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("parse policy: %w", err)
	}
	if err := p.normalizeAndValidate(); err != nil {
		return nil, err
	}
	return &p, nil
}

func (p *Policy) normalizeAndValidate() error {
	if p.DefaultAction == "" {
		p.DefaultAction = Deny
	}
	if p.DefaultAction != Allow && p.DefaultAction != Deny {
		return fmt.Errorf("invalid default_action %q (want allow or deny)", p.DefaultAction)
	}
	for i := range p.Rules {
		r := &p.Rules[i]
		if r.Effect == "" {
			r.Effect = Allow
		}
		if r.Effect != Allow && r.Effect != Deny {
			return fmt.Errorf("rule %q: invalid effect %q (want allow or deny)", r.displayName(i), r.Effect)
		}
		if len(r.Actions) == 0 {
			return fmt.Errorf("rule %q: must list at least one action", r.displayName(i))
		}
	}
	return nil
}

func (r *Rule) displayName(idx int) string {
	if r.Name != "" {
		return r.Name
	}
	return fmt.Sprintf("#%d", idx+1)
}

// Evaluate applies the policy to a request and returns the decision.
func (p *Policy) Evaluate(req Request) Decision {
	for i := range p.Rules {
		r := &p.Rules[i]
		if !r.matches(req.Action) {
			continue
		}
		name := r.displayName(i)

		if r.Effect == Deny {
			return Decision{Allowed: false, Rule: name, Reason: "denied by rule " + quote(name)}
		}

		// Allow rule: enforce any constraints (only meaningful for create).
		if req.Action == "container.create" {
			if reason, ok := r.checkCreate(req.Spec); !ok {
				return Decision{Allowed: false, Rule: name, Reason: reason}
			}
		}
		return Decision{Allowed: true, Rule: name, Reason: "allowed by rule " + quote(name)}
	}

	// No rule matched: fall back to the default action.
	if p.DefaultAction == Allow {
		return Decision{Allowed: true, Reason: "allowed by default_action"}
	}
	return Decision{Allowed: false, Reason: "denied by default_action (no matching rule)"}
}

// matches reports whether the rule applies to the given action.
func (r *Rule) matches(a dockerapi.Action) bool {
	action := string(a)
	for _, pat := range r.Actions {
		pat = strings.TrimSpace(pat)
		switch {
		case pat == "*":
			return true
		case strings.HasSuffix(pat, ".*"):
			if a.Category() == strings.TrimSuffix(pat, ".*") {
				return true
			}
		case pat == action:
			return true
		}
	}
	return false
}

// checkCreate enforces an allow rule's constraints against a create spec.
// It returns a denial reason and false on the first violated constraint.
func (r *Rule) checkCreate(spec dockerapi.CreateSpec) (string, bool) {
	if len(r.AllowedImages) > 0 && !imageAllowed(spec.Image, r.AllowedImages) {
		return fmt.Sprintf("image %q is not in the allowed_images list", spec.Image), false
	}
	if r.DenyPrivileged && spec.Privileged {
		return "privileged containers are not permitted", false
	}
	if r.DenyHostNetwork && strings.EqualFold(spec.NetworkMode, "host") {
		return "host network mode is not permitted", false
	}
	if r.DenyHostPID && strings.EqualFold(spec.PidMode, "host") {
		return "host PID namespace is not permitted", false
	}
	if r.DenyHostIPC && strings.EqualFold(spec.IpcMode, "host") {
		return "host IPC namespace is not permitted", false
	}
	if r.DenyBindMounts && len(spec.BindMounts) > 0 {
		return fmt.Sprintf("host bind mounts are not permitted (%s)", strings.Join(spec.BindMounts, ", ")), false
	}
	if len(r.DeniedCapabilities) > 0 {
		if cap, blocked := deniedCapability(spec.CapAdd, r.DeniedCapabilities); blocked {
			return fmt.Sprintf("capability %q is not permitted", cap), false
		}
	}
	return "", true
}

// deniedCapability reports the first added capability that the deny list
// forbids. "ALL" in either list is treated as matching everything.
func deniedCapability(added, denied []string) (string, bool) {
	deny := make(map[string]bool, len(denied))
	denyAll := false
	for _, d := range denied {
		d = strings.ToUpper(strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(d)), "CAP_"))
		if d == "ALL" {
			denyAll = true
		}
		deny[d] = true
	}
	for _, c := range added {
		if c == "ALL" || denyAll || deny[c] {
			return c, true
		}
	}
	return "", false
}

// strconv wraps a rule name in quotes for readable messages without importing
// the fmt verb everywhere.
func quote(name string) string {
	if name == "" {
		return "(unnamed)"
	}
	return "\"" + name + "\""
}
