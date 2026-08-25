package config

import "testing"

func TestDefaults(t *testing.T) {
	d := Defaults()
	if d.Listen != "127.0.0.1:2375" {
		t.Errorf("default Listen = %q", d.Listen)
	}
	if d.DockerSocket != "/var/run/docker.sock" {
		t.Errorf("default DockerSocket = %q", d.DockerSocket)
	}
	if d.PolicyPath != "policy.yaml" || d.AuditLog != "-" {
		t.Errorf("unexpected defaults: %+v", d)
	}
}

func TestLoadUsesDefaults(t *testing.T) {
	// Ensure no env leaks into this test.
	for _, k := range []string{"DOCKGATE_LISTEN", "DOCKGATE_DOCKER_SOCKET", "DOCKGATE_POLICY", "DOCKGATE_AUDIT_LOG"} {
		t.Setenv(k, "")
	}
	cfg, err := Load(nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg != Defaults() {
		t.Errorf("Load(nil) = %+v, want defaults", cfg)
	}
}

func TestLoadFlagsOverrideEnv(t *testing.T) {
	t.Setenv("DOCKGATE_LISTEN", "0.0.0.0:9999")
	t.Setenv("DOCKGATE_POLICY", "/env/policy.yaml")

	// Env is picked up when no flag is given.
	cfg, err := Load(nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Listen != "0.0.0.0:9999" || cfg.PolicyPath != "/env/policy.yaml" {
		t.Errorf("env not applied: %+v", cfg)
	}

	// A flag overrides the env fallback.
	cfg, err = Load([]string{"--listen", "127.0.0.1:1234", "--policy", "/flag/policy.yaml"})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Listen != "127.0.0.1:1234" || cfg.PolicyPath != "/flag/policy.yaml" {
		t.Errorf("flag did not override env: %+v", cfg)
	}
}

func TestLoadUnknownFlagErrors(t *testing.T) {
	if _, err := Load([]string{"--nope"}); err == nil {
		t.Error("expected error for unknown flag")
	}
}

func TestLoadEmptyValuesFailValidation(t *testing.T) {
	if _, err := Load([]string{"--listen", ""}); err == nil {
		t.Error("empty --listen should fail validation")
	}
	if _, err := Load([]string{"--docker-socket", ""}); err == nil {
		t.Error("empty --docker-socket should fail validation")
	}
	if _, err := Load([]string{"--policy", ""}); err == nil {
		t.Error("empty --policy should fail validation")
	}
}

func TestListenNetwork(t *testing.T) {
	cases := []struct {
		listen, wantNet, wantAddr string
	}{
		{"127.0.0.1:2375", "tcp", "127.0.0.1:2375"},
		{"0.0.0.0:2375", "tcp", "0.0.0.0:2375"},
		{"tcp://10.0.0.1:2375", "tcp", "10.0.0.1:2375"},
		{"unix:///var/run/dockgate.sock", "unix", "/var/run/dockgate.sock"},
		{"unix://relative.sock", "unix", "relative.sock"},
	}
	for _, c := range cases {
		net, addr := Config{Listen: c.listen}.ListenNetwork()
		if net != c.wantNet || addr != c.wantAddr {
			t.Errorf("ListenNetwork(%q) = (%q,%q), want (%q,%q)", c.listen, net, addr, c.wantNet, c.wantAddr)
		}
	}
}
