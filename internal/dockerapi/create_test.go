package dockerapi

import "testing"

func TestParseCreateSpec(t *testing.T) {
	body := []byte(`{
		"Image": "nginx:1.25",
		"User": "1000",
		"HostConfig": {
			"Privileged": true,
			"NetworkMode": "host",
			"PidMode": "host",
			"IpcMode": "host",
			"Binds": ["/etc:/host-etc:ro", "namedvol:/data"],
			"CapAdd": ["cap_sys_admin", "NET_ADMIN"],
			"Mounts": [
				{"Type": "bind", "Source": "/var/run/docker.sock"},
				{"Type": "volume", "Source": "myvol"}
			]
		}
	}`)

	spec, err := ParseCreateSpec(body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if spec.Image != "nginx:1.25" {
		t.Errorf("Image = %q", spec.Image)
	}
	if !spec.Privileged {
		t.Error("Privileged should be true")
	}
	if spec.NetworkMode != "host" || spec.PidMode != "host" || spec.IpcMode != "host" {
		t.Errorf("namespace modes = %q/%q/%q", spec.NetworkMode, spec.PidMode, spec.IpcMode)
	}
	// Only host binds; the named volume "namedvol:/data" must be excluded.
	wantBinds := map[string]bool{"/etc": true, "/var/run/docker.sock": true}
	if len(spec.BindMounts) != len(wantBinds) {
		t.Fatalf("BindMounts = %v, want %v", spec.BindMounts, wantBinds)
	}
	for _, b := range spec.BindMounts {
		if !wantBinds[b] {
			t.Errorf("unexpected bind mount %q", b)
		}
	}
	// Capabilities normalised to bare upper-case.
	wantCaps := map[string]bool{"SYS_ADMIN": true, "NET_ADMIN": true}
	for _, c := range spec.CapAdd {
		if !wantCaps[c] {
			t.Errorf("unexpected capability %q", c)
		}
	}
}

func TestParseCreateSpecEmpty(t *testing.T) {
	spec, err := ParseCreateSpec(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if spec.Image != "" || spec.Privileged {
		t.Errorf("expected zero-value spec, got %+v", spec)
	}
}

func TestParseCreateSpecMalformed(t *testing.T) {
	if _, err := ParseCreateSpec([]byte(`{not json`)); err == nil {
		t.Error("expected error for malformed body")
	}
}
