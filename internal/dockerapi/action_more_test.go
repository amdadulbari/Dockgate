package dockerapi

import "testing"

func TestClassifyMoreRoutes(t *testing.T) {
	cases := []struct {
		method, path string
		want         Action
	}{
		{"get", "/containers/json", "container.list"}, // lowercase method
		{"POST", "/containers/abc/rename?name=y", "container.rename"},
		{"POST", "/containers/abc/update", "container.update"},
		{"POST", "/containers/abc/resize", "container.resize"},
		{"POST", "/containers/abc/wait", "container.wait"},
		{"POST", "/containers/abc/attach", "container.attach"},
		{"GET", "/containers/abc/changes", "container.changes"},
		{"GET", "/containers/abc/export", "container.export"},
		{"POST", "/containers/prune", "container.prune"},
		{"POST", "/exec/abc/resize", "exec.resize"},
		{"GET", "/exec/abc/json", "exec.inspect"},
		{"POST", "/images/nginx/tag", "image.tag"},
		{"POST", "/images/nginx/push", "image.push"},
		{"GET", "/images/nginx/get", "image.save"},
		{"POST", "/images/load", "image.load"},
		{"GET", "/images/search?term=x", "image.search"},
		{"POST", "/images/prune", "image.prune"},
		{"POST", "/commit", "image.commit"},
		{"GET", "/networks/abc", "network.inspect"},
		{"POST", "/networks/abc/connect", "network.connect"},
		{"POST", "/networks/abc/disconnect", "network.disconnect"},
		{"DELETE", "/networks/abc", "network.remove"},
		{"POST", "/networks/prune", "network.prune"},
		{"GET", "/volumes/myvol", "volume.inspect"},
		{"DELETE", "/volumes/myvol", "volume.remove"},
		{"POST", "/volumes/prune", "volume.prune"},
		{"GET", "/system/df", "system.df"},
		{"GET", "/events", "system.events"},
		{"POST", "/auth", "system.auth"},
		{"GET", "/services", "service.list"},
		{"POST", "/secrets/create", "secret.create"},
		{"GET", "/configs", "config.list"},
		// Method mismatch and unknown paths fall through.
		{"PATCH", "/containers/json", ActionUnknown},
		{"GET", "/", ActionUnknown},
		{"GET", "/totally/unknown", ActionUnknown},
	}
	for _, c := range cases {
		if got := Classify(c.method, c.path); got != c.want {
			t.Errorf("Classify(%q, %q) = %q, want %q", c.method, c.path, got, c.want)
		}
	}
}

func TestParseCreateSpecNamedVolumesExcluded(t *testing.T) {
	body := []byte(`{
		"Image": "app",
		"HostConfig": {
			"Binds": ["data:/var/lib/data", "/host/logs:/logs"],
			"Mounts": [
				{"Type": "volume", "Source": "cache"},
				{"Type": "bind", "Source": "/host/conf"}
			]
		}
	}`)
	spec, err := ParseCreateSpec(body)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, b := range spec.BindMounts {
		got[b] = true
	}
	// Host binds are kept; named volumes ("data", "cache") are not.
	if !got["/host/logs"] || !got["/host/conf"] {
		t.Errorf("host binds missing: %v", spec.BindMounts)
	}
	if got["data"] || got["cache"] {
		t.Errorf("named volumes should be excluded: %v", spec.BindMounts)
	}
	if len(spec.BindMounts) != 2 {
		t.Errorf("expected exactly 2 host binds, got %v", spec.BindMounts)
	}
}

func TestParseCreateSpecCapAndUser(t *testing.T) {
	spec, err := ParseCreateSpec([]byte(`{"Image":"x","User":"1000:1000","HostConfig":{"CapAdd":["", "cap_net_raw", "SYS_TIME"]}}`))
	if err != nil {
		t.Fatal(err)
	}
	if spec.User != "1000:1000" {
		t.Errorf("User = %q", spec.User)
	}
	// Empty entries dropped; CAP_ prefix stripped; upper-cased.
	want := map[string]bool{"NET_RAW": true, "SYS_TIME": true}
	if len(spec.CapAdd) != 2 {
		t.Fatalf("CapAdd = %v, want 2 entries", spec.CapAdd)
	}
	for _, c := range spec.CapAdd {
		if !want[c] {
			t.Errorf("unexpected capability %q", c)
		}
	}
}

func TestParseCreateSpecWhitespaceBody(t *testing.T) {
	spec, err := ParseCreateSpec([]byte("   \n\t "))
	if err != nil {
		t.Fatalf("whitespace body should not error: %v", err)
	}
	if spec.Image != "" {
		t.Errorf("expected empty spec, got %+v", spec)
	}
}
