package dockerapi

import "testing"

func TestClassify(t *testing.T) {
	cases := []struct {
		method, path string
		want         Action
	}{
		{"GET", "/_ping", "system.ping"},
		{"GET", "/v1.43/_ping", "system.ping"},
		{"GET", "/v1.48/version", "system.version"},
		{"GET", "/containers/json", "container.list"},
		{"GET", "/containers/json?all=1&filters=%7B%7D", "container.list"},
		{"POST", "/v1.43/containers/create", "container.create"},
		{"POST", "/containers/create?name=web", "container.create"},
		{"GET", "/containers/abc123/json", "container.inspect"},
		{"GET", "/containers/abc123/logs?follow=1", "container.logs"},
		{"POST", "/containers/abc123/start", "container.start"},
		{"POST", "/containers/abc123/stop", "container.stop"},
		{"POST", "/containers/abc123/exec", "container.exec"},
		{"POST", "/exec/def456/start", "exec.start"},
		{"DELETE", "/containers/abc123", "container.remove"},
		{"DELETE", "/v1.43/containers/abc123?force=1", "container.remove"},
		{"POST", "/images/create?fromImage=nginx&tag=latest", "image.pull"},
		{"GET", "/images/json", "image.list"},
		{"POST", "/build", "image.build"},
		{"DELETE", "/images/nginx:latest", "image.remove"},
		{"GET", "/networks", "network.list"},
		{"POST", "/networks/create", "network.create"},
		{"GET", "/volumes", "volume.list"},
		{"POST", "/swarm/init", "swarm.init"},
		{"GET", "/containers/abc123/json/", "container.inspect"}, // trailing slash
		{"GET", "/nonsense/path", ActionUnknown},
		{"POST", "/containers/json", ActionUnknown}, // wrong method
		{"PUT", "/containers/abc/archive", "container.archive.write"},
		{"GET", "/containers/abc/archive", "container.archive.read"},
	}

	for _, c := range cases {
		if got := Classify(c.method, c.path); got != c.want {
			t.Errorf("Classify(%q, %q) = %q, want %q", c.method, c.path, got, c.want)
		}
	}
}

func TestActionCategory(t *testing.T) {
	if got := Action("container.create").Category(); got != "container" {
		t.Errorf("Category = %q, want container", got)
	}
	if got := ActionUnknown.Category(); got != "unknown" {
		t.Errorf("Category = %q, want unknown", got)
	}
}

func TestNeedsBodyInspection(t *testing.T) {
	if !Action("container.create").NeedsBodyInspection() {
		t.Error("container.create should need body inspection")
	}
	if Action("container.start").NeedsBodyInspection() {
		t.Error("container.start should not need body inspection")
	}
}
