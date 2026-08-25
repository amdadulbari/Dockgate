package proxy

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestProxyForwardsToUnixSocket(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "d.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	var gotHost, gotPath string
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
		gotPath = r.URL.Path
		io.WriteString(w, "ok")
	})}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })

	p := New(sock)
	req := httptest.NewRequest("GET", "/v1.43/containers/json", nil)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK || rec.Body.String() != "ok" {
		t.Fatalf("proxy did not forward: code=%d body=%q", rec.Code, rec.Body.String())
	}
	if gotPath != "/v1.43/containers/json" {
		t.Errorf("upstream path = %q", gotPath)
	}
	if gotHost != "docker" {
		t.Errorf("upstream Host = %q, want rewritten to docker", gotHost)
	}
}

func TestProxyErrorHandlerWhenEngineDown(t *testing.T) {
	// Point at a socket that nothing is listening on.
	p := New(filepath.Join(t.TempDir(), "missing.sock"))
	req := httptest.NewRequest("GET", "/_ping", nil)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("code = %d, want 502", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("content-type = %q, want application/json", ct)
	}
	if !strings.Contains(rec.Body.String(), "dockgate") {
		t.Errorf("error body should mention dockgate: %q", rec.Body.String())
	}
}
