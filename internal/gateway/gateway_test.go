package gateway

import (
	"bytes"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/amdadulbari/dockgate/internal/audit"
	"github.com/amdadulbari/dockgate/internal/policy"
	"github.com/amdadulbari/dockgate/internal/proxy"
)

const testPolicy = `
default_action: deny
rules:
  - name: read
    effect: allow
    actions: [container.list]
  - name: create
    effect: allow
    actions: [container.create]
    allowed_images: [nginx]
    deny_privileged: true
`

// fakeDocker starts an HTTP server on a Unix socket that echoes "upstream-ok"
// for any request, standing in for the real Docker Engine.
func fakeDocker(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	sock := filepath.Join(dir, "docker.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "upstream-ok")
	})}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return sock
}

func newTestGateway(t *testing.T) *Gateway {
	t.Helper()
	pol, err := policy.Parse([]byte(testPolicy))
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	sock := fakeDocker(t)
	up := proxy.New(sock)
	auditor := audit.New(io.Discard)
	return New(pol, auditor, up, log.New(os.Stderr, "", 0))
}

func do(g *Gateway, method, target string, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	rec := httptest.NewRecorder()
	g.ServeHTTP(rec, req)
	return rec
}

func TestGatewayAllowsListAndProxies(t *testing.T) {
	g := newTestGateway(t)
	rec := do(g, "GET", "/containers/json", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := rec.Body.String(); got != "upstream-ok" {
		t.Errorf("body = %q, want upstream-ok", got)
	}
}

func TestGatewayDeniesByDefault(t *testing.T) {
	g := newTestGateway(t)
	rec := do(g, "POST", "/networks/create", `{}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "denied") {
		t.Errorf("body should explain denial: %q", rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("content-type = %q, want application/json", ct)
	}
}

func TestGatewayAllowsCompliantCreate(t *testing.T) {
	g := newTestGateway(t)
	rec := do(g, "POST", "/containers/create", `{"Image":"nginx:1.25"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
}

func TestGatewayDeniesPrivilegedCreate(t *testing.T) {
	g := newTestGateway(t)
	rec := do(g, "POST", "/containers/create", `{"Image":"nginx","HostConfig":{"Privileged":true}}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "privileged") {
		t.Errorf("expected privileged denial, got %q", rec.Body.String())
	}
}

func TestGatewayDeniesDisallowedImageCreate(t *testing.T) {
	g := newTestGateway(t)
	rec := do(g, "POST", "/containers/create", `{"Image":"ubuntu:22.04"}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

func TestGatewayFailsClosedOnMalformedCreate(t *testing.T) {
	g := newTestGateway(t)
	rec := do(g, "POST", "/containers/create", `{not valid json`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestGatewayForwardsCreateBodyIntact(t *testing.T) {
	// Verify the buffered body is fully replayed upstream.
	dir := t.TempDir()
	sock := filepath.Join(dir, "docker.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	var received bytes.Buffer
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(&received, r.Body)
		w.WriteHeader(http.StatusCreated)
	})}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })

	pol, _ := policy.Parse([]byte(testPolicy))
	g := New(pol, audit.New(io.Discard), proxy.New(sock), log.New(io.Discard, "", 0))

	payload := `{"Image":"nginx:1.25","Env":["A=1"]}`
	rec := do(g, "POST", "/containers/create", payload)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 (body=%s)", rec.Code, rec.Body.String())
	}
	if received.String() != payload {
		t.Errorf("upstream got %q, want %q", received.String(), payload)
	}
}
