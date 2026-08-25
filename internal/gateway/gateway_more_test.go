package gateway

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/amdadulbari/dockgate/internal/audit"
	"github.com/amdadulbari/dockgate/internal/policy"
	"github.com/amdadulbari/dockgate/internal/proxy"
)

// gatewayWithAudit builds a gateway whose audit log is captured in buf.
func gatewayWithAudit(t *testing.T, pol *policy.Policy, buf *bytes.Buffer) *Gateway {
	t.Helper()
	sock := fakeDocker(t)
	return New(pol, audit.New(buf), proxy.New(sock), log.New(io.Discard, "", 0))
}

func TestUnknownActionDeniedByDefault(t *testing.T) {
	pol, _ := policy.Parse([]byte(testPolicy))
	g := gatewayWithAudit(t, pol, &bytes.Buffer{})
	// A path DockGate does not recognise classifies as "unknown".
	rec := do(g, "GET", "/some/unknown/endpoint", "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("unknown action should be denied, code=%d", rec.Code)
	}
}

func TestCreateBodyTooLargeRejected(t *testing.T) {
	pol, _ := policy.Parse([]byte(testPolicy))
	g := gatewayWithAudit(t, pol, &bytes.Buffer{})
	big := `{"Image":"nginx","x":"` + strings.Repeat("a", maxCreateBody+16) + `"}`
	rec := do(g, "POST", "/containers/create", big)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized create body should be 413, got %d", rec.Code)
	}
}

func TestCreateBodyAtLimitAllowed(t *testing.T) {
	pol, _ := policy.Parse([]byte(testPolicy))
	g := gatewayWithAudit(t, pol, &bytes.Buffer{})
	// Pad an otherwise-valid create body to just under the cap.
	base := `{"Image":"nginx","pad":"%s"}`
	padLen := maxCreateBody - len(base) // safely under the limit
	body := strings.Replace(base, "%s", strings.Repeat("a", padLen), 1)
	if len(body) > maxCreateBody {
		t.Fatalf("test body %d exceeds cap %d", len(body), maxCreateBody)
	}
	rec := do(g, "POST", "/containers/create", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("create at/under the limit should be allowed, got %d (%s)", rec.Code, rec.Body.String())
	}
}

func TestNonCreateBodyNotSizeLimited(t *testing.T) {
	// A large body on a non-create endpoint must stream through untouched (it is
	// never buffered), so the create size cap does not apply.
	pol, _ := policy.Parse([]byte(testPolicy))
	g := gatewayWithAudit(t, pol, &bytes.Buffer{})
	rec := do(g, "GET", "/containers/json", strings.Repeat("x", maxCreateBody*2))
	if rec.Code != http.StatusOK {
		t.Fatalf("large non-create request should pass, got %d", rec.Code)
	}
}

func TestAuditRecordsAllowAndDeny(t *testing.T) {
	var buf bytes.Buffer
	pol, _ := policy.Parse([]byte(testPolicy))
	g := gatewayWithAudit(t, pol, &buf)

	do(g, "GET", "/containers/json", "")                                                      // allow
	do(g, "POST", "/containers/create", `{"Image":"nginx","HostConfig":{"Privileged":true}}`) // deny

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 audit lines, got %d: %q", len(lines), buf.String())
	}

	var allow, deny audit.Event
	if err := json.Unmarshal([]byte(lines[0]), &allow); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(lines[1]), &deny); err != nil {
		t.Fatal(err)
	}
	if allow.Action != "container.list" || allow.Decision != "allow" {
		t.Errorf("allow line wrong: %+v", allow)
	}
	if deny.Action != "container.create" || deny.Decision != "deny" || deny.Status != 403 {
		t.Errorf("deny line wrong: %+v", deny)
	}
	if deny.Image != "nginx" || !strings.Contains(deny.Reason, "privileged") {
		t.Errorf("deny line should record image and reason: %+v", deny)
	}
}

func TestSetPolicyHotSwap(t *testing.T) {
	denyAll, _ := policy.Parse([]byte("default_action: deny\nrules: []"))
	g := gatewayWithAudit(t, denyAll, &bytes.Buffer{})

	if rec := do(g, "GET", "/containers/json", ""); rec.Code != http.StatusForbidden {
		t.Fatalf("with deny-all policy, list should be 403, got %d", rec.Code)
	}

	// Swap in a policy that allows listing; the change takes effect immediately.
	allowList, _ := policy.Parse([]byte("rules:\n  - effect: allow\n    actions: [container.list]"))
	g.SetPolicy(allowList)

	if rec := do(g, "GET", "/containers/json", ""); rec.Code != http.StatusOK {
		t.Fatalf("after hot swap, list should be 200, got %d", rec.Code)
	}
}

func TestRejectionMessageIsDockerCompatibleJSON(t *testing.T) {
	pol, _ := policy.Parse([]byte(testPolicy))
	g := gatewayWithAudit(t, pol, &bytes.Buffer{})
	rec := do(g, "POST", "/networks/create", `{}`)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("code = %d", rec.Code)
	}
	// Docker clients parse the top-level "message" field.
	var payload struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(rec.Body.Bytes()), &payload); err != nil {
		t.Fatalf("rejection body is not JSON: %v (%s)", err, rec.Body.String())
	}
	if !strings.Contains(payload.Message, "denied") {
		t.Errorf("message should explain denial: %q", payload.Message)
	}
}

func TestCreateBodyForwardedWithCorrectContentLength(t *testing.T) {
	// The upstream must see the exact bytes and a matching Content-Length after
	// the gateway buffers and replays the create body.
	sock := filepath.Join(t.TempDir(), "d.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	var gotLen int64
	var gotBody bytes.Buffer
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotLen = r.ContentLength
		io.Copy(&gotBody, r.Body)
		w.WriteHeader(http.StatusCreated)
	})}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })

	pol, _ := policy.Parse([]byte(testPolicy))
	g := New(pol, audit.New(io.Discard), proxy.New(sock), log.New(io.Discard, "", 0))

	payload := `{"Image":"nginx","Env":["K=V"]}`
	rec := do(g, "POST", "/containers/create", payload)
	if rec.Code != http.StatusCreated {
		t.Fatalf("code = %d (%s)", rec.Code, rec.Body.String())
	}
	if gotBody.String() != payload {
		t.Errorf("upstream body = %q, want %q", gotBody.String(), payload)
	}
	if gotLen != int64(len(payload)) {
		t.Errorf("upstream Content-Length = %d, want %d", gotLen, len(payload))
	}
}
