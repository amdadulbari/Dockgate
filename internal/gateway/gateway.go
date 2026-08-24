// Package gateway is the HTTP handler at the heart of DockGate. For every
// incoming Docker API request it classifies the operation, evaluates it against
// the active policy, records an audit event, and either forwards the request to
// the Docker Engine or rejects it with a Docker-compatible error.
package gateway

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync/atomic"

	"github.com/amdadulbari/dockgate/internal/audit"
	"github.com/amdadulbari/dockgate/internal/dockerapi"
	"github.com/amdadulbari/dockgate/internal/policy"
)

// maxCreateBody caps how much of a container-create body DockGate buffers for
// inspection. Real create payloads are a few KB; this guards against a client
// sending an unbounded body to exhaust memory.
const maxCreateBody = 1 << 20 // 1 MiB

// Gateway implements http.Handler. The policy is stored in an atomic pointer so
// it can be hot-reloaded (e.g. on SIGHUP) without locking the request path.
type Gateway struct {
	policy   atomic.Pointer[policy.Policy]
	audit    *audit.Logger
	upstream http.Handler
	log      *log.Logger
}

// New builds a Gateway. upstream is the reverse proxy to the Docker Engine.
func New(p *policy.Policy, auditor *audit.Logger, upstream http.Handler, logger *log.Logger) *Gateway {
	g := &Gateway{audit: auditor, upstream: upstream, log: logger}
	g.policy.Store(p)
	return g
}

// SetPolicy atomically swaps the active policy. Safe to call while serving.
func (g *Gateway) SetPolicy(p *policy.Policy) {
	g.policy.Store(p)
}

func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	action := dockerapi.Classify(r.Method, r.URL.RequestURI())

	req := policy.Request{Action: action}
	var body []byte

	// Only container.create needs body inspection; every other endpoint streams
	// through untouched so logs/exec/attach hijacking keeps working.
	if action.NeedsBodyInspection() {
		b, err := io.ReadAll(io.LimitReader(r.Body, maxCreateBody+1))
		_ = r.Body.Close()
		if err != nil {
			g.reject(w, r, action, "", policy.Decision{Reason: "could not read request body"}, http.StatusBadRequest)
			return
		}
		if len(b) > maxCreateBody {
			g.reject(w, r, action, "", policy.Decision{Reason: "request body too large to inspect"}, http.StatusRequestEntityTooLarge)
			return
		}
		body = b
		spec, err := dockerapi.ParseCreateSpec(body)
		if err != nil {
			// Fail closed: an unparseable create body cannot be safely allowed.
			g.reject(w, r, action, "", policy.Decision{Reason: "malformed container create body"}, http.StatusBadRequest)
			return
		}
		req.Spec = spec
		// Restore the body for the upstream proxy.
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))
	}

	decision := g.policy.Load().Evaluate(req)

	g.audit.Log(audit.Event{
		RemoteAddr: r.RemoteAddr,
		Method:     r.Method,
		Path:       r.URL.RequestURI(),
		Action:     string(action),
		Decision:   decisionWord(decision.Allowed),
		Rule:       decision.Rule,
		Reason:     decision.Reason,
		Image:      req.Spec.Image,
		Status:     statusFor(decision.Allowed),
	})

	if !decision.Allowed {
		g.reject(w, r, action, req.Spec.Image, decision, http.StatusForbidden)
		return
	}

	g.upstream.ServeHTTP(w, r)
}

// reject writes a Docker-style JSON error and (for denials) records the event.
// It is also used for pre-policy failures, which are logged here since they
// never reach the main audit call above.
func (g *Gateway) reject(w http.ResponseWriter, r *http.Request, action dockerapi.Action, image string, d policy.Decision, status int) {
	if status != http.StatusForbidden {
		// Pre-policy failure: emit its own audit line.
		g.audit.Log(audit.Event{
			RemoteAddr: r.RemoteAddr,
			Method:     r.Method,
			Path:       r.URL.RequestURI(),
			Action:     string(action),
			Decision:   "deny",
			Reason:     d.Reason,
			Image:      image,
			Status:     status,
		})
	}

	msg := fmt.Sprintf("dockgate: %s denied: %s", action, d.Reason)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Api-Version", "dockgate")
	w.WriteHeader(status)
	// Docker clients surface the "message" field verbatim to the user.
	if err := writeJSONMessage(w, msg); err != nil {
		g.log.Printf("failed to write rejection response: %v", err)
	}
}

func writeJSONMessage(w io.Writer, message string) error {
	_, err := fmt.Fprintf(w, `{"message":%q}`+"\n", message)
	return err
}

func decisionWord(allowed bool) string {
	if allowed {
		return "allow"
	}
	return "deny"
}

// statusFor reports the response status recorded for the decision. Allowed
// requests are proxied and their upstream status is not captured here, so 0
// (omitted from the log) is used; denials are always 403.
func statusFor(allowed bool) int {
	if allowed {
		return 0
	}
	return http.StatusForbidden
}
