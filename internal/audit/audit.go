// Package audit records every gateway decision as a structured, append-only
// JSON-lines stream. Each line is a self-contained event so the log can be
// tailed, shipped to a SIEM, or grepped without a parser.
package audit

import (
	"encoding/json"
	"io"
	"os"
	"sync"
	"time"
)

// Event is a single audited gateway decision.
type Event struct {
	Time       string `json:"time"`             // RFC3339 UTC
	RemoteAddr string `json:"remote_addr"`      // client address
	Method     string `json:"method"`           // HTTP method
	Path       string `json:"path"`             // request path
	Action     string `json:"action"`           // canonical action name
	Decision   string `json:"decision"`         // "allow" or "deny"
	Rule       string `json:"rule,omitempty"`   // matching rule name, if any
	Reason     string `json:"reason"`           // human-readable explanation
	Image      string `json:"image,omitempty"`  // image ref for container.create
	Status     int    `json:"status,omitempty"` // upstream/response status code
}

// Logger serialises audit events to an io.Writer. It is safe for concurrent use.
type Logger struct {
	mu     sync.Mutex
	w      io.Writer
	closer io.Closer // non-nil when Logger owns the underlying file
	now    func() time.Time
}

// New returns a Logger writing to w. The Logger does not take ownership of w.
func New(w io.Writer) *Logger {
	return &Logger{w: w, now: time.Now}
}

// Open returns a Logger writing to the given destination. The special path "-"
// (or "") selects stdout. Any other path is opened for appending and created if
// absent; the returned Logger owns the file and closes it on Close.
func Open(path string) (*Logger, error) {
	if path == "" || path == "-" {
		return New(os.Stdout), nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return nil, err
	}
	l := New(f)
	l.closer = f
	return l, nil
}

// Log writes one event. The Time field is stamped here if empty. Write errors
// are reported to the caller but never block the request path.
func (l *Logger) Log(e Event) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if e.Time == "" {
		e.Time = l.now().UTC().Format(time.RFC3339)
	}
	// Marshalling a fixed struct cannot fail; ignore the error deliberately.
	line, _ := json.Marshal(e)
	line = append(line, '\n')
	_, _ = l.w.Write(line)
}

// Close releases the underlying file if the Logger owns one.
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closer != nil {
		return l.closer.Close()
	}
	return nil
}
