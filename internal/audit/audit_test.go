package audit

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func fixedClock(l *Logger) {
	l.now = func() time.Time { return time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC) }
}

func TestLogStampsTimeAndFields(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf)
	fixedClock(l)

	l.Log(Event{
		RemoteAddr: "1.2.3.4:5",
		Method:     "POST",
		Path:       "/v1.43/containers/create",
		Action:     "container.create",
		Decision:   "deny",
		Rule:       "hardened",
		Reason:     "privileged containers are not permitted",
		Image:      "nginx",
		Status:     403,
	})

	var e Event
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &e); err != nil {
		t.Fatalf("audit line is not valid JSON: %v\n%s", err, buf.String())
	}
	if e.Time != "2026-01-02T03:04:05Z" {
		t.Errorf("Time = %q, want stamped RFC3339", e.Time)
	}
	if e.Action != "container.create" || e.Decision != "deny" || e.Status != 403 {
		t.Errorf("fields not preserved: %+v", e)
	}
	if !strings.HasSuffix(buf.String(), "\n") {
		t.Error("each event must end with a newline")
	}
}

func TestLogOmitsEmptyOptionalFields(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf)
	fixedClock(l)
	l.Log(Event{Method: "GET", Path: "/_ping", Action: "system.ping", Decision: "allow", Reason: "ok"})

	s := buf.String()
	for _, omitted := range []string{`"rule"`, `"image"`, `"status"`} {
		if strings.Contains(s, omitted) {
			t.Errorf("expected %s to be omitted, got: %s", omitted, s)
		}
	}
	// A pre-set Time must be preserved, not overwritten.
	buf.Reset()
	l.Log(Event{Time: "2000-01-01T00:00:00Z", Decision: "allow", Reason: "x"})
	if !strings.Contains(buf.String(), "2000-01-01T00:00:00Z") {
		t.Errorf("preset Time was overwritten: %s", buf.String())
	}
}

func TestOpenStdout(t *testing.T) {
	l, err := Open("-")
	if err != nil {
		t.Fatalf("Open(-): %v", err)
	}
	if l.closer != nil {
		t.Error("stdout logger should not own a closer")
	}
	if err := l.Close(); err != nil {
		t.Errorf("Close on stdout logger should be nil, got %v", err)
	}
	// "" behaves like "-".
	if l2, err := Open(""); err != nil || l2.closer != nil {
		t.Errorf(`Open("") should be stdout: %v`, err)
	}
}

func TestOpenFileAppends(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")

	l, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	l.Log(Event{Decision: "allow", Reason: "first"})
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Re-open the same file: content must be appended, not truncated.
	l2, err := Open(path)
	if err != nil {
		t.Fatalf("re-Open: %v", err)
	}
	l2.Log(Event{Decision: "deny", Reason: "second"})
	l2.Close()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 appended lines, got %d: %q", len(lines), data)
	}
	if !strings.Contains(lines[0], "first") || !strings.Contains(lines[1], "second") {
		t.Errorf("append order wrong: %q", data)
	}
}

func TestOpenFileError(t *testing.T) {
	// A path whose parent directory does not exist should error.
	_, err := Open(filepath.Join(t.TempDir(), "no-such-dir", "audit.log"))
	if err == nil {
		t.Error("expected error opening file in nonexistent directory")
	}
}

func TestLogConcurrent(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf)

	const n = 200
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			l.Log(Event{Decision: "allow", Reason: "concurrent"})
		}()
	}
	wg.Wait()

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != n {
		t.Fatalf("expected %d lines, got %d", n, len(lines))
	}
	// Every line must be intact JSON (no interleaved/torn writes).
	for _, ln := range lines {
		var e Event
		if err := json.Unmarshal([]byte(ln), &e); err != nil {
			t.Fatalf("torn/invalid line under concurrency: %q", ln)
		}
	}
}
