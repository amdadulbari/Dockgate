// Package proxy forwards approved requests to the real Docker Engine over its
// Unix socket. It is a thin wrapper around httputil.ReverseProxy configured to
// dial the socket and to preserve streaming/hijacked connections (logs, events,
// exec, attach).
package proxy

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"time"
)

// New returns a ReverseProxy that sends every request to the Docker Engine
// listening on the given Unix socket path. The proxy leaves request bodies
// untouched, so the caller is responsible for any inspection before forwarding.
func New(socketPath string) *httputil.ReverseProxy {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 10 * time.Second}
			return d.DialContext(ctx, "unix", socketPath)
		},
		// The Docker daemon is local; keep a small idle pool and disable
		// compression (the API does not benefit and it complicates streaming).
		MaxIdleConns:        16,
		IdleConnTimeout:     60 * time.Second,
		DisableCompression:  true,
		TLSHandshakeTimeout: 5 * time.Second,
	}

	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = "http"
			// The Host is irrelevant for a Unix socket but must be set for the
			// HTTP/1.1 request line to be valid.
			pr.Out.URL.Host = "docker"
			pr.Out.Host = "docker"
		},
		Transport: transport,
		// FlushInterval < 0 flushes writes immediately, which is required for
		// Docker's streaming endpoints (logs -f, events, stats).
		FlushInterval: -1,
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadGateway)
			fmt.Fprintf(w, `{"message":%q}`, "dockgate: upstream Docker Engine error: "+err.Error())
		},
	}
	return rp
}
