// Command dockgate is a security and policy gateway for the Docker Engine.
//
// AI SRE agents (or any Docker client) connect to DockGate instead of the
// Docker socket. DockGate classifies each request, checks it against a YAML
// policy, records an audit event, and only then forwards approved requests to
// the real Docker Engine. The Docker socket is never exposed to the agent.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/amdadulbari/dockgate/internal/audit"
	"github.com/amdadulbari/dockgate/internal/config"
	"github.com/amdadulbari/dockgate/internal/gateway"
	"github.com/amdadulbari/dockgate/internal/policy"
	"github.com/amdadulbari/dockgate/internal/proxy"
)

// version is overridden at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if err := run(os.Args[1:]); err != nil {
		if errors.Is(err, http.ErrServerClosed) {
			return
		}
		fmt.Fprintln(os.Stderr, "dockgate: "+err.Error())
		os.Exit(1)
	}
}

func run(args []string) error {
	logger := log.New(os.Stderr, "dockgate ", log.LstdFlags|log.Lmsgprefix)

	cfg, err := config.Load(args)
	if err != nil {
		return err
	}

	pol, err := policy.Load(cfg.PolicyPath)
	if err != nil {
		return err
	}

	auditor, err := audit.Open(cfg.AuditLog)
	if err != nil {
		return fmt.Errorf("open audit log: %w", err)
	}
	defer auditor.Close()

	upstream := proxy.New(cfg.DockerSocket)
	gw := gateway.New(pol, auditor, upstream, logger)

	network, address := cfg.ListenNetwork()
	// Remove a stale Unix socket left by a previous unclean shutdown.
	if network == "unix" {
		_ = os.Remove(address)
	}
	ln, err := net.Listen(network, address)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", cfg.Listen, err)
	}
	if network == "unix" {
		// Allow the docker group to reach the gateway socket, mirroring the
		// permissions of the real Docker socket.
		_ = os.Chmod(address, 0o660)
	}

	srv := &http.Server{
		Handler:           gw,
		ReadHeaderTimeout: 15 * time.Second,
		// No write/read timeouts: Docker streaming endpoints (logs -f, events,
		// stats, exec) hold connections open indefinitely by design.
	}

	logger.Printf("version %s", version)
	logger.Printf("listening on %s", cfg.Listen)
	logger.Printf("proxying to Docker Engine at %s", cfg.DockerSocket)
	logger.Printf("policy %s (%d rules, default_action=%s)", cfg.PolicyPath, len(pol.Rules), pol.DefaultAction)
	logger.Printf("audit log: %s", auditLogName(cfg.AuditLog))

	// Handle signals: INT/TERM shut down gracefully; HUP reloads the policy.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for range hup {
			reloadPolicy(gw, cfg.PolicyPath, logger)
		}
	}()

	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ln) }()

	select {
	case err := <-serveErr:
		return err
	case <-ctx.Done():
		logger.Printf("shutting down…")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}

// reloadPolicy attempts to load the policy afresh and swap it in. A failed
// reload is logged and the previous policy is kept, so a bad edit never takes
// the gateway offline.
func reloadPolicy(gw *gateway.Gateway, path string, logger *log.Logger) {
	pol, err := policy.Load(path)
	if err != nil {
		logger.Printf("policy reload failed, keeping previous policy: %v", err)
		return
	}
	gw.SetPolicy(pol)
	logger.Printf("policy reloaded from %s (%d rules, default_action=%s)", path, len(pol.Rules), pol.DefaultAction)
}

func auditLogName(dest string) string {
	if dest == "" || dest == "-" {
		return "stdout"
	}
	return dest
}
