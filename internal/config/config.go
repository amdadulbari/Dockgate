// Package config resolves DockGate's runtime configuration from command-line
// flags with environment-variable fallbacks.
package config

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

// Config holds all resolved runtime settings.
type Config struct {
	// Listen is where DockGate accepts client (agent) connections. It is either
	// a "host:port" TCP address or a "unix:///path/to/socket" address.
	Listen string
	// DockerSocket is the path to the real Docker Engine Unix socket.
	DockerSocket string
	// PolicyPath is the path to the YAML policy file.
	PolicyPath string
	// AuditLog is the audit destination ("-" or "" for stdout, else a file path).
	AuditLog string
}

// Defaults returns the built-in configuration. The listen address defaults to
// loopback so an unconfigured deployment is not exposed on the network.
func Defaults() Config {
	return Config{
		Listen:       "127.0.0.1:2375",
		DockerSocket: "/var/run/docker.sock",
		PolicyPath:   "policy.yaml",
		AuditLog:     "-",
	}
}

// Load parses flags (with DOCKGATE_* environment fallbacks) into a Config.
// args should be os.Args[1:]. On -help it returns flag.ErrHelp.
func Load(args []string) (Config, error) {
	cfg := Defaults()

	fs := flag.NewFlagSet("dockgate", flag.ContinueOnError)
	fs.StringVar(&cfg.Listen, "listen", env("DOCKGATE_LISTEN", cfg.Listen),
		"address to accept agent connections on (host:port or unix:///path)")
	fs.StringVar(&cfg.DockerSocket, "docker-socket", env("DOCKGATE_DOCKER_SOCKET", cfg.DockerSocket),
		"path to the Docker Engine Unix socket")
	fs.StringVar(&cfg.PolicyPath, "policy", env("DOCKGATE_POLICY", cfg.PolicyPath),
		"path to the YAML security policy")
	fs.StringVar(&cfg.AuditLog, "audit-log", env("DOCKGATE_AUDIT_LOG", cfg.AuditLog),
		`audit log destination ("-" for stdout, or a file path)`)

	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "DockGate — a security & policy gateway for Docker.\n\nUsage:\n  dockgate [flags]\n\nFlags:\n")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return cfg, err
	}
	if err := cfg.validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func (c Config) validate() error {
	if c.Listen == "" {
		return fmt.Errorf("listen address must not be empty")
	}
	if c.DockerSocket == "" {
		return fmt.Errorf("docker socket path must not be empty")
	}
	if c.PolicyPath == "" {
		return fmt.Errorf("policy path must not be empty")
	}
	return nil
}

// ListenNetwork splits Listen into a net.Listen("network", "address") pair,
// supporting "unix:///path" and plain "host:port" (tcp).
func (c Config) ListenNetwork() (network, address string) {
	if rest, ok := strings.CutPrefix(c.Listen, "unix://"); ok {
		return "unix", rest
	}
	if rest, ok := strings.CutPrefix(c.Listen, "tcp://"); ok {
		return "tcp", rest
	}
	return "tcp", c.Listen
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
