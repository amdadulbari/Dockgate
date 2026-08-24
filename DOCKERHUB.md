# DockGate

**A security and policy gateway that keeps AI agents off the raw Docker socket.**

Handing an AI SRE agent `/var/run/docker.sock` is handing it root on the host.
DockGate sits in front of the Docker Engine: the agent talks to DockGate, and
DockGate validates every requested operation against a simple YAML policy — and
audits it — before forwarding approved calls to the real Docker socket.

```
 AI agent ──HTTP──► DockGate ──/var/run/docker.sock──► Docker Engine
                       │  (every call policy-checked & audited)
                       ▼
                  audit log (JSON lines)
```

DockGate speaks the native Docker Engine API, so any Docker client (CLI, SDK,
raw HTTP) works unchanged — you only change the endpoint.

- 📦 **Source & full docs:** https://github.com/amdadulbari/Dockgate
- 🐛 **Issues:** https://github.com/amdadulbari/Dockgate/issues
- 🔒 **Security policy:** https://github.com/amdadulbari/Dockgate/blob/main/SECURITY.md
- 🏗 **Architectures:** `linux/amd64`, `linux/arm64`

## Supported tags

| Tag | Meaning |
|-----|---------|
| `latest` | The most recent stable release. |
| `1.2.3`, `1.2` | Specific version / minor line — pin these in production. |
| `edge` | Latest manual build from `main` (may be unstable). |

## Quick start

DockGate needs two things: access to the host's Docker socket, and a policy file.

```bash
docker run -d --name dockgate \
  -p 127.0.0.1:2375:2375 \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$PWD/policy.yaml:/etc/dockgate/policy.yaml:ro" \
  --group-add "$(getent group docker | cut -d: -f3)" \
  amdadulbari/dockgate:latest
```

Then point any Docker client at DockGate instead of the socket:

```bash
export DOCKER_HOST=tcp://127.0.0.1:2375

docker ps                       # allowed by the policy
docker run --rm nginx           # allowed only if the policy permits it
docker run --privileged nginx   # DENIED: privileged containers are not permitted
```

> **Important:** DockGate only helps if the agent **cannot** reach the Docker
> socket directly. Mount the socket into the DockGate container only, and put the
> agent on a network where DockGate is its sole route to Docker. Bind DockGate to
> loopback or a private network.

## A minimal policy

Save this as `policy.yaml`. It denies everything except read-only inspection —
the agent can look, but never change anything.

```yaml
default_action: deny

rules:
  - name: "Read-only"
    effect: allow
    actions:
      - system.ping
      - container.list
      - container.inspect
      - container.logs
      - image.list
```

The full policy syntax — image allow-lists and guardrails against privileged
mode, host networking, bind mounts, and dangerous capabilities — is documented
in the [project README](https://github.com/amdadulbari/Dockgate#the-policy-file).

## Configuration

Every flag has a `DOCKGATE_*` environment-variable fallback.

| Flag | Env | Default | Description |
|------|-----|---------|-------------|
| `--listen` | `DOCKGATE_LISTEN` | `127.0.0.1:2375` | Where agents connect (`host:port` or `unix:///path`). In a container use `0.0.0.0:2375`. |
| `--docker-socket` | `DOCKGATE_DOCKER_SOCKET` | `/var/run/docker.sock` | The real Docker Engine socket. |
| `--policy` | `DOCKGATE_POLICY` | `/etc/dockgate/policy.yaml` | Path to the YAML policy. |
| `--audit-log` | `DOCKGATE_AUDIT_LOG` | `-` (stdout) | Audit destination: `-` for stdout, or a file path. |

The image's default command is:

```
--listen 0.0.0.0:2375 --policy /etc/dockgate/policy.yaml
```

## docker compose

```yaml
services:
  dockgate:
    image: amdadulbari/dockgate:latest
    command: ["--listen", "0.0.0.0:2375", "--policy", "/etc/dockgate/policy.yaml"]
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - ./policy.yaml:/etc/dockgate/policy.yaml:ro
    group_add:
      - "999"   # your host's docker gid: `getent group docker | cut -d: -f3`
    networks: [agent-net]
    restart: unless-stopped

  ai-agent:
    image: alpine:3.20
    depends_on: [dockgate]
    environment:
      DOCKER_HOST: "tcp://dockgate:2375"
    command: ["sleep", "infinity"]
    networks: [agent-net]

networks:
  agent-net:
```

## License

MIT © Md. Amdadul Bari Imad —
[LICENSE](https://github.com/amdadulbari/Dockgate/blob/main/LICENSE)
