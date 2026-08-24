# DockGate

**A security and policy gateway that stands between AI SRE agents and the Docker Engine.**

AI agents are increasingly trusted to operate infrastructure — restarting a
stuck container, pulling an image, checking logs. But handing an agent the
Docker socket (`/var/run/docker.sock`) hands it **root on the host**: with the
socket, anything can launch a privileged container, bind-mount `/`, and take over
the machine.

DockGate removes that risk. The agent never sees the socket. It talks to
DockGate, and DockGate validates **every** requested operation against a simple
YAML policy before forwarding approved requests to the real Docker Engine. Every
decision — allowed or denied — is written to an append-only audit log.

```
   ┌────────────┐   Docker API over TCP    ┌────────────┐   /var/run/docker.sock   ┌───────────────┐
   │  AI agent  │ ───────────────────────► │  DockGate  │ ───────────────────────► │ Docker Engine │
   └────────────┘   (every call checked)   └────────────┘     (never exposed)      └───────────────┘
                                                 │
                                                 ▼
                                        append-only audit log
```

Because DockGate speaks the native Docker Engine API, **any** Docker client works
unchanged — the `docker` CLI, the Python/Go SDKs, or an agent's raw HTTP calls.
You only change the endpoint.

---

## Table of contents

- [Why](#why)
- [How it works](#how-it-works)
- [Quick start](#quick-start)
- [Configuration](#configuration)
- [The policy file](#the-policy-file)
- [Action reference](#action-reference)
- [Audit log](#audit-log)
- [Security model](#security-model)
- [Development](#development)
- [License](#license)

## Why

Giving an AI agent direct socket access is equivalent to giving it root:

```bash
# With the raw socket, this is all it takes to own the host:
docker run -v /:/host --privileged alpine chroot /host sh
```

DockGate enforces the principle of least privilege for machine operators:

- **Default deny.** Nothing is permitted unless a rule explicitly allows it.
- **Least privilege.** Grant exactly the operations an agent needs — often just
  "inspect and restart".
- **Guardrails on creation.** Even when container creation is allowed, DockGate
  can forbid privileged mode, host networking/PID/IPC, bind mounts, dangerous
  Linux capabilities, and untrusted images.
- **Auditable.** Every request is logged as structured JSON with the decision and
  the reason.
- **Fail closed.** Malformed or unrecognised requests are denied, not passed
  through.

## How it works

For each incoming request DockGate:

1. **Classifies** it into a canonical action from the HTTP method and path
   (e.g. `POST /v1.43/containers/create` → `container.create`).
2. **Inspects** the body when it matters — for `container.create` it extracts the
   image, privileged flag, network/PID/IPC mode, bind mounts, and capabilities.
3. **Evaluates** it against the policy. Rules are checked top to bottom; the first
   matching rule decides the outcome. If none match, `default_action` applies.
4. **Audits** the decision.
5. **Forwards or rejects.** Approved requests are reverse-proxied to the Docker
   socket (streaming endpoints like `logs -f`, `events`, and `stats` are
   preserved). Denied requests get a Docker-compatible `403` with a clear message.

## Quick start

### Run from source

```bash
git clone https://github.com/amdadulbari/dockgate.git
cd dockgate
make run           # builds ./bin/dockgate and listens on 127.0.0.1:2375
```

In another terminal, point any Docker client at DockGate:

```bash
export DOCKER_HOST=tcp://127.0.0.1:2375

docker ps                       # allowed by the default policy
docker run --rm nginx           # allowed (nginx is on the allow-list)
docker run --privileged nginx   # DENIED: privileged containers are not permitted
docker run --rm ubuntu          # DENIED: ubuntu is not in allowed_images
docker network create test      # DENIED by default_action
```

Or exercise it with the bundled smoke test:

```bash
./examples/smoke-test.sh
```

### Run with Docker Compose

The [`docker-compose.yml`](docker-compose.yml) shows the intended topology: the
Docker socket is mounted **only** into the DockGate container, and the agent
reaches Docker exclusively through `tcp://dockgate:2375`.

```bash
docker compose up --build
```

### Use the prebuilt image

Published multi-arch images (`linux/amd64`, `linux/arm64`) are on Docker Hub at
[`amdadulbari/dockgate`](https://hub.docker.com/r/amdadulbari/dockgate):

```bash
docker run -d --name dockgate \
  -p 127.0.0.1:2375:2375 \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$PWD/policy.yaml:/etc/dockgate/policy.yaml:ro" \
  --group-add "$(getent group docker | cut -d: -f3)" \
  amdadulbari/dockgate:latest
```

Releases are cut by pushing a version tag; a GitHub Actions workflow
([`docker-publish.yml`](.github/workflows/docker-publish.yml)) builds the image,
pushes `X.Y.Z` / `X.Y` / `latest`, and syncs the Docker Hub description. It needs
two repository secrets: `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN` (a Docker Hub
access token).

```bash
git tag v0.1.0
git push origin v0.1.0   # -> builds & publishes amdadulbari/dockgate:0.1.0 and :latest
```

## Configuration

Every flag has a `DOCKGATE_*` environment-variable fallback.

| Flag | Env | Default | Description |
|------|-----|---------|-------------|
| `--listen` | `DOCKGATE_LISTEN` | `127.0.0.1:2375` | Where agents connect. `host:port` for TCP, or `unix:///path/to.sock`. |
| `--docker-socket` | `DOCKGATE_DOCKER_SOCKET` | `/var/run/docker.sock` | The real Docker Engine socket. |
| `--policy` | `DOCKGATE_POLICY` | `policy.yaml` | Path to the YAML policy. |
| `--audit-log` | `DOCKGATE_AUDIT_LOG` | `-` (stdout) | Audit destination: `-` for stdout, or a file path (appended). |

**Signals**

- `SIGHUP` — reload the policy without dropping connections. A policy that fails
  to parse is rejected and the previous one is kept, so a bad edit never takes the
  gateway offline.
- `SIGINT` / `SIGTERM` — graceful shutdown.

```bash
kill -HUP "$(pgrep dockgate)"   # apply an edited policy.yaml live
```

## The policy file

A policy is deliberately small: a default action plus an ordered list of rules.

### Simplest example: read-only

Deny everything, then allow only the operations that observe Docker without
changing anything. The agent can look, but never touch.

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

With this policy `docker ps`, `docker logs`, and `docker inspect` succeed, while
`docker run`, `docker stop`, `docker rm`, and everything else return `403`.

### A fuller example

```yaml
default_action: deny        # what to do when no rule matches (deny | allow)

rules:
  - name: "Read-only inspection"
    effect: allow             # allow | deny  (default: allow)
    actions:
      - system.ping
      - container.list
      - container.inspect
      - container.logs

  - name: "Restart existing containers"
    effect: allow
    actions: [container.start, container.stop, container.restart]

  - name: "Create hardened containers from approved images"
    effect: allow
    actions: [container.create]
    allowed_images:           # only these image patterns may be created
      - "nginx"               #   bare name  → any tag of nginx
      - "redis:*"             #   glob       → any tag of redis
      - "ghcr.io/acme/*"      #   any image from your registry org
    deny_privileged: true     # reject --privileged
    deny_host_network: true   # reject --network host
    deny_host_pid: true       # reject --pid host
    deny_host_ipc: true       # reject --ipc host
    deny_bind_mounts: true    # reject -v /host/path:...
    denied_capabilities: [ALL]# reject any --cap-add

  - name: "Never allow exec into containers"
    effect: deny
    actions: [container.exec, exec.start]
```

### How rules are matched

- **First match wins.** Rules are evaluated top to bottom. The first rule whose
  `actions` include the request's action decides the outcome.
- **Action patterns.** Each `actions` entry is an exact action
  (`container.create`), a category wildcard (`container.*`), or `*` (everything).
- **Allow + constraints.** If a matching `allow` rule has constraints (the fields
  below `actions`), the request must satisfy **all** of them — otherwise it is
  denied and the log records exactly which constraint failed. Constraints only
  apply to `container.create`.
- **No match → `default_action`.** Keep it `deny`.

### Constraint fields (for `container.create`)

| Field | Effect |
|-------|--------|
| `allowed_images` | List of glob patterns. The image must match one. A bare name (`nginx`) matches any tag or digest of that repo; `redis:*` requires a tag; `ghcr.io/acme/*` matches an org. |
| `deny_privileged` | Reject privileged containers. |
| `deny_host_network` | Reject `NetworkMode: host`. |
| `deny_host_pid` | Reject `PidMode: host`. |
| `deny_host_ipc` | Reject `IpcMode: host`. |
| `deny_bind_mounts` | Reject any host-path bind mount (named volumes are still allowed). |
| `denied_capabilities` | List of capabilities to forbid via `--cap-add` (e.g. `SYS_ADMIN`, or `ALL`). |

Ready-made examples live in [`examples/policies/`](examples/policies/):
[`read-only.yaml`](examples/policies/read-only.yaml) and
[`restart-only.yaml`](examples/policies/restart-only.yaml).

## Action reference

DockGate maps Docker Engine API endpoints to these canonical action names. Use
them in `actions:`. Unlisted or unrecognised endpoints classify as `unknown` and
hit `default_action`.

| Category | Actions |
|----------|---------|
| `system` | `system.ping`, `system.version`, `system.info`, `system.df`, `system.events`, `system.auth` |
| `container` | `container.list`, `container.create`, `container.inspect`, `container.logs`, `container.top`, `container.stats`, `container.changes`, `container.export`, `container.archive.read`, `container.archive.write`, `container.start`, `container.stop`, `container.restart`, `container.kill`, `container.pause`, `container.unpause`, `container.rename`, `container.update`, `container.resize`, `container.wait`, `container.attach`, `container.exec`, `container.remove`, `container.prune` |
| `exec` | `exec.start`, `exec.resize`, `exec.inspect` |
| `image` | `image.list`, `image.pull`, `image.inspect`, `image.history`, `image.save`, `image.load`, `image.search`, `image.tag`, `image.push`, `image.remove`, `image.build`, `image.commit`, `image.prune` |
| `network` | `network.list`, `network.inspect`, `network.create`, `network.connect`, `network.disconnect`, `network.remove`, `network.prune` |
| `volume` | `volume.list`, `volume.inspect`, `volume.create`, `volume.remove`, `volume.prune` |
| `swarm` / `service` / `secret` / `config` | `swarm.init`, `swarm.join`, `swarm.leave`, `swarm.inspect`, `service.list`, `service.create`, `secret.list`, `secret.create`, `config.list`, `config.create` |

> **Tip:** `container.exec` + `exec.start` are how a client runs commands inside a
> container. Since `docker exec` can trivially escalate, deny them unless you have
> a specific reason not to.

## Audit log

One JSON object per line — easy to `grep`, `jq`, or ship to a SIEM.

```json
{"time":"2026-08-24T17:53:14Z","remote_addr":"127.0.0.1:53668","method":"GET","path":"/_ping","action":"system.ping","decision":"allow","rule":"Read-only inspection","reason":"allowed by rule \"Read-only inspection\""}
{"time":"2026-08-24T17:53:14Z","remote_addr":"127.0.0.1:53688","method":"POST","path":"/v1.43/containers/create","action":"container.create","decision":"deny","rule":"Create hardened containers from approved images","reason":"privileged containers are not permitted","image":"nginx","status":403}
```

Show only denials:

```bash
tail -f audit.log | jq 'select(.decision=="deny")'
```

## Security model

**What DockGate protects.** DockGate is an authorization gateway. It ensures an
agent can only perform Docker operations your policy permits, and records them.

**What it assumes.**

- **Keep the socket off the agent.** DockGate only helps if the agent cannot
  reach `/var/run/docker.sock` directly. Mount the socket into the DockGate
  container/host only, and put the agent on a network where DockGate is its sole
  route to Docker.
- **Protect the DockGate endpoint.** Anyone who can reach DockGate gets whatever
  the policy allows. Bind it to loopback or a private network; front it with
  mTLS/authentication if agents connect over untrusted networks.
- **`allow` broadly and you inherit the risk.** Actions such as `image.build`,
  `container.exec`, and `container.update` can be used to escalate. The shipped
  policy denies them by default — loosen deliberately.

**Fail-closed behaviour.** Unrecognised endpoints, oversized create bodies, and
unparseable create payloads are all denied rather than forwarded.

Found a vulnerability? See [SECURITY.md](SECURITY.md).

## Development

Requires Go 1.23+.

```bash
make test     # run the unit + integration tests
make race     # tests under the race detector
make vet      # go vet
make cover    # coverage summary
make build    # build ./bin/dockgate
make docker   # build the container image
```

The codebase is small and dependency-light (only `gopkg.in/yaml.v3`):

```
cmd/dockgate         entrypoint, server lifecycle, signal handling
internal/config      flags + env configuration
internal/dockerapi   request → canonical action; container-create body parsing
internal/policy      policy loading + evaluation (the security core)
internal/audit       structured JSON-lines audit logging
internal/proxy       reverse proxy to the Docker socket
internal/gateway     the HTTP handler tying it all together
```

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE) © Md. Amdadul Bari Imad
