---
title: "Never give your AI agent the Docker socket"
published: false
description: "Handing an AI agent /var/run/docker.sock is handing it root on your host. Here's the one-liner that proves it — and a 30-line policy that stops it."
tags: ai, docker, security, devops
# cover_image: https://raw.githubusercontent.com/amdadulbari/Dockgate/main/docs/architecture.svg
canonical_url:
---

Your AI SRE agent needs to restart a stuck container. So you give it access to
Docker. The quickest way is to mount the socket:

```yaml
volumes:
  - /var/run/docker.sock:/var/run/docker.sock
```

Congratulations — you just gave your agent **root on the host**.

## The one-liner that owns your machine

Anything that can talk to `/var/run/docker.sock` can run this:

```bash
docker run -v /:/host --privileged alpine chroot /host sh
```

That mounts the host's entire filesystem into a privileged container and drops
you into a shell **as root on the host**. Not root in a container — root on the
box. From there: read every secret, install a backdoor, pivot to the rest of
your infrastructure.

The Docker socket has no concept of "read-only" or "just this one container." It
is all-or-nothing. And an LLM-driven agent is exactly the kind of operator that
will, eventually, be talked into running the wrong command — by a confused
plan, a prompt injection in a log line it's summarizing, or a hallucinated fix.

"Just prompt it not to" is not a security boundary.

## Why the usual answers fall short

- **Rootless Docker** shrinks the blast radius but doesn't stop an agent from
  doing destructive things within its reach, and it changes your whole setup.
- **A generic socket proxy** can allow/deny whole API endpoints, but it doesn't
  understand *intent* — it can't say "you may create containers, but never
  privileged ones, and only from these images."
- **Giving the agent its own VM** works but is heavy, and you still want a
  policy inside it.

What you actually want is a bouncer that understands Docker operations and
enforces a policy you wrote — and logs everything.

## Enter DockGate

[DockGate](https://github.com/amdadulbari/Dockgate) is a small Go gateway that
sits between your agent and the Docker Engine. The agent talks to DockGate;
DockGate talks to the socket. The socket is never exposed to the agent.

For every request it:

1. **Classifies** it into a canonical action (`POST /containers/create` →
   `container.create`).
2. **Checks** it against your YAML policy.
3. **Audits** the decision as a line of JSON.
4. **Forwards** it to Docker — only if allowed.

Because DockGate speaks the native Docker Engine API, *every* Docker client
works unchanged. You only change the endpoint:

```bash
export DOCKER_HOST=tcp://127.0.0.1:2375
```

## The policy is one small file

Default-deny, then allow exactly what the agent needs. Here's a complete
read-only policy — the agent can look, but never touch:

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

Need it to actually *do* things? Allow creation — but with guardrails:

```yaml
  - name: "Create hardened containers from approved images"
    effect: allow
    actions: [container.create]
    allowed_images: ["nginx", "redis:*", "ghcr.io/acme/*"]
    deny_privileged: true
    deny_host_network: true
    deny_bind_mounts: true
    denied_capabilities: [ALL]
```

Now watch it work:

```bash
docker ps                       # ✅ allowed
docker run --rm nginx           # ✅ allowed (nginx is on the allow-list)
docker run --privileged nginx   # ⛔ denied: privileged containers are not permitted
docker run --rm ubuntu          # ⛔ denied: ubuntu is not in allowed_images
docker network create test      # ⛔ denied by default
```

That `--privileged` request — the one that would have owned your host — never
reaches the socket.

## Everything is audited

Every decision is one line of JSON, ready to tail or ship to a SIEM:

```json
{"time":"2026-08-24T17:53:14Z","action":"container.create","decision":"deny","reason":"privileged containers are not permitted","image":"nginx","status":403}
```

```bash
tail -f audit.log | jq 'select(.decision=="deny")'
```

When your agent tries something it shouldn't, you'll know — with the exact
action, image, and reason.

## Run it

```bash
docker run -d --name dockgate \
  -p 127.0.0.1:2375:2375 \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$PWD/policy.yaml:/etc/dockgate/policy.yaml:ro" \
  --group-add "$(getent group docker | cut -d: -f3)" \
  amdadulbari/dockgate:latest
```

One caveat worth repeating: DockGate only helps if the agent **cannot** reach
the socket directly. Mount the socket into DockGate only, and put the agent on a
network where DockGate is its sole route to Docker.

## The takeaway

AI agents operating infrastructure is happening whether we're ready or not. The
lazy default — handing them the Docker socket — is a root shell waiting to be
triggered. A default-deny policy gateway turns "the agent can do anything" into
"the agent can do exactly these things, and I have the logs."

DockGate is open source (MIT) and a single static binary. If it saves you from
one bad `--privileged`, it's earned its keep.

👉 **[Star it on GitHub](https://github.com/amdadulbari/Dockgate)** and tell me
what your agent tried to do that it shouldn't have.
