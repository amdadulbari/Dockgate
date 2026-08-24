#!/usr/bin/env python3
"""
Example: an AI SRE agent's Docker tool, pointed at DockGate instead of the
Docker socket.

The agent code is identical to normal Docker usage — the only change is the
endpoint. DockGate transparently enforces policy.yaml, so operations the policy
forbids come back as HTTP 403 with a clear message the agent can reason about.

    pip install docker
    python3 agent_python.py

Assumes DockGate is running on tcp://127.0.0.1:2375 (the default `make run`).
"""

import docker
from docker.errors import APIError

DOCKGATE_URL = "tcp://127.0.0.1:2375"


def main() -> None:
    # A standard Docker SDK client — it has no idea DockGate is in the path.
    client = docker.DockerClient(base_url=DOCKGATE_URL)

    print("Docker reachable via DockGate:", client.ping())

    print("\nRunning containers:")
    for c in client.containers.list():
        print(f"  - {c.name} ({c.image.tags})")

    # This will be ALLOWED only if the image matches the policy's allow-list
    # and the container is not privileged / host-networked / bind-mounted.
    try:
        print("\nAttempting a compliant container create (nginx)…")
        client.containers.create("nginx:latest", name="dockgate-demo")
        print("  -> allowed")
    except APIError as e:
        print(f"  -> refused by DockGate: {e.explanation or e}")

    # This SHOULD be denied by a hardened policy: privileged container.
    try:
        print("\nAttempting a privileged container create (should be denied)…")
        client.containers.create("nginx:latest", privileged=True)
        print("  -> allowed (check your policy!)")
    except APIError as e:
        print(f"  -> correctly refused: {e.explanation or e}")


if __name__ == "__main__":
    main()
