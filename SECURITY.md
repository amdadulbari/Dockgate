# Security Policy

## Reporting a vulnerability

DockGate is a security control, so vulnerabilities are taken seriously.

If you discover a security issue, please report it **privately**:

- Use GitHub's [private vulnerability reporting](https://github.com/amdadulbari/dockgate/security/advisories/new)
  (**Security → Report a vulnerability**), or
- email **amdadulbari@gmail.com** with the details.

Please include:

- a description of the issue and its impact,
- steps to reproduce (a policy snippet and request that demonstrate the bypass),
- the DockGate version / commit.

Please do not open a public issue or PR until a fix is available.

## Scope

DockGate's security promise is: *an agent can only perform Docker operations the
policy allows, and every attempt is audited.* Reports that are in scope include,
for example:

- a request that reaches the Docker Engine despite the policy denying it (a
  **policy bypass**),
- a classification gap where a sensitive endpoint is mistaken for an innocuous
  one,
- a `container.create` body that evades a constraint (privileged, bind mount,
  capability, image allow-list).

Out of scope: misconfigurations such as exposing the DockGate endpoint on an
untrusted network without authentication, or mounting the Docker socket into the
agent. See the Security model section of the README.

## Supported versions

DockGate is pre-1.0; security fixes are applied to `main` and the latest release.
