# Contributing to DockGate

Thanks for your interest in improving DockGate! This is a security-sensitive
project, so contributions are held to a simple, high bar.

## Ground rules

- **Fail closed.** Any ambiguity in a request must resolve to *deny*. New request
  types default to `unknown` (and therefore `default_action`) until a route and,
  where relevant, body inspection are added deliberately.
- **Keep it small and dependency-light.** The only runtime dependency is a YAML
  parser. Please don't add the Docker SDK or heavy frameworks.
- **Test what you change.** Bug fixes and features need tests. Policy and
  classification logic especially — those are the security core.

## Development workflow

```bash
make vet test     # must pass
make race         # race-clean
gofmt -s -w .     # formatted (CI enforces this)
```

## Adding support for a new Docker endpoint

1. Add a `route` in `internal/dockerapi/action.go` (more specific patterns
   first) and a matching case in `action_test.go`.
2. If the endpoint carries security-relevant body fields, extend the parser in
   `internal/dockerapi/create.go` (or add a sibling) plus tests.
3. Document the new action in the README's action reference.

## Pull requests

- One logical change per PR.
- Describe the security implications, if any.
- Ensure CI is green.

## Reporting security issues

Please do **not** open a public issue for vulnerabilities. See
[SECURITY.md](SECURITY.md).
