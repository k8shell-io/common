# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

This is a library — there is no runnable binary. Use these commands during development:

```bash
# Verify all packages compile
go build ./...

# Run tests
go test ./...

# Run a single test by name
go test ./pkg/userstr/... -run TestUserStr/implicit

# Regenerate gRPC stubs from proto sources (requires buf or protoc)
make proto

# Lint proto files
make proto-lint

# Check for breaking wire changes against main
make proto-breaking
```

## Architecture

### Generated stubs are committed

`pkg/api/gen/go/` is checked in. Consumers import this module and get generated code without any proto toolchain. **Never edit files under `pkg/api/gen/go/` directly** — they are overwritten by `make proto`.

Proto sources live in `pkg/api/proto/` with one subdirectory per service (`identity/v1/`, `provisioner/v1/`, etc.). `buf.gen.yaml` drives generation; `buf.yaml` enforces `STANDARD` lint rules and `FILE`-level breaking change detection.

### Authz contract pattern

Every authorization policy check uses the `EvalRequest` interface (`pkg/authz/contract.go`). The pattern is:

- **Client side**: construct a typed request with `With*` builder methods, then call `.ToProto(jwtToken)` to produce the gRPC wire message.
- **Server side** (the authz service): call the domain's `FromProto(msg)` function to validate and restore the typed struct, then build a `PolicyInput` for OPA evaluation.

The contract for each policy point (its required fields, optional context, and possible obligations) is documented as a comment block at the top of each domain file (e.g. `pkg/authz/user.go`). Obligations returned by OPA (extra scopes, role assignments, sudo flag) are parsed into typed Go structs by helpers in `pkg/authz/scope.go` and related files.

### User string format

`pkg/userstr` parses the SSH username that carries workspace identity through the k8Shell SSH layer. The grammar is: `username~key=val+key=val…`, where the first key determines the `UserStrForm`:

- No `~`: implicit (username only)
- `~<name>` (no `=`): explicit blueprint
- `~pod=<name>`: named workspace
- `~repo=<owner>/<repo>`: repository workspace

`ParseUserStrWithGrammar` validates that each key is permitted in the detected form — for example, `ns` is not valid alone (only with `pod`, `workload`, or `repo`). The grammar is extensible; services can pass a custom `UserStrGrammar` to restrict or expand allowed keys. Strings may be base64-encoded with a `b64-` prefix to safely carry repo paths through SSH client username constraints.

`scripts/wscode` is a developer script that constructs a user string and opens VS Code Remote SSH directly into a workspace.

### gRPC server

`pkg/gapi.Server` is the shared gRPC server wrapper embedded by every k8Shell service. Configure it with a `ServerConfig` YAML struct (port, TLS cert/key, OIDC issuer, audience, allowed ServiceAccounts). TLS certificates hot-reload on file change. Authentication is skipped for requests from `AllowedCaller` namespace/serviceAccount pairs, which is how service-to-service in-cluster calls bypass JWT verification.

### Configuration processing

`pkg/config.Processor` rewrites a YAML document before unmarshalling:

1. `${VAR_NAME}` → environment variable value (errors if missing and `RequireEnvVars` is set)
2. `!file /path/to/file` YAML tag → file contents inlined as a string

Services use this to mount Kubernetes secrets as files and reference them with `!file` in their config YAML rather than passing secrets as environment variables.
