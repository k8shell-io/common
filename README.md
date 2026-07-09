# common

Shared Go library for the k8Shell platform. Defines all gRPC API contracts (proto files, generated stubs, typed clients), canonical domain models, and utility packages consumed by every k8Shell service.

## Concepts

### Proto contracts

All service interfaces are defined as Protocol Buffer files under `pkg/api/proto/`. Generated Go stubs live in `pkg/api/gen/go/` and are committed to the repository so consumers do not need a proto toolchain to build.

The library defines the following gRPC services:

| Service | Proto file | Description |
|---|---|---|
| `IdentityService` | `identity/v1/identity.proto` | User lookup, authentication, onboarding, credential management, PAT lifecycle |
| `IdentityProviderService` | `identity/v1/idp.proto` | Interface implemented by remote identity providers (GitHub, GitLab, etc.) |
| `AuthzService` | `authz/v1/authz.proto` | OPA/Rego policy evaluation — single and batch authorization checks |
| `ProvisionerService` | `provisioner/v1/provisioner.proto` | Workspace lifecycle (create, list, delete, stop) with streaming progress events |
| `SessionService` | `session/v1/session.proto` | SSH session recording and metadata tracking |
| `RecordingService` | `session/v1/session.proto` | Client-streaming ingestion of PTY, exec, port-forward, and SFTP channel recordings |
| `SystemService` | `k8shelld/v1/k8shelld.proto` | In-workspace daemon: handshake and system metrics |
| `SshService` | `k8shelld/v1/k8shelld.proto` | In-workspace daemon: shell, port-forward, exec, Unix socket operations |
| `CommandService` | `k8shelld/v1/k8shelld.proto` | In-workspace daemon: bidirectional command messaging |
| `AppService` | `k8shelld/v1/k8shelld.proto` | In-workspace daemon: app lifecycle (install, start, stop, logs) |

Two message-only protocols drive the web console:

| Protocol | Proto file | Description |
|---|---|---|
| `WebShellMessage` | `console/webshell/v1/webshell.proto` | Terminal I/O over WebSocket |
| `WebFilesMessage` | `console/webfiles/v1/webfiles.proto` | File explorer operations over WebSocket |
| `CloudshellMessage` | `cloudshell/cloudshell.proto` | Unified web console envelope |

Shared message types used across services are defined in `common/v1/common.proto`.

### Typed gRPC clients

`pkg/api/client/` provides thin, preconfigured gRPC client wrappers for the four services most commonly dialed by other k8Shell components: `identity`, `k8shelld`, `provisioner`, and `session`. Each client handles TLS setup and connection lifetime, and exposes the generated service client directly.

### Domain models

`pkg/models` defines the canonical Go structs used throughout the platform. These are distinct from the generated Protobuf types and carry richer Go-native behavior (validation tags, helper methods).

| Model | Key fields |
|---|---|
| `User` | Username, organization, POSIX UID/GID, roles, blueprint permissions, auth methods (password, SSH keys, OIDC providers), credential list |
| `Workspace` | Status, resource allocation (CPU/memory), pod details (IP, hostname, port, namespace), repository context (owner, name, branch/tag/commit), blueprint and blueprint kind |
| `SSHSession` | Session ID, user, client IP, timestamps, byte counts (input/output), channel types used |
| `UserCredential` | External service credentials (registry, git, Kubernetes), OAuth tokens and API keys, expiration and activity timestamps |
| `AccessToken` | Personal Access Token with scope list, expiration, and last-used timestamp |

### Authz contracts

`pkg/authz` defines typed request builders for every authorization policy point evaluated across the platform. Services construct a typed request with `With*` builder methods, call `ToProto` to produce the wire message, and send it to the `AuthzService`. On the server side, `FromProto` validates and restores the typed struct.

| Policy | Who evaluates | Purpose |
|---|---|---|
| `user:onboard` | Identity service | Can deny onboarding or attach obligations (sudo, roles, blueprints) before a new user is persisted |
| `user:auth` | Identity service | Evaluated on each authentication attempt |
| `user:read` | Identity service | Controls visibility of individual user records |
| `user:list` | Identity service | Controls whether a caller may enumerate users |
| `token:create` | Identity service | Can restrict PAT scopes or cap maximum expiry |
| `token:read` | Identity service | Controls access to PAT metadata |
| `user:delete` | Identity service | Authorizes an admin to permanently remove a user record |

Obligations returned by the policy engine (additional scopes, expiry caps, role assignments) are parsed by helpers in this package into strongly typed Go structs.

### User string format

`pkg/userstr` parses the SSH username string that carries workspace identity through the k8Shell SSH layer. A user string encodes the username plus optional workspace context in a compact, URL-safe format.

| Form | Example | Meaning |
|---|---|---|
| Implicit | `alice` | Default workspace, implicit blueprint |
| Explicit blueprint | `alice+myblueprint` | Named blueprint, no repository |
| Named workspace | `alice@myworkspace` | Explicit workspace name |
| Repo workspace | `alice/owner/repo[/ref]` | Repository-bound workspace (branch, tag, or commit) |

Strings may be base64-encoded (prefixed `b64-`) to safely carry arbitrary repo paths through SSH client constraints. Blueprint kind (`implicit`, `explicit`, `custom`) is carried as a typed field on the parsed struct.

### gRPC server utilities

`pkg/gapi` provides a configurable gRPC server wrapper used by every k8Shell service:

- **TLS** — certificate loading from disk with optional hot-reload on file change (configurable delay).
- **OIDC/JWT authentication** — validates Bearer tokens against a configured issuer and audience. Bypassed for requests from trusted Kubernetes ServiceAccounts.
- **Kubernetes ServiceAccount authorization** — allows calls from specific namespace/ServiceAccount pairs without a user JWT (for in-cluster service-to-service traffic).
- **Request logging** — per-RPC log lines with method, duration, peer address, and caller identity.

### Configuration processing

`pkg/config` processes YAML configuration files before unmarshalling:

- **Environment variable expansion** — `${VAR_NAME}` references are resolved at load time. Variables must be present unless `RequireEnvVars` is disabled.
- **`!file` tag** — inlines the contents of an external file into a YAML string value, useful for mounting secrets from Kubernetes.
- **`FileWatcher`** — wraps `fsnotify` to trigger a reload callback when the configuration file changes on disk.

### NATS/JetStream client

`pkg/nats` provides a managed NATS connection with:

- Auto-reconnect with configurable backoff and maximum attempts (default: infinite).
- JetStream context for persistent streams.
- KV store helpers with TTL-based caching.
- Distributed lock primitives backed by JetStream KV.
- Generic JSON publish/subscribe helpers.

### Structured logging

`pkg/logger` wraps [zerolog](https://github.com/rs/zerolog) with a small initialization helper. Output is JSON by default; pass `--logtext` (or set the text flag in code) to enable human-readable console output. Every log line includes a component name and the process PID.

### Database utilities

`pkg/db` provides a thin connection helper over [pgx/v5](https://github.com/jackc/pgx) and exposes SQL migration support via [golang-migrate](https://github.com/golang-migrate/migrate). Services call `db.Connect` to get a `*pgxpool.Pool` from a standard `DATABASE_URL`-style DSN.

## Repository layout

```
pkg/
  api/
    proto/           # Protocol Buffer source files
      authz/v1/
      cloudshell/
      common/v1/
      console/
        webfiles/v1/
        webshell/v1/
      identity/v1/
      k8shelld/v1/
      provisioner/v1/
      session/v1/
    gen/go/          # Generated Go stubs (committed, do not edit)
    client/          # Typed gRPC client wrappers
      identity/
      k8shelld/
      provisioner/
      session/
  authz/             # Typed authz policy request builders and obligation parsing
  config/            # YAML processor (env-var expansion, !file tag, FileWatcher)
  db/                # pgx connection helper and migration support
  gapi/              # gRPC server wrapper (TLS, OIDC auth, request logging)
  logger/            # zerolog initialization (JSON / console output)
  models/            # Canonical domain models (User, Workspace, SSHSession, etc.)
  nats/              # NATS/JetStream client (reconnect, KV cache, distributed lock)
  userstr/           # SSH username / workspace identity string parser
  utils/             # General-purpose helpers
  validator/         # Input validation wrappers
```

## Prerequisites

- Go 1.24+
- [`buf`](https://buf.build/docs/installation) (recommended) **or** `protoc` with `protoc-gen-go` and `protoc-gen-go-grpc` plugins — only required to regenerate stubs from proto sources

## Code generation

Generated stubs are committed and kept up to date in CI. You only need to run generation locally when modifying `.proto` files.

**With buf (recommended):**
```bash
cd pkg/api/proto && buf generate
```

**With protoc (fallback):**
```bash
make proto
```

**Lint proto files:**
```bash
make proto-lint
```

**Check for breaking changes against `main`:**
```bash
make proto-breaking
```

## Makefile targets

| Target | Description |
|---|---|
| `make proto` | Generate Go stubs from all `.proto` files (uses `buf` if available, falls back to `protoc`) |
| `make proto-lint` | Run `buf lint` over all proto files |
| `make proto-breaking` | Check for breaking wire changes against the `main` branch |

## Using as a dependency

```bash
go get github.com/k8shell-io/common@latest
```

Import the package you need:

```go
import (
    identityv1  "github.com/k8shell-io/common/pkg/api/gen/go/identity/v1"
    "github.com/k8shell-io/common/pkg/api/client/identity"
    "github.com/k8shell-io/common/pkg/models"
    "github.com/k8shell-io/common/pkg/userstr"
)
```

Services that expose a gRPC endpoint embed `pkg/gapi.Server`; services that dial other k8Shell services use the typed clients in `pkg/api/client/`.

## License

AGPL-3.0-or-later. See [LICENSE](LICENSE).
