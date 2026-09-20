# CLAUDE-SHARED.md

Cross-service knowledge for AI agents working anywhere in the k8Shell fleet.
Each service repo imports this file from the top of its own `CLAUDE.md` with:

```
@common/CLAUDE-SHARED.md
```

That path resolves once `common` is checked out (or symlinked, e.g. via a
`debug-setup`-style make target) next to the service's source. If it isn't
present — a plain clone without that setup step, or CI — the import simply
doesn't resolve and this content is skipped; there is no error, but the agent
loses this context, so treat linking `common` as a prerequisite for full
awareness of fleet-wide conventions.

## Service map

k8Shell is a gateway-plus-backends system, with two separate access points
into the fleet: `api-server` for HTTP/browser traffic and `ssh-proxy` (guarded
by `ssh-shield`) for SSH-based flows. Everything else is reached through one
of those via gRPC, backed by the infrastructure below.

| Service | Owns |
|---|---|
| `api-server` | HTTP/gRPC gateway: session cookies, JWT/PAT auth, authz enforcement for HTTP flows, port-forwarding to workspace pods, routing to every backend below |
| `ssh-proxy` | SSH access point: enforces authz for SSH-based flows (its own authz contracts, separate from api-server's) |
| `ssh-shield` | SSH brute-force protection: tracks login attempts per IP in a rolling window and calls a downstream service to block the IP at the SSH gateway node when abusive |
| `identity` | User accounts, login/auth, PAT (personal access token) lifecycle, credential resolution — federates login to the IdPs below |
| `session` | Shell session recording and listing |
| `provisioner` | Workspace CRUD and async provisioning jobs; enforces its own authz contracts for workspace provisioning |
| `k8shelld` | Per-workspace-pod agent: terminal sessions, file ops, installed apps, sysinfo — one instance per running workspace pod |
| `authz` | OPA/Rego policy evaluation — every protected action in every service is authorized through here |
| `frontend` | Web UI consuming `api-server`'s HTTP API |
| `common` | Shared Go module: generated gRPC stubs, models, authz contracts, config/logging helpers — depended on by every service above |

### Infrastructure

| Component | Purpose |
|---|---|
| PostgreSQL (`db-postgresql`) | Primary relational datastore backing the fleet's services |
| NATS JetStream (`nats-0/1/2`) | Messaging/KV backbone — e.g. `api-server`'s session and job-queue KV buckets (see its own `CLAUDE.md`) |
| IdPs (`idp-github`, `idp-ctufit`, ...) | External OAuth/OIDC identity providers that `identity` federates login to |

If you're an agent working in one of these repos and need to understand a
*caller or callee* service's behavior rather than your own, its source may not
be checked out in your workspace — say so rather than guessing at its
internals from this table alone.

## Local development against `common`

A dev/agent session may run inside a workspace pod where the live service is
already running — detect this via the `WORKLOAD_KIND` / `WORKLOAD_NAME` env
vars (`ps` also shows the sibling process sharing the pod's PID namespace).

In that case, the service's source is linked with `common` via `go.work`
(commonly set up by a `make debug-setup`-style target that generates
`go.work` and symlinks the live `common` checkout into the repo as `common/`).
This lets you edit `common` directly to prototype a cross-cutting change —
**do not commit changes made to `common` from inside a service's workspace**;
land them as a deliberate, separate change in the `common` repo, tagged and
picked up by services via their own dependency-bump step (e.g. `go get
github.com/k8shell-io/common@<version> && go mod tidy`).

## Debugging with kubectl

A dev/agent session may have `kubectl` available against the live cluster —
useful for inspecting real resources (pod status, logs, describe) across any
of the services in the map above while debugging an issue. The namespace to
inspect is given by the `WORKLOAD_NAMESPACE` env var (see "Local development
against `common`" above for the related `WORKLOAD_KIND`/`WORKLOAD_NAME` vars).
Read-only inspection (`get`, `describe`, `logs`, etc.) is fine to run on your
own judgment. Anything that changes cluster state (`apply`, `delete`, `edit`,
`scale`, `rollout restart`, exec-ing commands that mutate a pod, etc.) must be
explicitly approved by a human first — don't run it on your own initiative.

## Adding a new API endpoint

Request/response payload structs go in `common`'s `pkg/models`, not in the
service repo, so every consumer (other services, the frontend) shares the
same type instead of hand-rolling a duplicate.

## Cross-service feature contracts

**STEP 0, before writing or reading any code for a named feature:** run `ls
common/docs/features/` and match the feature name against existing
folders. If a matching folder is found, read its `README.md` and every other 
service's `<service>.md` file —  especially any "Questions for `<my service>`" section — 
before touching source. Do this even if the user's request doesn't mention other 
services by name; a single-word feature name is enough to trigger this.

**Trigger**: whenever the user says something of the shape "we are working on
feature `<name>` across `<service A>`, `<service B>`, ..." (or otherwise names
a feature and the services it spans), treat that as an instruction to use
`common/docs/features/<slug>/` as the shared contract for that feature —
derive `<slug>` from the feature name (kebab-case) unless the user gives one.
Don't wait to be told the file path explicitly.

Layout, to avoid two agents ever writing the same file concurrently:

- `common/docs/features/<slug>/README.md` — the agent map: one row per
  participating service with its role and status, linking to its file below.
  Add or update your own row when you join; leave others' rows alone.
- `common/docs/features/<slug>/<your-service-name>.md` — **you own this file.
  Only you write it; everyone else only reads it.** Put your part of the
  contract here: for the producing side (e.g. `api-server` designing an
  endpoint `frontend` will consume), endpoint method/path, request/response
  shape (point at the `pkg/models` struct rather than restating it),
  auth/authz requirements, error cases. For the consuming side, read the
  producing service's file instead of waiting for the contract to be relayed
  to you by hand.
- If you need something from another service or have a question for them,
  write it in **your own** file (e.g. a "Questions for api-server" section in
  `frontend.md`) rather than editing theirs — they'll read it there.
- If you discover mid-feature that another service needs to join the flow,
  add its row to `README.md` and note in your own file what changed for the
  services already involved. The human still needs to tell those agents to
  re-read the folder — there's no push notification between agent sessions.

This is a short-lived working folder, not permanent reference — delete it (or
fold anything worth keeping into permanent docs) once the feature ships.

## Authz contracts

Three services enforce OPA/Rego policy checks directly and own the
`common/pkg/authz` contracts for their own flows — everything else trusts one
of these rather than re-checking authz itself:

- `api-server` — HTTP/gRPC flows (`checkAuthz`/`checkSessionAuthz`)
- `ssh-proxy` — SSH-based flows
- `provisioner` — workspace provisioning

If you're adding a new protected action, the contract belongs in whichever of
these three actually enforces that flow — see that repo's own `CLAUDE.md` for
the process. If you're working in a different service, you generally won't
need to touch this.
