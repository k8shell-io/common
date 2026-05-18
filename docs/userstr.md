---
sidebar_position: 4
---

# User String

The **User String** (`USERSTR`) is the user portion of the SSH connection string—the substring before the `@` delimiter. It is a compact identifier that represents a user together with an optional workspace specification. The workspace can be specified as:

- an **explicit blueprint name** (`bp-name`), or
- a **parameter list** that describes a git-based or named workspace.

## Grammar

```ebnf
USERSTR        ::= USER [ "~" WS_SPEC ]

WS_SPEC        ::= BP_FORM | PARAM_LIST

; Blueprint form: first segment contains no "="
BP_FORM        ::= BP_NAME *( "+" KV )
BP_NAME        ::= <url-path-escaped string>      ; decoded with url.PathUnescape

; Parameter-list form: all segments are key=value pairs
PARAM_LIST     ::= KV *( "+" KV )
KV             ::= KEY "=" VALUE

KEY            ::= "repo" | "ref" | "user" | "pod" | "ns" | "workload"
VALUE          ::= <url-path-escaped string>      ; decoded with url.PathUnescape

USER           ::= 1*( ALPHA / DIGIT / "_" / "-" )

DELIMS         ::= "@" | "~" | "+" | "="
```

### Base64-wrapped user strings

A whole `USERSTR` may be provided as a raw base64url token:

```ebnf
USERSTR ::= ( "b64-" | "base64-" ) b64url-raw
```

This token is decoded (base64url **raw**, **no padding**) into a plain `USERSTR`, which is then parsed normally.

## Forms

There are four distinct forms a user string can take:

| Form | Description |
|------|-------------|
| **Implicit** | `alice` — username only; workspace is resolved from user defaults. |
| **Explicit blueprint** | `alice~dev` — blueprint name given literally after `~`. Optional `workload`, `ns`, and `user` params may follow. |
| **Named workspace** | `alice~pod=ws1` — targets a specific running pod by name. Optional `ns` and `user` params allowed. |
| **Repo workspace** | `alice~repo=org/proj` — git-based blueprint computed from repo. Optional `ref`, `workload`, `ns`, and `user` params allowed. |

## Parameters

| Key | Allowed in forms | Case | Description |
|-----|-----------------|------|-------------|
| `repo` | Repo workspace | lowercase | Repository in `owner/name` or bare `name` format. Owner defaults to username if omitted. |
| `ref` | Repo workspace | lowercase | Branch, tag, or commit ref. |
| `user` | All forms | lowercase | Override the OS user inside the workspace container. |
| `pod` | Named workspace | lowercase | Name of a specific running workspace pod to connect to. |
| `ns` | Explicit blueprint, Named workspace, Repo workspace | lowercase | Kubernetes namespace. Required when `workload` is set; must not appear without `workload` (in blueprint and repo forms). |
| `workload` | Explicit blueprint, Repo workspace | lowercase | Kubernetes workload to inject into, in `kind/name` format (e.g. `deployment/identity`, `statefulset/postgres`, `daemonset/agent`). Must be paired with `ns`. |

## Parsing, decoding, and normalization rules

| Rule | Description |
|------|-------------|
| Whitespace | Leading/trailing whitespace is trimmed before parsing. |
| Case: username | Usernames are normalized to lowercase. |
| Case: keys | Parameter keys are normalized to lowercase. |
| Case: most values | Parameter values (other than `workload`) are normalized to lowercase. |
| Case: `workload` value | The `workload` value is normalized to lowercase. |
| Form detection | If the first segment after `~` contains **no** `=`, it is treated as a blueprint name. Otherwise all segments are treated as `key=value` pairs. |
| Percent-decoding | `url.PathUnescape` is applied to blueprint names and to all parameter values (not keys). |
| Slash `/` in values | `/` is allowed inside values (e.g. `repo=org/proj`, `workload=Deployment/identity`). When encoded as `%2F` it is decoded back to `/`. |
| Reserved delimiters | `@`, `~`, `+`, `=` are syntax delimiters. To use them literally inside a value, percent-encode them (`%40`, `%7E`, `%2B`, `%3D`). |
| `workload` + `ns` pairing | `workload` and `ns` must always appear together. Specifying one without the other is an error. |
| `pod` exclusivity | `pod` cannot be combined with `repo` or `workload`. |
| Maximum length | Total user string length ≤ 128 characters. |

> **Note:** Some clients require certain characters in the user string to be URL-encoded.
> For example, Visual Studio Code's `code` CLI and `scp` may require the slash (`/`) character to be percent-encoded, whereas the standard `ssh` CLI often accepts it without encoding.

## Semantics

### Implicit form

No workspace spec is given. The workspace blueprint is resolved from the user's default settings.

### Explicit blueprint form

The first segment after `~` (no `=` present) is decoded with `url.PathUnescape` and used as an **explicit** blueprint name. The optional `workload` and `ns` params target a specific Kubernetes workload within a namespace.

### Named workspace form

`pod` is the primary key. The value is the name of a specific running workspace pod. `ns` may optionally narrow the namespace. Cannot be combined with `repo` or `workload`.

### Repo workspace form

- `repo` determines the git blueprint source.
- Owner defaults to the username when `repo=<name>` (no slash).
- `repo=<owner>/<name>` sets both owner and name explicitly.
- The computed blueprint name is `repo-<repoOwner>-<repoName>`.
- `ref` pins a branch, tag, or commit.
- `workload` and `ns` (paired) target a specific Kubernetes workload.

### `workload` value format

The `workload` value uses the format `kind/name`, where `kind` is the lowercase Kubernetes resource kind and `name` is the resource name:

```
workload=deployment/identity
workload=statefulset/postgres
workload=daemonset/agent
```

When `workload` is set, no workspace name is generated — the workload itself is the injection target.

## Examples

### User only (implicit blueprint)

```text
alice
```

- `username=alice`, no workspace spec → implicit blueprint.

### Explicit blueprint name

```text
bob~dev
```

- `username=bob`, `blueprint=dev`.

### Explicit blueprint with workload injection

```text
bob~dev+workload=Deployment%2Fidentity+ns=team-a
```

- `username=bob`, `blueprint=dev`
- `workloadKind=deployment`, `workloadName=identity`, `namespace=team-a`

### Git-based blueprint

```text
carol~repo=myorg%2Fproject1
```

- `username=carol`, `repoOwner=myorg`, `repoName=project1`
- computed `blueprint=repo-myorg-project1`

### Git-based blueprint with ref

```text
eve~repo=acme/portal+ref=v1.2
```

- `username=eve`, `repoOwner=acme`, `repoName=portal`, `repoRef=v1.2`
- computed `blueprint=repo-acme-portal`

### Git-based blueprint with workload injection

```text
alice~repo=org/proj+workload=Deployment%2Fidentity+ns=k8s-test
```

- `username=alice`, `repoOwner=org`, `repoName=proj`
- `workloadKind=deployment`, `workloadName=identity`, `namespace=k8s-test`
- computed `blueprint=repo-org-proj`

### Named workspace (pod)

```text
alice~pod=workspace1+ns=team-a
```

- `username=alice`, `pod=workspace1`, `namespace=team-a`

### Override container user

```text
alice~dev+user=root
```

- `username=alice`, `blueprint=dev`, container OS user overridden to `root`.

### Base64-wrapped user string

```text
b64-ZXZlfnJlcG89YWNtZS9wb3J0YWwrcmVmPXYxLjI
```

Decodes to `eve~repo=acme/portal+ref=v1.2`, then parsed normally.
