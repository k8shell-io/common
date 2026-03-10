package authz

// This file shows "how it links together" conceptually.
// There is no DB: you load users.yaml into User objects,
// load policy.yaml into PolicyDocument, and evaluate per request.

type UserModel struct {
	Username     string   `yaml:"username" json:"username"`
	Organization string   `yaml:"organization" json:"organization"`
	Roles        []string `yaml:"roles" json:"roles"`

	AuthKeys []string `yaml:"authKeys" json:"authKeys"` // configured keys
}

// Subject is built from your User object (Username + Roles + Organization later).
type Subject struct {
	Username string
	Roles    []string
}

// Action is the operation the caller is trying to perform.
//
// Intentionally a string enum so:
// - config files can remain readable
// - JSON/YAML round-tripping remains stable
// - external services can introduce additional actions without changing wire formats
type Action string

const (
	ActionWebTerminal    Action = "web.terminal"
	ActionAuthPassword   Action = "auth.password"
	ActionSSHExec        Action = "ssh.exec"
	ActionSSHPortForward Action = "ssh.port_forward"
)

// ObjectKind describes the type of resource being accessed.
//
// Keep this intentionally broad: the API server can authorize many kinds of
// entities (users, tokens, blueprints, etc.) and not all of them live in this
// repo.
type ObjectKind string

const (
	ObjectKindWorkspace ObjectKind = "workspace"
	ObjectKindUser      ObjectKind = "user"
	ObjectKindBlueprint ObjectKind = "blueprint"
	ObjectKindToken     ObjectKind = "token"
	ObjectKindUnknown   ObjectKind = "unknown"
)

// Workspace is the resource being accessed.
// It links to Blueprint and Owner so selectors can match.
type Workspace struct {
	ID        string
	Blueprint string // blueprint name/id that created it
	Owner     string // username of the owner (the "personal workspace" concept)
}

// Object is the resource being accessed.
//
// - For workspaces, populate Workspace and set Kind=workspace.
// - For everything else, set Kind/ID and optionally supply Attrs.
//
// Policy evaluation can match on Kind/ID and any fields in Workspace / Attrs.
type Object struct {
	Kind ObjectKind `yaml:"kind" json:"kind"`
	ID   string     `yaml:"id"   json:"id"`

	Workspace *Workspace     `yaml:"workspace,omitempty" json:"workspace,omitempty"`
	Attrs     map[string]any `yaml:"attrs,omitempty"     json:"attrs,omitempty"`
}

func WorkspaceObject(ws Workspace) Object {
	wsCopy := ws
	return Object{
		Kind:      ObjectKindWorkspace,
		ID:        ws.ID,
		Workspace: &wsCopy,
	}
}

func EntityObject(kind ObjectKind, id string, attrs map[string]any) Object {
	if kind == "" {
		kind = ObjectKindUnknown
	}
	if attrs == nil {
		attrs = map[string]any{}
	}
	return Object{
		Kind:  kind,
		ID:    id,
		Attrs: attrs,
	}
}

// Context is request-scoped data that constraints may inspect.
//
// It is intentionally un-opinionated: different actions can attach different
// fields. Keep keys stable across services.
type Context map[string]any

const (
	ContextKeyCommand      = "command"
	ContextKeyPort         = "port"
	ContextKeyPTYRequested = "ptyRequested"
	ContextKeyAuthMethod   = "authMethod" // e.g. "password" | "publickey" | "oidc"
)

// Request is what your API/SSH layer asks the authorizer.
type Request struct {
	Subject Subject
	Object  Object
	Action  Action
	Context Context
}

func SubjectFromUser(u UserModel) Subject {
	return Subject{
		Username: u.Username,
		Roles:    append([]string{}, u.Roles...),
	}
}

// Example: authorize a web terminal websocket to a workspace.
func ExampleWebTerminalRequest(u UserModel, ws Workspace) Request {
	return Request{
		Subject: SubjectFromUser(u),
		Object:  WorkspaceObject(ws),
		Action:  ActionWebTerminal,
	}
}

// Example: authorize SSH password auth attempt (policy likely denies by default).
func ExampleSSHPasswordAuth(u UserModel, ws Workspace) Request {
	return Request{
		Subject: SubjectFromUser(u),
		Object:  WorkspaceObject(ws),
		Action:  ActionAuthPassword,
		Context: Context{
			ContextKeyAuthMethod: "password",
		},
	}
}

// Example: authorize exec request with command constraint checks.
func ExampleSSHExec(u UserModel, ws Workspace, cmd string) Request {
	return Request{
		Subject: SubjectFromUser(u),
		Object:  WorkspaceObject(ws),
		Action:  ActionSSHExec,
		Context: Context{
			ContextKeyCommand: cmd,
		},
	}
}

// Extend Constraints with a WorkspaceSecurityProfile. This profile will be
// compiled to Tetragon policies when provisioning or updating a workspace.
type Constraints struct {
	// ---- Exec/Shell controls ----
	AllowedCommands []string `yaml:"allowedCommands,omitempty" json:"allowedCommands,omitempty"`
	DeniedCommands  []string `yaml:"deniedCommands,omitempty" json:"deniedCommands,omitempty"`
	RequirePTY      *bool    `yaml:"requirePTY,omitempty" json:"requirePTY,omitempty"`
	AllowPTY        *bool    `yaml:"allowPTY,omitempty" json:"allowPTY,omitempty"`

	// ---- Port forward controls ----
	AllowedPortRanges []string `yaml:"allowedPortRanges,omitempty" json:"allowedPortRanges,omitempty"`
	DeniedPorts       []int    `yaml:"deniedPorts,omitempty" json:"deniedPorts,omitempty"`

	// ---- Misc SSH channel features ----
	AllowAgentForwarding *bool `yaml:"allowAgentForwarding,omitempty" json:"allowAgentForwarding,omitempty"`

	// ---- Workspace runtime security (new) ----
	WorkspaceSecurity *WorkspaceSecurityProfile `yaml:"workspaceSecurity,omitempty" json:"workspaceSecurity,omitempty"`
}

// WorkspaceSecurityProfile describes restrictions enforced *inside* the workspace.
// Think of it as “what this workspace is allowed to do at runtime”.
type WorkspaceSecurityProfile struct {
	// Exec constraints (process-level)
	Exec *ExecPolicy `yaml:"exec,omitempty" json:"exec,omitempty"`

	// Syscall constraints (kernel-level)
	Syscalls *SyscallPolicy `yaml:"syscalls,omitempty" json:"syscalls,omitempty"`

	// Optional: file/network policies if you plan to express them later via Tetragon
	// or other mechanisms.
	Network *NetworkPolicy `yaml:"network,omitempty" json:"network,omitempty"`
}

type ExecPolicy struct {
	// Allowlist/denylist of executed binaries (paths). You can also support globbing.
	AllowedPaths []string `yaml:"allowedPaths,omitempty" json:"allowedPaths,omitempty"`
	DeniedPaths  []string `yaml:"deniedPaths,omitempty" json:"deniedPaths,omitempty"`

	// Optional: deny execution when running as root, etc.
	DenyAsRoot *bool `yaml:"denyAsRoot,omitempty" json:"denyAsRoot,omitempty"`

	// Optional: restrict by argv patterns (be careful: fragile).
	DeniedArgvContains []string `yaml:"deniedArgvContains,omitempty" json:"deniedArgvContains,omitempty"`
}

type SyscallPolicy struct {
	// Choose one approach:
	// - Allowed list (deny all others) OR
	// - Denied list (allow all others)
	Allowed []string `yaml:"allowed,omitempty" json:"allowed,omitempty"`
	Denied  []string `yaml:"denied,omitempty" json:"denied,omitempty"`

	// Optional: architecture filters, etc.
	Architectures []string `yaml:"architectures,omitempty" json:"architectures,omitempty"`
}

type NetworkPolicy struct {
	// Example placeholders; whether you can enforce these via Tetragon depends
	// on what you implement.
	DeniedPorts []int `yaml:"deniedPorts,omitempty" json:"deniedPorts,omitempty"`
}
