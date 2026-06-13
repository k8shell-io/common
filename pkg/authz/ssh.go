// Copyright 2026 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package authz

// Contract: ssh:shell | ssh:exec | ssh:sftp | ssh:direct-tcpip | ssh:direct-streamlocal | ssh:agent-forward
//
// Resource  type="workspace"
//   id            workspace name            (required)
//   owner         workspace owner username  (required)
//   blueprint     blueprint name            (optional)
//
// Context
//   pty           "true" if PTY requested                           (optional; shell/exec)
//   command       command string                                    (required for exec)
//   host          destination host                                  (required for direct-tcpip)
//   port          destination port                                  (required for direct-tcpip)
//   socket_path   Unix socket path                                  (required for direct-streamlocal)
//   as_user       Linux user to run as inside workspace             (optional; shell/exec)
//
// Subject   injected by the backend from JWT claims (username, roles, email, ...)
//
// Obligations
//   (none)

import (
	"fmt"

	authzv1 "github.com/k8shell-io/common/pkg/api/gen/go/authz/v1"
)

// SSHAction is the typed representation of an SSH policy action.
type SSHAction string

const (
	// SSHActionShell is an interactive PTY session (session channel + shell request).
	SSHActionShell SSHAction = "ssh:shell"

	// SSHActionExec is a non-interactive command execution (session channel + exec request).
	// Also covers SCP.
	SSHActionExec SSHAction = "ssh:exec"

	// SSHActionSFTP is a subsystem "sftp" request on a session channel.
	SSHActionSFTP SSHAction = "ssh:sftp"

	// SSHActionDirectTCPIP is a client-initiated TCP port forward (direct-tcpip channel).
	SSHActionDirectTCPIP SSHAction = "ssh:direct-tcpip"

	// SSHActionDirectStreamlocal is a Unix domain socket forward
	// (direct-streamlocal@openssh.com channel).
	SSHActionDirectStreamlocal SSHAction = "ssh:direct-streamlocal"

	// SSHActionAgentForward is SSH agent forwarding
	// (auth-agent-req@openssh.com session request).
	SSHActionAgentForward SSHAction = "ssh:agent-forward"
)

// validSSHActions is the set of recognized SSH actions for fast lookup.
var validSSHActions = map[SSHAction]struct{}{
	SSHActionShell:             {},
	SSHActionExec:              {},
	SSHActionSFTP:              {},
	SSHActionDirectTCPIP:       {},
	SSHActionDirectStreamlocal: {},
	SSHActionAgentForward:      {},
}

// SSHWorkspaceResource holds the workspace-scoped attributes of the resource
// being accessed.
type SSHWorkspaceResource struct {
	// ID is the workspace name (resource.id in the EvaluateRequest).
	ID string

	// Owner is the username of the workspace owner (resource.attributes["owner"]).
	Owner string

	// BlueprintName is the blueprint the workspace was launched from
	// (resource.attributes["blueprint"]).
	BlueprintName string
}

// SSHContext holds the ambient SSH channel/request attributes supplied by the
// ssh-proxy in the context map of the EvaluateRequest.
type SSHContext struct {
	// PTY is true when a pseudo-terminal was requested (context["pty"] == "true").
	PTY bool

	// Command is the exact command string for ssh:exec channels (context["command"]).
	Command string

	// Host is the destination host for ssh:direct-tcpip channels (context["host"]).
	Host string

	// Port is the destination port for ssh:direct-tcpip channels (context["port"]).
	Port string

	// SocketPath is the Unix socket path for ssh:direct-streamlocal channels
	// (context["socket_path"]).
	SocketPath string

	// AsUser is the Linux user the session runs as inside the workspace
	// (context["as_user"]). Optional; empty means the workspace default user.
	AsUser string
}

// SSHEvalRequest is the validated, typed model for SSH policy evaluation.
// Use NewSSHEvalRequest to start building, then chain With* methods and call
// Build to get a validated instance. Use SSHEvalRequestFromProto to convert
// directly from a gRPC EvaluateRequest.
type SSHEvalRequest struct {
	Action   SSHAction
	Resource SSHWorkspaceResource
	Context  SSHContext
}

var _ EvalRequest = (*SSHEvalRequest)(nil)

// NewSSHEvalRequest begins building an SSHEvalRequest for the given action and
// workspace ID. Chain With* methods to supply additional fields, then call
// Build to validate and obtain the final struct.
func NewSSHEvalRequest(action SSHAction, workspaceID string) *SSHEvalRequest {
	return &SSHEvalRequest{
		Action:   action,
		Resource: SSHWorkspaceResource{ID: workspaceID},
	}
}

// WithOwner sets the workspace owner on the resource.
func (r *SSHEvalRequest) WithOwner(owner string) *SSHEvalRequest {
	r.Resource.Owner = owner
	return r
}

// WithBlueprintName sets the blueprint name on the resource.
func (r *SSHEvalRequest) WithBlueprintName(blueprint string) *SSHEvalRequest {
	r.Resource.BlueprintName = blueprint
	return r
}

// WithPTY records whether a pseudo-terminal was requested.
func (r *SSHEvalRequest) WithPTY(pty bool) *SSHEvalRequest {
	r.Context.PTY = pty
	return r
}

// WithCommand sets the command string; required for SSHActionExec.
func (r *SSHEvalRequest) WithCommand(cmd string) *SSHEvalRequest {
	r.Context.Command = cmd
	return r
}

// WithHost sets the destination host; required for SSHActionDirectTCPIP.
func (r *SSHEvalRequest) WithHost(host string) *SSHEvalRequest {
	r.Context.Host = host
	return r
}

// WithPort sets the destination port; required for SSHActionDirectTCPIP.
func (r *SSHEvalRequest) WithPort(port string) *SSHEvalRequest {
	r.Context.Port = port
	return r
}

// WithSocketPath sets the Unix socket path; required for SSHActionDirectStreamlocal.
func (r *SSHEvalRequest) WithSocketPath(path string) *SSHEvalRequest {
	r.Context.SocketPath = path
	return r
}

// WithAsUser sets the Linux user the session runs as inside the workspace.
// Optional for SSHActionShell and SSHActionExec; empty means the workspace default user.
func (r *SSHEvalRequest) WithAsUser(user string) *SSHEvalRequest {
	r.Context.AsUser = user
	return r
}

// Build validates the request and returns it if all constraints are satisfied.
// It is the required terminator for the builder chain.
func (r *SSHEvalRequest) Build() (*SSHEvalRequest, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return r, nil
}

// ToProto serializes the typed request into a gRPC EvaluateRequest, attaching
// the supplied JWT token. Only non-empty / non-default context fields are
// included in the context map.
// Implements EvalRequest.
func (r *SSHEvalRequest) ToProto(token string) *authzv1.EvaluateRequest {
	attrs := map[string]string{
		"owner": r.Resource.Owner,
	}
	if r.Resource.BlueprintName != "" {
		attrs["blueprint"] = r.Resource.BlueprintName
	}

	ctx := map[string]string{}
	if r.Context.PTY {
		ctx["pty"] = "true"
	}
	if r.Context.Command != "" {
		ctx["command"] = r.Context.Command
	}
	if r.Context.Host != "" {
		ctx["host"] = r.Context.Host
	}
	if r.Context.Port != "" {
		ctx["port"] = r.Context.Port
	}
	if r.Context.SocketPath != "" {
		ctx["socket_path"] = r.Context.SocketPath
	}
	if r.Context.AsUser != "" {
		ctx["as_user"] = r.Context.AsUser
	}

	return &authzv1.EvaluateRequest{
		Token:  token,
		Action: string(r.Action),
		Resource: &authzv1.Resource{
			Type:       "workspace",
			Id:         r.Resource.ID,
			Attributes: attrs,
		},
		Context: ctx,
	}
}

// SSHEvalRequestFromProto converts a gRPC EvaluateRequest into a validated
// SSHEvalRequest. Returns an error if the request does not conform to the SSH
// policy contract.
func SSHEvalRequestFromProto(req *authzv1.EvaluateRequest) (*SSHEvalRequest, error) {
	if req == nil {
		return nil, fmt.Errorf("ssh: EvaluateRequest is nil")
	}
	if req.Resource == nil {
		return nil, fmt.Errorf("ssh: resource is nil")
	}
	if req.Resource.Type != "workspace" {
		return nil, fmt.Errorf("ssh: resource type must be \"workspace\", got %q", req.Resource.Type)
	}

	attrs := req.Resource.Attributes
	ctx := req.Context

	r := &SSHEvalRequest{
		Action: SSHAction(req.Action),
		Resource: SSHWorkspaceResource{
			ID:            req.Resource.Id,
			Owner:         attrs["owner"],
			BlueprintName: attrs["blueprint"],
		},
		Context: SSHContext{
			PTY:        ctx["pty"] == "true",
			Command:    ctx["command"],
			Host:       ctx["host"],
			Port:       ctx["port"],
			SocketPath: ctx["socket_path"],
			AsUser:     ctx["as_user"],
		},
	}

	if err := r.Validate(); err != nil {
		return nil, err
	}
	return r, nil
}

// Validate checks the request against the SSH policy contract: the action must
// be recognized, core resource fields must be present, and each action enforces
// its own required context fields.
// Implements EvalRequest.
func (r *SSHEvalRequest) Validate() error {
	if _, ok := validSSHActions[r.Action]; !ok {
		return fmt.Errorf("ssh: unknown action %q", r.Action)
	}
	if r.Resource.ID == "" {
		return fmt.Errorf("ssh: resource ID (workspace name) is required")
	}
	if r.Resource.Owner == "" {
		return fmt.Errorf("ssh: resource attribute \"owner\" is required")
	}

	switch r.Action {
	case SSHActionExec:
		if r.Context.Command == "" {
			return fmt.Errorf("ssh: context \"command\" is required for action %q", r.Action)
		}
	case SSHActionDirectTCPIP:
		if r.Context.Host == "" {
			return fmt.Errorf("ssh: context \"host\" is required for action %q", r.Action)
		}
		if r.Context.Port == "" {
			return fmt.Errorf("ssh: context \"port\" is required for action %q", r.Action)
		}
	case SSHActionDirectStreamlocal:
		if r.Context.SocketPath == "" {
			return fmt.Errorf("ssh: context \"socket_path\" is required for action %q", r.Action)
		}
	}

	return nil
}
