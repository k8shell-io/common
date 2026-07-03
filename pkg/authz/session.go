// Copyright 2026 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package authz

// Contract: session:start
//
// Resource  type="workspace"
//   id             workspace name            (required)
//   owner          workspace owner username  (required)
//   blueprint      blueprint name            (optional)
//
// Context
//   session_type    shell | tcpip | exec | sftp  (required)
//   session_source  ssh-proxy | api-server   (required)
//
// Subject   injected by the backend from JWT claims (username, roles, email, ...)
//
// Obligations
//   record  none | shell,exec,direct-tcpip,sftp  (comma-separated channel tokens)
//
// ---
//
// Contract: session:list
//
// Resource  type="workspace"
//   id     workspace name           (optional — omit to list across workspaces)
//   owner  workspace owner username (optional — omit to list all sessions;
//                                    required when id is set)
//
// Context   (none)
//
// Subject   injected by the backend from JWT claims (username, roles, email, ...)
//
// Obligations — exactly these three keys; no other obligation is defined for
// session:list.
//   roles     JSON array of role name strings — the enforcer lists only
//             sessions belonging to users who have at least one of these
//             roles (e.g. ["admin","dev"]). Same key/type as user:list's
//             roles obligation — parse with ParseRolesObligation.
//   org       organization name — the enforcer lists only sessions belonging
//             to users in this org. Same key/type as user:list's org
//             obligation — parse with ParseOrgObligation.
//   username  a single username — the enforcer lists only sessions owned by
//             this user. Parse with ParseUsernameObligation.
//
//             Each key is independent and optional; when absent, that
//             dimension is unrestricted. When present, dimensions combine
//             with AND (e.g. roles + org means "has one of these roles AND
//             is in this org").
//
// Scope matrix:
//   id set,    owner set   → sessions for one workspace
//   id empty,  owner set   → sessions for all workspaces owned by that user
//   id empty,  owner empty → all sessions (admin)

import (
	"fmt"
	"strings"

	authzv1 "github.com/k8shell-io/common/pkg/api/gen/go/authz/v1"
)

// SessionAction is the typed representation of a session policy action.
type SessionAction string

const (
	// SessionActionStart is the action evaluated when a new session is being
	// established. The policy result may carry a "record" obligation that
	// instructs the enforcer what kind of recording to apply to the session.
	SessionActionStart SessionAction = "session:start"

	// SessionActionList is the action evaluated when listing sessions. The
	// scope is controlled by the resource fields: both id and owner set scopes
	// to one workspace; owner only scopes to a user; neither means all sessions.
	SessionActionList SessionAction = "session:list"
)

// validSessionActions is the set of recognized session actions for fast lookup.
var validSessionActions = map[SessionAction]struct{}{
	SessionActionStart: {},
	SessionActionList:  {},
}

// SessionType describes the kind of session being established.
type SessionType string

const (
	// SessionTypeShell is an interactive shell/PTY session (terminal recording).
	SessionTypeShell SessionType = "shell"

	// SessionTypeTCPIP is a TCP/IP port-forwarding session (network traffic recording).
	SessionTypeTCPIP SessionType = "tcpip"

	// SessionTypeExec is a non-interactive exec session (single command, no PTY).
	SessionTypeExec SessionType = "exec"

	// SessionTypeSFTP is an SFTP subsystem session (file transfer).
	SessionTypeSFTP SessionType = "sftp"
)

// validSessionTypes is the set of recognized session types for fast lookup.
var validSessionTypes = map[SessionType]struct{}{
	SessionTypeShell: {},
	SessionTypeTCPIP: {},
	SessionTypeExec:  {},
	SessionTypeSFTP:  {},
}

// SessionSource identifies the component that initiated the session.
type SessionSource string

const (
	// SessionSourceSSHProxy is set when the session originates from the SSH proxy.
	SessionSourceSSHProxy SessionSource = "ssh-proxy"

	// SessionSourceAPIServer is set when the session originates from the API server.
	SessionSourceAPIServer SessionSource = "api-server"
)

// validSessionSources is the set of recognized session sources for fast lookup.
var validSessionSources = map[SessionSource]struct{}{
	SessionSourceSSHProxy:  {},
	SessionSourceAPIServer: {},
}

// SessionContext holds the ambient session attributes supplied by the caller
// in the context map of the EvaluateRequest.
type SessionContext struct {
	// Type is the kind of session being established (context["session_type"]).
	Type SessionType

	// Source is the component that initiated the session (context["session_source"]).
	Source SessionSource
}

// SessionStartEvalRequest is the validated, typed model for session policy evaluation.
// Use NewSessionStartEvalRequest to start building, then chain With* methods and call
// Build to get a validated instance. Use SessionStartEvalRequestFromProto to convert
// directly from a gRPC EvaluateRequest.
type SessionStartEvalRequest struct {
	Action   SessionAction
	Resource WorkspaceResource
	Context  SessionContext
}

var _ EvalRequest = (*SessionStartEvalRequest)(nil)

// NewSessionStartEvalRequest begins building a SessionStartEvalRequest for the given
// action, workspace ID, and session type. Chain With* methods to supply
// additional fields, then call Build to validate and obtain the final struct.
func NewSessionStartEvalRequest(action SessionAction, workspaceID string, sessionType SessionType) *SessionStartEvalRequest {
	return &SessionStartEvalRequest{
		Action:   action,
		Resource: WorkspaceResource{ID: workspaceID},
		Context:  SessionContext{Type: sessionType},
	}
}

// WithSource sets the session source on the context.
func (r *SessionStartEvalRequest) WithSource(source SessionSource) *SessionStartEvalRequest {
	r.Context.Source = source
	return r
}

// WithOwner sets the workspace owner on the resource.
func (r *SessionStartEvalRequest) WithOwner(owner string) *SessionStartEvalRequest {
	r.Resource.Owner = owner
	return r
}

// WithBlueprint sets the blueprint name on the resource.
func (r *SessionStartEvalRequest) WithBlueprint(blueprint string) *SessionStartEvalRequest {
	r.Resource.Blueprint = blueprint
	return r
}

// Build validates the request and returns it if all constraints are satisfied.
// It is the required terminator for the builder chain.
func (r *SessionStartEvalRequest) Build() (*SessionStartEvalRequest, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return r, nil
}

// ToProto serializes the typed request into a gRPC EvaluateRequest, attaching
// the supplied JWT token. Only non-empty resource attributes are included.
// Implements EvalRequest.
func (r *SessionStartEvalRequest) ToProto(token string) *authzv1.EvaluateRequest {
	attrs := map[string]string{
		"owner": r.Resource.Owner,
	}
	if r.Resource.Blueprint != "" {
		attrs["blueprint"] = r.Resource.Blueprint
	}

	return &authzv1.EvaluateRequest{
		Token:  token,
		Action: string(r.Action),
		Resource: &authzv1.Resource{
			Type:       "workspace",
			Id:         r.Resource.ID,
			Attributes: attrs,
		},
		Context: map[string]string{
			"session_type":   string(r.Context.Type),
			"session_source": string(r.Context.Source),
		},
	}
}

// SessionStartEvalRequestFromProto converts a gRPC EvaluateRequest into a validated
// SessionStartEvalRequest. Returns an error if the request does not conform to the
// session policy contract.
func SessionStartEvalRequestFromProto(req *authzv1.EvaluateRequest) (*SessionStartEvalRequest, error) {
	if req == nil {
		return nil, fmt.Errorf("session: EvaluateRequest is nil")
	}
	if req.Resource == nil {
		return nil, fmt.Errorf("session: resource is nil")
	}
	if req.Resource.Type != "workspace" {
		return nil, fmt.Errorf("session: resource type must be \"workspace\", got %q", req.Resource.Type)
	}

	attrs := req.Resource.Attributes
	ctx := req.Context

	r := &SessionStartEvalRequest{
		Action: SessionAction(req.Action),
		Resource: WorkspaceResource{
			ID:        req.Resource.Id,
			Owner:     attrs["owner"],
			Blueprint: attrs["blueprint"],
		},
		Context: SessionContext{
			Type:   SessionType(ctx["session_type"]),
			Source: SessionSource(ctx["session_source"]),
		},
	}

	if err := r.Validate(); err != nil {
		return nil, err
	}
	return r, nil
}

// Validate checks the request against the session policy contract: the action
// must be recognized, core resource fields must be present, and the session
// type must be a known value.
// Implements EvalRequest.
func (r *SessionStartEvalRequest) Validate() error {
	if _, ok := validSessionActions[r.Action]; !ok {
		return fmt.Errorf("session: unknown action %q", r.Action)
	}
	if r.Resource.ID == "" {
		return fmt.Errorf("session: resource ID (workspace name) is required")
	}
	if r.Resource.Owner == "" {
		return fmt.Errorf("session: resource attribute \"owner\" is required")
	}
	if _, ok := validSessionTypes[r.Context.Type]; !ok {
		return fmt.Errorf("session: context \"session_type\" must be %q, %q, %q, or %q, got %q",
			SessionTypeShell, SessionTypeTCPIP, SessionTypeExec, SessionTypeSFTP, r.Context.Type)
	}
	if _, ok := validSessionSources[r.Context.Source]; !ok {
		return fmt.Errorf("session: context \"session_source\" must be %q or %q, got %q",
			SessionSourceSSHProxy, SessionSourceAPIServer, r.Context.Source)
	}
	return nil
}

// --- session:list ---

// SessionListEvalRequest is the validated, typed model for session:list policy
// evaluation. Both resource fields are optional; their combination controls the
// listing scope (see the contract comment at the top of this file).
type SessionListEvalRequest struct {
	Resource WorkspaceResource
}

var _ EvalRequest = (*SessionListEvalRequest)(nil)

// NewSessionListEvalRequest returns a SessionListEvalRequest ready to be built.
// Chain WithWorkspace and/or WithOwner to narrow the scope, then call Build.
func NewSessionListEvalRequest() *SessionListEvalRequest {
	return &SessionListEvalRequest{}
}

// WithWorkspace sets the workspace name; requires WithOwner to also be called.
func (r *SessionListEvalRequest) WithWorkspace(workspaceID string) *SessionListEvalRequest {
	r.Resource.ID = workspaceID
	return r
}

// WithOwner sets the owner username.
func (r *SessionListEvalRequest) WithOwner(owner string) *SessionListEvalRequest {
	r.Resource.Owner = owner
	return r
}

// Build validates the request and returns it if all constraints are satisfied.
func (r *SessionListEvalRequest) Build() (*SessionListEvalRequest, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return r, nil
}

// ToProto serializes the typed request into a gRPC EvaluateRequest.
// Implements EvalRequest.
func (r *SessionListEvalRequest) ToProto(token string) *authzv1.EvaluateRequest {
	attrs := map[string]string{}
	if r.Resource.Owner != "" {
		attrs["owner"] = r.Resource.Owner
	}
	return &authzv1.EvaluateRequest{
		Token:  token,
		Action: "session:list",
		Resource: &authzv1.Resource{
			Type:       "workspace",
			Id:         r.Resource.ID,
			Attributes: attrs,
		},
	}
}

// SessionListEvalRequestFromProto converts a gRPC EvaluateRequest into a
// validated SessionListEvalRequest.
func SessionListEvalRequestFromProto(req *authzv1.EvaluateRequest) (*SessionListEvalRequest, error) {
	if req == nil {
		return nil, fmt.Errorf("session:list: EvaluateRequest is nil")
	}
	if req.Action != "session:list" {
		return nil, fmt.Errorf("session:list: action must be \"session:list\", got %q", req.Action)
	}
	if req.Resource == nil {
		return nil, fmt.Errorf("session:list: resource is nil")
	}
	if req.Resource.Type != "workspace" {
		return nil, fmt.Errorf("session:list: resource type must be \"workspace\", got %q", req.Resource.Type)
	}
	r := &SessionListEvalRequest{
		Resource: WorkspaceResource{
			ID:    req.Resource.Id,
			Owner: req.Resource.Attributes["owner"],
		},
	}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return r, nil
}

// Validate checks the request: if a workspace id is set, owner must also be set.
// Implements EvalRequest.
func (r *SessionListEvalRequest) Validate() error {
	if r.Resource.ID != "" && r.Resource.Owner == "" {
		return fmt.Errorf("session:list: resource attribute \"owner\" is required when workspace id is set")
	}
	return nil
}

const (
	// ObligationKeyRecord is the key the policy engine writes when expressing a
	// session recording obligation. The enforcer reads this key and activates
	// the appropriate recording backends before the session begins.
	ObligationKeyRecord = "record"

	// ObligationRecordNone explicitly disables all session recording.
	ObligationRecordNone = "none"

	// Recording channel name tokens used as comma-separated values of the
	// "record" obligation key.
	ObligationRecordShell       = "shell"
	ObligationRecordExec        = "exec"
	ObligationRecordDirectTCPIP = "direct-tcpip"
	ObligationRecordSFTP        = "sftp"
)

// RecordObligation is the typed representation of the "record" obligation key
// returned by the policy engine in a PolicyResult for session:start.
// Each field corresponds to one recording channel; all default to false.
type RecordObligation struct {
	Shell       bool
	Exec        bool
	DirectTCPIP bool
	SFTP        bool
}

// ParseRecordObligation reads the "record" key from the obligations map.
// The value is a comma-separated list of channel tokens ("shell", "exec",
// "direct-tcpip", "sftp"); "none" or an unrecognised value leaves all fields
// false. Returns (obligation, true) when the key is present, (zero, false)
// when the policy did not set a record obligation — the enforcer should then
// apply its configured default (typically no recording).
func ParseRecordObligation(obligations map[string]string) (RecordObligation, bool) {
	v, ok := obligations[ObligationKeyRecord]
	if !ok {
		return RecordObligation{}, false
	}
	var ob RecordObligation
	for ch := range strings.SplitSeq(v, ",") {
		switch strings.TrimSpace(ch) {
		case ObligationRecordShell:
			ob.Shell = true
		case ObligationRecordExec:
			ob.Exec = true
		case ObligationRecordDirectTCPIP:
			ob.DirectTCPIP = true
		case ObligationRecordSFTP:
			ob.SFTP = true
		}
	}
	return ob, true
}

const (
	// ObligationKeyUsername is the key the policy engine writes to scope a
	// session:list result to a single session owner. The value is a username.
	ObligationKeyUsername = "username"
)

// UsernameObligation is the typed representation of the "username" obligation
// key returned by the policy engine in a PolicyResult for session:list.
type UsernameObligation struct {
	// Username is the single user the enforcer should restrict the listing to.
	Username string
}

// ParseUsernameObligation reads the "username" key from the obligations map.
// Returns (obligation, true) when the key is present, (zero value, false) when
// the policy did not set a username obligation — in that case the enforcer
// should not scope the listing to a single user.
func ParseUsernameObligation(obligations map[string]string) (UsernameObligation, bool) {
	v, ok := obligations[ObligationKeyUsername]
	if !ok || v == "" {
		return UsernameObligation{}, false
	}
	return UsernameObligation{Username: v}, true
}
