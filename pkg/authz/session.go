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
//   session_type    shell | tcpip            (required)
//   session_source  ssh-proxy | api-server   (required)
//
// Subject   injected by the backend from JWT claims (username, roles, email, ...)
//
// Obligations
//   record  none | shell,exec,direct-tcpip  (comma-separated channel tokens)

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
)

// validSessionActions is the set of recognized session actions for fast lookup.
var validSessionActions = map[SessionAction]struct{}{
	SessionActionStart: {},
}

// SessionType describes the kind of session being established.
type SessionType string

const (
	// SessionTypeShell is an interactive shell/PTY session (terminal recording).
	SessionTypeShell SessionType = "shell"

	// SessionTypeTCPIP is a TCP/IP port-forwarding session (network traffic recording).
	SessionTypeTCPIP SessionType = "tcpip"
)

// validSessionTypes is the set of recognized session types for fast lookup.
var validSessionTypes = map[SessionType]struct{}{
	SessionTypeShell: {},
	SessionTypeTCPIP: {},
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

// SessionWorkspaceResource holds the workspace-scoped attributes of the resource
// being accessed.
type SessionWorkspaceResource struct {
	// ID is the workspace name (resource.id in the EvaluateRequest).
	ID string

	// Owner is the username of the workspace owner (resource.attributes["owner"]).
	Owner string

	// Blueprint is the blueprint the workspace was launched from
	// (resource.attributes["blueprint"]).
	Blueprint string
}

// SessionContext holds the ambient session attributes supplied by the caller
// in the context map of the EvaluateRequest.
type SessionContext struct {
	// Type is the kind of session being established (context["session_type"]).
	Type SessionType

	// Source is the component that initiated the session (context["session_source"]).
	Source SessionSource
}

// SessionEvalRequest is the validated, typed model for session policy evaluation.
// Use NewSessionEvalRequest to start building, then chain With* methods and call
// Build to get a validated instance. Use SessionEvalRequestFromProto to convert
// directly from a gRPC EvaluateRequest.
type SessionEvalRequest struct {
	Action   SessionAction
	Resource SessionWorkspaceResource
	Context  SessionContext
}

var _ EvalRequest = (*SessionEvalRequest)(nil)

// NewSessionEvalRequest begins building a SessionEvalRequest for the given
// action, workspace ID, and session type. Chain With* methods to supply
// additional fields, then call Build to validate and obtain the final struct.
func NewSessionEvalRequest(action SessionAction, workspaceID string, sessionType SessionType) *SessionEvalRequest {
	return &SessionEvalRequest{
		Action:   action,
		Resource: SessionWorkspaceResource{ID: workspaceID},
		Context:  SessionContext{Type: sessionType},
	}
}

// WithSource sets the session source on the context.
func (r *SessionEvalRequest) WithSource(source SessionSource) *SessionEvalRequest {
	r.Context.Source = source
	return r
}

// WithOwner sets the workspace owner on the resource.
func (r *SessionEvalRequest) WithOwner(owner string) *SessionEvalRequest {
	r.Resource.Owner = owner
	return r
}

// WithBlueprint sets the blueprint name on the resource.
func (r *SessionEvalRequest) WithBlueprint(blueprint string) *SessionEvalRequest {
	r.Resource.Blueprint = blueprint
	return r
}

// Build validates the request and returns it if all constraints are satisfied.
// It is the required terminator for the builder chain.
func (r *SessionEvalRequest) Build() (*SessionEvalRequest, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return r, nil
}

// ToProto serializes the typed request into a gRPC EvaluateRequest, attaching
// the supplied JWT token. Only non-empty resource attributes are included.
// Implements EvalRequest.
func (r *SessionEvalRequest) ToProto(token string) *authzv1.EvaluateRequest {
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

// SessionEvalRequestFromProto converts a gRPC EvaluateRequest into a validated
// SessionEvalRequest. Returns an error if the request does not conform to the
// session policy contract.
func SessionEvalRequestFromProto(req *authzv1.EvaluateRequest) (*SessionEvalRequest, error) {
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

	r := &SessionEvalRequest{
		Action: SessionAction(req.Action),
		Resource: SessionWorkspaceResource{
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
func (r *SessionEvalRequest) Validate() error {
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
		return fmt.Errorf("session: context \"session_type\" must be %q or %q, got %q",
			SessionTypeShell, SessionTypeTCPIP, r.Context.Type)
	}
	if _, ok := validSessionSources[r.Context.Source]; !ok {
		return fmt.Errorf("session: context \"session_source\" must be %q or %q, got %q",
			SessionSourceSSHProxy, SessionSourceAPIServer, r.Context.Source)
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
)

// RecordObligation is the typed representation of the "record" obligation key
// returned by the policy engine in a PolicyResult for session:start.
// Each field corresponds to one recording channel; all default to false.
type RecordObligation struct {
	Shell       bool
	Exec        bool
	DirectTCPIP bool
}

// ParseRecordObligation reads the "record" key from the obligations map.
// The value is a comma-separated list of channel tokens ("shell", "exec",
// "direct-tcpip"); "none" or an unrecognised value leaves all fields false.
// Returns (obligation, true) when the key is present, (zero, false) when the
// policy did not set a record obligation — the enforcer should then apply its
// configured default (typically no recording).
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
		}
	}
	return ob, true
}
