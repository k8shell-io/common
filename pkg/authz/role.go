// Copyright 2026 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package authz

// Contract: role:list
//
// Resource  type="role"
//   id   (none)
//
// Context   (none)
//
// Subject   injected by the backend from JWT claims (username, roles, email, ...)
//
// Obligations
//   org  organization name — the enforcer lists only roles scoped to this
//        org (plus global roles); absent/empty imposes no restriction.
//        Parse with ParseOrgObligation.
//
// ---
//
// Contract: role:create
//
// Resource  type="role"
//   id   proposed role name (required)
//   org  organization the role is scoped to (optional) — empty means global
//
// Context   (none)
//
// Subject   injected by the backend from JWT claims (username, roles, email, ...)
//
// Obligations  (none) — allow/deny only
//
// This action must not use the enrich.user builtin: identity's role registry
// write path (CreateRole) is what would call authz to evaluate role:create,
// so a policy that calls back into identity for enrichment creates a
// dependency cycle. input.subject.roles and the proposed role name in the
// resource are already sufficient to decide this policy without enrichment.
//
// ---
//
// Contract: role:delete
//
// Resource  type="role"
//   id   role name (required)
//   org  organization the role is scoped to (optional) — empty means global.
//        name and org together identify the role.
//
// Context   (none)
//
// Subject   injected by the backend from JWT claims (username, roles, email, ...)
//
// Obligations  (none) — allow/deny only
//
// ---
//
// Contract: role:update
//
// Resource  type="role"
//   id   role name (required)
//   org  organization the role is scoped to (optional) — empty means global.
//        name and org together identify the role and are immutable; this
//        action only ever changes the role's description.
//
// Context   (none)
//
// Subject   injected by the backend from JWT claims (username, roles, email, ...)
//
// Obligations  (none) — allow/deny only

import (
	"fmt"

	authzv1 "github.com/k8shell-io/common/pkg/api/gen/go/authz/v1"
)

// RoleResource holds the resource-scoped attributes for a role policy check.
type RoleResource struct {
	// ID is the role name (resource.id in the EvaluateRequest).
	ID string

	// Org is the organization the role is scoped to (resource.attributes["org"]).
	// Empty means global (assignable across all organizations).
	Org string
}

func roleResourceToAttrs(r RoleResource) map[string]string {
	attrs := map[string]string{}
	if r.Org != "" {
		attrs["org"] = r.Org
	}
	return attrs
}

// RoleListEvalRequest is the validated, typed model for role:list policy
// evaluation. No resource id is required; the subject claims determine access.
type RoleListEvalRequest struct{}

var _ EvalRequest = (*RoleListEvalRequest)(nil)

// NewRoleListEvalRequest returns a RoleListEvalRequest ready to be built.
func NewRoleListEvalRequest() *RoleListEvalRequest {
	return &RoleListEvalRequest{}
}

// Build returns the request. It is the required terminator for the builder chain.
func (r *RoleListEvalRequest) Build() (*RoleListEvalRequest, error) {
	return r, nil
}

// ToProto serializes the typed request into a gRPC EvaluateRequest, attaching
// the supplied JWT token.
// Implements EvalRequest.
func (r *RoleListEvalRequest) ToProto(token string) *authzv1.EvaluateRequest {
	return &authzv1.EvaluateRequest{
		Token:  token,
		Action: "role:list",
		Resource: &authzv1.Resource{
			Type: "role",
		},
	}
}

// RoleListEvalRequestFromProto converts a gRPC EvaluateRequest into a
// validated RoleListEvalRequest.
func RoleListEvalRequestFromProto(req *authzv1.EvaluateRequest) (*RoleListEvalRequest, error) {
	if req == nil {
		return nil, fmt.Errorf("role:list: EvaluateRequest is nil")
	}
	if req.Action != "role:list" {
		return nil, fmt.Errorf("role:list: action must be \"role:list\", got %q", req.Action)
	}
	if req.Resource == nil {
		return nil, fmt.Errorf("role:list: resource is nil")
	}
	if req.Resource.Type != "role" {
		return nil, fmt.Errorf("role:list: resource type must be \"role\", got %q", req.Resource.Type)
	}
	return &RoleListEvalRequest{}, nil
}

// Validate is a no-op for role:list; no fields are required.
// Implements EvalRequest.
func (r *RoleListEvalRequest) Validate() error { return nil }

// RoleCreateEvalRequest is the validated, typed model for role:create policy
// evaluation. Use NewRoleCreateEvalRequest to start building, then chain
// With* methods and call Build to get a validated instance.
type RoleCreateEvalRequest struct {
	Resource RoleResource
}

var _ EvalRequest = (*RoleCreateEvalRequest)(nil)

// NewRoleCreateEvalRequest begins building a RoleCreateEvalRequest for the
// given proposed role name. Chain With* methods to supply additional fields,
// then call Build to validate and obtain the final struct.
func NewRoleCreateEvalRequest(name string) *RoleCreateEvalRequest {
	return &RoleCreateEvalRequest{Resource: RoleResource{ID: name}}
}

// WithOrg sets the organization the new role will be scoped to.
func (r *RoleCreateEvalRequest) WithOrg(org string) *RoleCreateEvalRequest {
	r.Resource.Org = org
	return r
}

// Build validates the request and returns it if all constraints are satisfied.
// It is the required terminator for the builder chain.
func (r *RoleCreateEvalRequest) Build() (*RoleCreateEvalRequest, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return r, nil
}

// ToProto serializes the typed request into a gRPC EvaluateRequest, attaching
// the supplied JWT token.
// Implements EvalRequest.
func (r *RoleCreateEvalRequest) ToProto(token string) *authzv1.EvaluateRequest {
	return &authzv1.EvaluateRequest{
		Token:  token,
		Action: "role:create",
		Resource: &authzv1.Resource{
			Type:       "role",
			Id:         r.Resource.ID,
			Attributes: roleResourceToAttrs(r.Resource),
		},
	}
}

// RoleCreateEvalRequestFromProto converts a gRPC EvaluateRequest into a
// validated RoleCreateEvalRequest.
func RoleCreateEvalRequestFromProto(req *authzv1.EvaluateRequest) (*RoleCreateEvalRequest, error) {
	if req == nil {
		return nil, fmt.Errorf("role:create: EvaluateRequest is nil")
	}
	if req.Action != "role:create" {
		return nil, fmt.Errorf("role:create: action must be \"role:create\", got %q", req.Action)
	}
	if req.Resource == nil {
		return nil, fmt.Errorf("role:create: resource is nil")
	}
	if req.Resource.Type != "role" {
		return nil, fmt.Errorf("role:create: resource type must be \"role\", got %q", req.Resource.Type)
	}
	r := &RoleCreateEvalRequest{
		Resource: RoleResource{
			ID:  req.Resource.Id,
			Org: req.Resource.Attributes["org"],
		},
	}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return r, nil
}

// Validate checks the request against the role:create contract.
// Implements EvalRequest.
func (r *RoleCreateEvalRequest) Validate() error {
	if r.Resource.ID == "" {
		return fmt.Errorf("role:create: resource ID (role name) is required")
	}
	return nil
}

// RoleDeleteEvalRequest is the validated, typed model for role:delete policy
// evaluation. Use NewRoleDeleteEvalRequest to start building, then call Build
// to get a validated instance.
type RoleDeleteEvalRequest struct {
	Resource RoleResource
}

var _ EvalRequest = (*RoleDeleteEvalRequest)(nil)

// NewRoleDeleteEvalRequest begins building a RoleDeleteEvalRequest for the
// given role name. Chain WithOrg to supply the role's organization, then call
// Build to validate and obtain the final struct.
func NewRoleDeleteEvalRequest(name string) *RoleDeleteEvalRequest {
	return &RoleDeleteEvalRequest{Resource: RoleResource{ID: name}}
}

// WithOrg sets the organization the role being deleted is scoped to.
func (r *RoleDeleteEvalRequest) WithOrg(org string) *RoleDeleteEvalRequest {
	r.Resource.Org = org
	return r
}

// Build validates the request and returns it if all constraints are satisfied.
// It is the required terminator for the builder chain.
func (r *RoleDeleteEvalRequest) Build() (*RoleDeleteEvalRequest, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return r, nil
}

// ToProto serializes the typed request into a gRPC EvaluateRequest, attaching
// the supplied JWT token.
// Implements EvalRequest.
func (r *RoleDeleteEvalRequest) ToProto(token string) *authzv1.EvaluateRequest {
	return &authzv1.EvaluateRequest{
		Token:  token,
		Action: "role:delete",
		Resource: &authzv1.Resource{
			Type:       "role",
			Id:         r.Resource.ID,
			Attributes: roleResourceToAttrs(r.Resource),
		},
	}
}

// RoleDeleteEvalRequestFromProto converts a gRPC EvaluateRequest into a
// validated RoleDeleteEvalRequest.
func RoleDeleteEvalRequestFromProto(req *authzv1.EvaluateRequest) (*RoleDeleteEvalRequest, error) {
	if req == nil {
		return nil, fmt.Errorf("role:delete: EvaluateRequest is nil")
	}
	if req.Action != "role:delete" {
		return nil, fmt.Errorf("role:delete: action must be \"role:delete\", got %q", req.Action)
	}
	if req.Resource == nil {
		return nil, fmt.Errorf("role:delete: resource is nil")
	}
	if req.Resource.Type != "role" {
		return nil, fmt.Errorf("role:delete: resource type must be \"role\", got %q", req.Resource.Type)
	}
	r := &RoleDeleteEvalRequest{
		Resource: RoleResource{
			ID:  req.Resource.Id,
			Org: req.Resource.Attributes["org"],
		},
	}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return r, nil
}

// Validate checks the request against the role:delete contract.
// Implements EvalRequest.
func (r *RoleDeleteEvalRequest) Validate() error {
	if r.Resource.ID == "" {
		return fmt.Errorf("role:delete: resource ID (role name) is required")
	}
	return nil
}

// RoleUpdateEvalRequest is the validated, typed model for role:update policy
// evaluation. Use NewRoleUpdateEvalRequest to start building, then chain
// With* methods and call Build to get a validated instance.
type RoleUpdateEvalRequest struct {
	Resource RoleResource
}

var _ EvalRequest = (*RoleUpdateEvalRequest)(nil)

// NewRoleUpdateEvalRequest begins building a RoleUpdateEvalRequest for the
// given role name. Chain WithOrg to supply the role's organization, then call
// Build to validate and obtain the final struct.
func NewRoleUpdateEvalRequest(name string) *RoleUpdateEvalRequest {
	return &RoleUpdateEvalRequest{Resource: RoleResource{ID: name}}
}

// WithOrg sets the organization the role being updated is scoped to.
func (r *RoleUpdateEvalRequest) WithOrg(org string) *RoleUpdateEvalRequest {
	r.Resource.Org = org
	return r
}

// Build validates the request and returns it if all constraints are satisfied.
// It is the required terminator for the builder chain.
func (r *RoleUpdateEvalRequest) Build() (*RoleUpdateEvalRequest, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return r, nil
}

// ToProto serializes the typed request into a gRPC EvaluateRequest, attaching
// the supplied JWT token.
// Implements EvalRequest.
func (r *RoleUpdateEvalRequest) ToProto(token string) *authzv1.EvaluateRequest {
	return &authzv1.EvaluateRequest{
		Token:  token,
		Action: "role:update",
		Resource: &authzv1.Resource{
			Type:       "role",
			Id:         r.Resource.ID,
			Attributes: roleResourceToAttrs(r.Resource),
		},
	}
}

// RoleUpdateEvalRequestFromProto converts a gRPC EvaluateRequest into a
// validated RoleUpdateEvalRequest.
func RoleUpdateEvalRequestFromProto(req *authzv1.EvaluateRequest) (*RoleUpdateEvalRequest, error) {
	if req == nil {
		return nil, fmt.Errorf("role:update: EvaluateRequest is nil")
	}
	if req.Action != "role:update" {
		return nil, fmt.Errorf("role:update: action must be \"role:update\", got %q", req.Action)
	}
	if req.Resource == nil {
		return nil, fmt.Errorf("role:update: resource is nil")
	}
	if req.Resource.Type != "role" {
		return nil, fmt.Errorf("role:update: resource type must be \"role\", got %q", req.Resource.Type)
	}
	r := &RoleUpdateEvalRequest{
		Resource: RoleResource{
			ID:  req.Resource.Id,
			Org: req.Resource.Attributes["org"],
		},
	}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return r, nil
}

// Validate checks the request against the role:update contract.
// Implements EvalRequest.
func (r *RoleUpdateEvalRequest) Validate() error {
	if r.Resource.ID == "" {
		return fmt.Errorf("role:update: resource ID (role name) is required")
	}
	return nil
}

// init registers a capability probe for every role domain action. See
// CapabilityCheck and registerCapabilityCheck in capability.go.
func init() {
	registerCapabilityCheck(CapabilityCheck{
		Action: "role:list", Package: "role", Scope: "role:list",
		Build: func(ctx CapabilityContext) (EvalRequest, error) {
			return NewRoleListEvalRequest().Build()
		},
	})
	registerCapabilityCheck(CapabilityCheck{
		Action: "role:create", Package: "role", Scope: "role:create",
		Build: func(ctx CapabilityContext) (EvalRequest, error) {
			return NewRoleCreateEvalRequest(capabilityWildcardRole).WithOrg(ctx.Org).Build()
		},
	})
	registerCapabilityCheck(CapabilityCheck{
		Action: "role:delete", Package: "role", Scope: "role:delete",
		Build: func(ctx CapabilityContext) (EvalRequest, error) {
			return NewRoleDeleteEvalRequest(capabilityWildcardRole).WithOrg(ctx.Org).Build()
		},
	})
	registerCapabilityCheck(CapabilityCheck{
		Action: "role:update", Package: "role", Scope: "role:update",
		Build: func(ctx CapabilityContext) (EvalRequest, error) {
			return NewRoleUpdateEvalRequest(capabilityWildcardRole).WithOrg(ctx.Org).Build()
		},
	})
}
