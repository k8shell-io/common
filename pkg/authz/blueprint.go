// Copyright 2026 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package authz

// Contract: blueprints:read
//
// Resource  type="blueprint"
//   id   (none)
//
// Context   (none)
//
// Subject   injected by the backend from JWT claims (username, roles, email, ...)
//
// Obligations
//   org — organization name the enforcer must scope the blueprint listing
//        to, or "*" for every organization. provisioner's ListBlueprints
//        returns the file-based global catalog plus every org-scoped
//        blueprint, so the policy narrows it much as user:list/role:list do:
//        an org-scoped role gets org = <caller's org> and sees only that
//        org's blueprints (plus the globals); a role granted cross-org
//        visibility (e.g. a global admin) gets org = "*". A missing
//        obligation is treated by the enforcer as the caller's own org, so an
//        un-updated policy can never widen the listing. Parsed with
//        ParseOrgObligation.
//
// Contract: blueprints:write
//
// Resource  type="blueprint"
//   id   (none)
//
// Context   (none)
//
// Subject   injected by the backend from JWT claims (username, roles, email, ...)
//
// Obligations  (none) — allow/deny only. Gates the mutating org-scoped
// blueprint routes (create/update/delete) the same way blueprints:read gates
// the read routes; the org a blueprint is scoped to is carried by the RPC
// request, not this policy input.

import (
	"fmt"

	authzv1 "github.com/k8shell-io/common/pkg/api/gen/go/authz/v1"
)

// BlueprintReadEvalRequest is the validated, typed model for blueprints:read
// policy evaluation. No resource id is required; the subject claims
// determine access.
type BlueprintReadEvalRequest struct{}

var _ EvalRequest = (*BlueprintReadEvalRequest)(nil)

// NewBlueprintReadEvalRequest returns a BlueprintReadEvalRequest ready to be built.
func NewBlueprintReadEvalRequest() *BlueprintReadEvalRequest {
	return &BlueprintReadEvalRequest{}
}

// Build returns the request. It is the required terminator for the builder chain.
func (r *BlueprintReadEvalRequest) Build() (*BlueprintReadEvalRequest, error) {
	return r, nil
}

// ToProto serializes the typed request into a gRPC EvaluateRequest, attaching
// the supplied JWT token.
// Implements EvalRequest.
func (r *BlueprintReadEvalRequest) ToProto(token string) *authzv1.EvaluateRequest {
	return &authzv1.EvaluateRequest{
		Token:  token,
		Action: "blueprints:read",
		Resource: &authzv1.Resource{
			Type: "blueprint",
		},
	}
}

// BlueprintReadEvalRequestFromProto converts a gRPC EvaluateRequest into a
// validated BlueprintReadEvalRequest.
func BlueprintReadEvalRequestFromProto(req *authzv1.EvaluateRequest) (*BlueprintReadEvalRequest, error) {
	if req == nil {
		return nil, fmt.Errorf("blueprints:read: EvaluateRequest is nil")
	}
	if req.Action != "blueprints:read" {
		return nil, fmt.Errorf("blueprints:read: action must be \"blueprints:read\", got %q", req.Action)
	}
	if req.Resource == nil {
		return nil, fmt.Errorf("blueprints:read: resource is nil")
	}
	if req.Resource.Type != "blueprint" {
		return nil, fmt.Errorf("blueprints:read: resource type must be \"blueprint\", got %q", req.Resource.Type)
	}
	return &BlueprintReadEvalRequest{}, nil
}

// Validate is a no-op for blueprints:read; no fields are required.
// Implements EvalRequest.
func (r *BlueprintReadEvalRequest) Validate() error { return nil }

// BlueprintWriteEvalRequest is the validated, typed model for blueprints:write
// policy evaluation — creating, updating, or deleting org-scoped blueprints.
// Like blueprints:read it carries no resource id; the subject claims
// determine access.
type BlueprintWriteEvalRequest struct{}

var _ EvalRequest = (*BlueprintWriteEvalRequest)(nil)

// NewBlueprintWriteEvalRequest returns a BlueprintWriteEvalRequest ready to be built.
func NewBlueprintWriteEvalRequest() *BlueprintWriteEvalRequest {
	return &BlueprintWriteEvalRequest{}
}

// Build returns the request. It is the required terminator for the builder chain.
func (r *BlueprintWriteEvalRequest) Build() (*BlueprintWriteEvalRequest, error) {
	return r, nil
}

// ToProto serializes the typed request into a gRPC EvaluateRequest, attaching
// the supplied JWT token.
// Implements EvalRequest.
func (r *BlueprintWriteEvalRequest) ToProto(token string) *authzv1.EvaluateRequest {
	return &authzv1.EvaluateRequest{
		Token:  token,
		Action: "blueprints:write",
		Resource: &authzv1.Resource{
			Type: "blueprint",
		},
	}
}

// BlueprintWriteEvalRequestFromProto converts a gRPC EvaluateRequest into a
// validated BlueprintWriteEvalRequest.
func BlueprintWriteEvalRequestFromProto(req *authzv1.EvaluateRequest) (*BlueprintWriteEvalRequest, error) {
	if req == nil {
		return nil, fmt.Errorf("blueprints:write: EvaluateRequest is nil")
	}
	if req.Action != "blueprints:write" {
		return nil, fmt.Errorf("blueprints:write: action must be \"blueprints:write\", got %q", req.Action)
	}
	if req.Resource == nil {
		return nil, fmt.Errorf("blueprints:write: resource is nil")
	}
	if req.Resource.Type != "blueprint" {
		return nil, fmt.Errorf("blueprints:write: resource type must be \"blueprint\", got %q", req.Resource.Type)
	}
	return &BlueprintWriteEvalRequest{}, nil
}

// Validate is a no-op for blueprints:write; no fields are required.
// Implements EvalRequest.
func (r *BlueprintWriteEvalRequest) Validate() error { return nil }

// init registers capability probes for blueprints:read and blueprints:write.
// See CapabilityCheck and registerCapabilityCheck in capability.go.
func init() {
	registerCapabilityCheck(CapabilityCheck{
		Action: "blueprints:read", Package: "blueprint", Scope: "blueprints:read",
		Build: func(ctx CapabilityContext) (EvalRequest, error) {
			return NewBlueprintReadEvalRequest().Build()
		},
	})
	registerCapabilityCheck(CapabilityCheck{
		Action: "blueprints:write", Package: "blueprint", Scope: "blueprints:write",
		Build: func(ctx CapabilityContext) (EvalRequest, error) {
			return NewBlueprintWriteEvalRequest().Build()
		},
	})
}
