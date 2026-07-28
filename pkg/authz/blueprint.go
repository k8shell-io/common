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
// Obligations  (none) — allow/deny only. The blueprint catalog returned by
// provisioner's GetBlueprints is global (every registered blueprint,
// regardless of user or org), so there is no dimension to scope the listing
// by — unlike user:list/role:list, which narrow by org/roles/blueprints.

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

// init registers a capability probe for blueprints:read. See CapabilityCheck
// and registerCapabilityCheck in capability.go.
func init() {
	registerCapabilityCheck(CapabilityCheck{
		Action: "blueprints:read", Package: "blueprint", Scope: "blueprints:read",
		Build: func(ctx CapabilityContext) (EvalRequest, error) {
			return NewBlueprintReadEvalRequest().Build()
		},
	})
}
