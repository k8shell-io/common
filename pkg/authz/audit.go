// Copyright 2026 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package authz

// Contract: audit:list
//
// Resource  type="audit"
//   id   (none)
//
// Context   (none)
//
// Subject   injected by the backend from JWT claims (username, roles, email, ...)
//
// Obligations  (policy-defined; forwarded verbatim to QueryAudit as a
//               mandatory constraint on top of the caller's own query.v1
//               Filters — the same mechanism user:list/session:list/org:list
//               use for their own org/roles/username scoping)

import (
	"fmt"

	authzv1 "github.com/k8shell-io/common/pkg/api/gen/go/authz/v1"
)

// AuditListEvalRequest is the validated, typed model for audit:list policy
// evaluation. No resource id is required; the subject claims determine
// access.
type AuditListEvalRequest struct{}

var _ EvalRequest = (*AuditListEvalRequest)(nil)

// NewAuditListEvalRequest returns an AuditListEvalRequest ready to be built.
func NewAuditListEvalRequest() *AuditListEvalRequest {
	return &AuditListEvalRequest{}
}

// Build returns the request. It is the required terminator for the builder chain.
func (r *AuditListEvalRequest) Build() (*AuditListEvalRequest, error) {
	return r, nil
}

// ToProto serializes the typed request into a gRPC EvaluateRequest, attaching
// the supplied JWT token.
// Implements EvalRequest.
func (r *AuditListEvalRequest) ToProto(token string) *authzv1.EvaluateRequest {
	return &authzv1.EvaluateRequest{
		Token:  token,
		Action: "audit:list",
		Resource: &authzv1.Resource{
			Type: "audit",
		},
	}
}

// AuditListEvalRequestFromProto converts a gRPC EvaluateRequest into a
// validated AuditListEvalRequest.
func AuditListEvalRequestFromProto(req *authzv1.EvaluateRequest) (*AuditListEvalRequest, error) {
	if req == nil {
		return nil, fmt.Errorf("audit:list: EvaluateRequest is nil")
	}
	if req.Action != "audit:list" {
		return nil, fmt.Errorf("audit:list: action must be \"audit:list\", got %q", req.Action)
	}
	if req.Resource == nil {
		return nil, fmt.Errorf("audit:list: resource is nil")
	}
	if req.Resource.Type != "audit" {
		return nil, fmt.Errorf("audit:list: resource type must be \"audit\", got %q", req.Resource.Type)
	}
	return &AuditListEvalRequest{}, nil
}

// Validate is a no-op for audit:list; no fields are required.
// Implements EvalRequest.
func (r *AuditListEvalRequest) Validate() error { return nil }

// init registers a capability probe for the audit domain action. See
// CapabilityCheck and registerCapabilityCheck in capability.go.
func init() {
	registerCapabilityCheck(CapabilityCheck{
		Action: "audit:list", Package: "audit", Scope: "audit:list",
		Build: func(ctx CapabilityContext) (EvalRequest, error) {
			return NewAuditListEvalRequest().Build()
		},
	})
}
