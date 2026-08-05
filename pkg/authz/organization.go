// Copyright 2026 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package authz

// Contract: org:list
//
// Resource  type="org"
//   id   (none)
//
// Context   (none)
//
// Subject   injected by the backend from JWT claims (username, roles, email, ...)
//
// Obligations
//   orgs  JSON array of organization name strings — the enforcer lists only
//         these organizations. Absent means unrestricted (e.g. a global
//         admin sees every organization); an org-scoped admin role is
//         expected to set this to the org(s) they administer rather than
//         relying on org:list allow/deny alone, since allow/deny has no way
//         to express "some but not all organizations are visible."
//
// ---
//
// Contract: org:read
//
// Resource  type="org"
//   id   organization name (required)
//
// Context   (none)
//
// Subject   injected by the backend from JWT claims (username, roles, email, ...)
//
// Obligations  (none) — allow/deny only
//
// ---
//
// Contract: org:create
//
// Resource  type="org"
//   id   proposed organization name (required)
//
// Context   (none)
//
// Subject   injected by the backend from JWT claims (username, roles, email, ...)
//
// Obligations  (none) — allow/deny only
//
// This action must not use the enrich.user builtin, for the same reason as
// role:create: identity's organization registry write path (CreateOrganization)
// is what would call authz to evaluate org:create, so a policy that calls back
// into identity for enrichment creates a dependency cycle. input.subject.roles
// and the proposed organization name in the resource are already sufficient
// to decide this policy without enrichment.
//
// ---
//
// Contract: org:delete
//
// Resource  type="org"
//   id   organization name (required)
//
// Context   (none)
//
// Subject   injected by the backend from JWT claims (username, roles, email, ...)
//
// Obligations  (none) — allow/deny only
//
// ---
//
// Contract: org:update
//
// Resource  type="org"
//   id   organization name (required) — the name is immutable and only
//        identifies which organization is being updated; UpdateOrganization
//        has no way to change it
//
// Context   (none)
//
// Subject   injected by the backend from JWT claims (username, roles, email, ...)
//
// Obligations  (none) — allow/deny only

import (
	"encoding/json"
	"fmt"

	authzv1 "github.com/k8shell-io/common/pkg/api/gen/go/authz/v1"
)

// OrganizationResource holds the resource-scoped attributes for an
// organization policy check.
type OrganizationResource struct {
	// ID is the organization name (resource.id in the EvaluateRequest).
	ID string
}

// OrganizationListEvalRequest is the validated, typed model for org:list
// policy evaluation. No resource id is required; the subject claims
// determine access.
type OrganizationListEvalRequest struct{}

var _ EvalRequest = (*OrganizationListEvalRequest)(nil)

// NewOrganizationListEvalRequest returns an OrganizationListEvalRequest ready to be built.
func NewOrganizationListEvalRequest() *OrganizationListEvalRequest {
	return &OrganizationListEvalRequest{}
}

// Build returns the request. It is the required terminator for the builder chain.
func (r *OrganizationListEvalRequest) Build() (*OrganizationListEvalRequest, error) {
	return r, nil
}

// ToProto serializes the typed request into a gRPC EvaluateRequest, attaching
// the supplied JWT token.
// Implements EvalRequest.
func (r *OrganizationListEvalRequest) ToProto(token string) *authzv1.EvaluateRequest {
	return &authzv1.EvaluateRequest{
		Token:  token,
		Action: "org:list",
		Resource: &authzv1.Resource{
			Type: "org",
		},
	}
}

// OrganizationListEvalRequestFromProto converts a gRPC EvaluateRequest into a
// validated OrganizationListEvalRequest.
func OrganizationListEvalRequestFromProto(req *authzv1.EvaluateRequest) (*OrganizationListEvalRequest, error) {
	if req == nil {
		return nil, fmt.Errorf("org:list: EvaluateRequest is nil")
	}
	if req.Action != "org:list" {
		return nil, fmt.Errorf("org:list: action must be \"org:list\", got %q", req.Action)
	}
	if req.Resource == nil {
		return nil, fmt.Errorf("org:list: resource is nil")
	}
	if req.Resource.Type != "org" {
		return nil, fmt.Errorf("org:list: resource type must be \"org\", got %q", req.Resource.Type)
	}
	return &OrganizationListEvalRequest{}, nil
}

// Validate is a no-op for org:list; no fields are required.
// Implements EvalRequest.
func (r *OrganizationListEvalRequest) Validate() error { return nil }

const (
	// ObligationKeyOrgs is the key the policy engine writes to scope an
	// org:list result to a set of organizations. The value is a JSON-encoded
	// array of organization name strings.
	ObligationKeyOrgs = "orgs"
)

// OrgsObligation is the typed representation of the "orgs" obligation key
// returned by the policy engine in a PolicyResult for org:list.
type OrgsObligation struct {
	// Orgs is the list of organization names the enforcer should restrict
	// the listing to.
	Orgs []string
}

// ParseOrgsObligation reads the "orgs" key from the obligations map.
// Returns (obligation, true) when the key is present, (zero value, false)
// when the policy did not set an orgs obligation — in that case the
// enforcer should not scope the listing by organization.
func ParseOrgsObligation(obligations map[string]string) (OrgsObligation, bool) {
	v, ok := obligations[ObligationKeyOrgs]
	if !ok {
		return OrgsObligation{}, false
	}
	var raw []string
	if err := json.Unmarshal([]byte(v), &raw); err != nil {
		return OrgsObligation{}, false
	}
	orgs := make([]string, 0, len(raw))
	for _, o := range raw {
		if o != "" {
			orgs = append(orgs, o)
		}
	}
	return OrgsObligation{Orgs: orgs}, true
}

// OrganizationReadEvalRequest is the validated, typed model for org:read
// policy evaluation. Use NewOrganizationReadEvalRequest to start building,
// then call Build to get a validated instance.
type OrganizationReadEvalRequest struct {
	Resource OrganizationResource
}

var _ EvalRequest = (*OrganizationReadEvalRequest)(nil)

// NewOrganizationReadEvalRequest begins building an OrganizationReadEvalRequest
// for the given organization name. Call Build to validate and obtain the final struct.
func NewOrganizationReadEvalRequest(name string) *OrganizationReadEvalRequest {
	return &OrganizationReadEvalRequest{Resource: OrganizationResource{ID: name}}
}

// Build validates the request and returns it if all constraints are satisfied.
// It is the required terminator for the builder chain.
func (r *OrganizationReadEvalRequest) Build() (*OrganizationReadEvalRequest, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return r, nil
}

// ToProto serializes the typed request into a gRPC EvaluateRequest, attaching
// the supplied JWT token.
// Implements EvalRequest.
func (r *OrganizationReadEvalRequest) ToProto(token string) *authzv1.EvaluateRequest {
	return &authzv1.EvaluateRequest{
		Token:  token,
		Action: "org:read",
		Resource: &authzv1.Resource{
			Type: "org",
			Id:   r.Resource.ID,
		},
	}
}

// OrganizationReadEvalRequestFromProto converts a gRPC EvaluateRequest into
// a validated OrganizationReadEvalRequest.
func OrganizationReadEvalRequestFromProto(req *authzv1.EvaluateRequest) (*OrganizationReadEvalRequest, error) {
	if req == nil {
		return nil, fmt.Errorf("org:read: EvaluateRequest is nil")
	}
	if req.Action != "org:read" {
		return nil, fmt.Errorf("org:read: action must be \"org:read\", got %q", req.Action)
	}
	if req.Resource == nil {
		return nil, fmt.Errorf("org:read: resource is nil")
	}
	if req.Resource.Type != "org" {
		return nil, fmt.Errorf("org:read: resource type must be \"org\", got %q", req.Resource.Type)
	}
	r := &OrganizationReadEvalRequest{
		Resource: OrganizationResource{ID: req.Resource.Id},
	}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return r, nil
}

// Validate checks the request against the org:read contract.
// Implements EvalRequest.
func (r *OrganizationReadEvalRequest) Validate() error {
	if r.Resource.ID == "" {
		return fmt.Errorf("org:read: resource ID (organization name) is required")
	}
	return nil
}

// OrganizationCreateEvalRequest is the validated, typed model for org:create
// policy evaluation. Use NewOrganizationCreateEvalRequest to start building,
// then call Build to get a validated instance.
type OrganizationCreateEvalRequest struct {
	Resource OrganizationResource
}

var _ EvalRequest = (*OrganizationCreateEvalRequest)(nil)

// NewOrganizationCreateEvalRequest begins building an OrganizationCreateEvalRequest
// for the given proposed organization name. Call Build to validate and obtain
// the final struct.
func NewOrganizationCreateEvalRequest(name string) *OrganizationCreateEvalRequest {
	return &OrganizationCreateEvalRequest{Resource: OrganizationResource{ID: name}}
}

// Build validates the request and returns it if all constraints are satisfied.
// It is the required terminator for the builder chain.
func (r *OrganizationCreateEvalRequest) Build() (*OrganizationCreateEvalRequest, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return r, nil
}

// ToProto serializes the typed request into a gRPC EvaluateRequest, attaching
// the supplied JWT token.
// Implements EvalRequest.
func (r *OrganizationCreateEvalRequest) ToProto(token string) *authzv1.EvaluateRequest {
	return &authzv1.EvaluateRequest{
		Token:  token,
		Action: "org:create",
		Resource: &authzv1.Resource{
			Type: "org",
			Id:   r.Resource.ID,
		},
	}
}

// OrganizationCreateEvalRequestFromProto converts a gRPC EvaluateRequest into
// a validated OrganizationCreateEvalRequest.
func OrganizationCreateEvalRequestFromProto(req *authzv1.EvaluateRequest) (*OrganizationCreateEvalRequest, error) {
	if req == nil {
		return nil, fmt.Errorf("org:create: EvaluateRequest is nil")
	}
	if req.Action != "org:create" {
		return nil, fmt.Errorf("org:create: action must be \"org:create\", got %q", req.Action)
	}
	if req.Resource == nil {
		return nil, fmt.Errorf("org:create: resource is nil")
	}
	if req.Resource.Type != "org" {
		return nil, fmt.Errorf("org:create: resource type must be \"org\", got %q", req.Resource.Type)
	}
	r := &OrganizationCreateEvalRequest{
		Resource: OrganizationResource{ID: req.Resource.Id},
	}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return r, nil
}

// Validate checks the request against the org:create contract.
// Implements EvalRequest.
func (r *OrganizationCreateEvalRequest) Validate() error {
	if r.Resource.ID == "" {
		return fmt.Errorf("org:create: resource ID (organization name) is required")
	}
	return nil
}

// OrganizationDeleteEvalRequest is the validated, typed model for org:delete
// policy evaluation. Use NewOrganizationDeleteEvalRequest to start building,
// then call Build to get a validated instance.
type OrganizationDeleteEvalRequest struct {
	Resource OrganizationResource
}

var _ EvalRequest = (*OrganizationDeleteEvalRequest)(nil)

// NewOrganizationDeleteEvalRequest begins building an OrganizationDeleteEvalRequest
// for the given organization name. Call Build to validate and obtain the final struct.
func NewOrganizationDeleteEvalRequest(name string) *OrganizationDeleteEvalRequest {
	return &OrganizationDeleteEvalRequest{Resource: OrganizationResource{ID: name}}
}

// Build validates the request and returns it if all constraints are satisfied.
// It is the required terminator for the builder chain.
func (r *OrganizationDeleteEvalRequest) Build() (*OrganizationDeleteEvalRequest, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return r, nil
}

// ToProto serializes the typed request into a gRPC EvaluateRequest, attaching
// the supplied JWT token.
// Implements EvalRequest.
func (r *OrganizationDeleteEvalRequest) ToProto(token string) *authzv1.EvaluateRequest {
	return &authzv1.EvaluateRequest{
		Token:  token,
		Action: "org:delete",
		Resource: &authzv1.Resource{
			Type: "org",
			Id:   r.Resource.ID,
		},
	}
}

// OrganizationDeleteEvalRequestFromProto converts a gRPC EvaluateRequest into
// a validated OrganizationDeleteEvalRequest.
func OrganizationDeleteEvalRequestFromProto(req *authzv1.EvaluateRequest) (*OrganizationDeleteEvalRequest, error) {
	if req == nil {
		return nil, fmt.Errorf("org:delete: EvaluateRequest is nil")
	}
	if req.Action != "org:delete" {
		return nil, fmt.Errorf("org:delete: action must be \"org:delete\", got %q", req.Action)
	}
	if req.Resource == nil {
		return nil, fmt.Errorf("org:delete: resource is nil")
	}
	if req.Resource.Type != "org" {
		return nil, fmt.Errorf("org:delete: resource type must be \"org\", got %q", req.Resource.Type)
	}
	r := &OrganizationDeleteEvalRequest{
		Resource: OrganizationResource{ID: req.Resource.Id},
	}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return r, nil
}

// Validate checks the request against the org:delete contract.
// Implements EvalRequest.
func (r *OrganizationDeleteEvalRequest) Validate() error {
	if r.Resource.ID == "" {
		return fmt.Errorf("org:delete: resource ID (organization name) is required")
	}
	return nil
}

// OrganizationUpdateEvalRequest is the validated, typed model for org:update
// policy evaluation. Use NewOrganizationUpdateEvalRequest to start building,
// then call Build to get a validated instance.
type OrganizationUpdateEvalRequest struct {
	Resource OrganizationResource
}

var _ EvalRequest = (*OrganizationUpdateEvalRequest)(nil)

// NewOrganizationUpdateEvalRequest begins building an OrganizationUpdateEvalRequest
// for the given organization name. Call Build to validate and obtain the final struct.
func NewOrganizationUpdateEvalRequest(name string) *OrganizationUpdateEvalRequest {
	return &OrganizationUpdateEvalRequest{Resource: OrganizationResource{ID: name}}
}

// Build validates the request and returns it if all constraints are satisfied.
// It is the required terminator for the builder chain.
func (r *OrganizationUpdateEvalRequest) Build() (*OrganizationUpdateEvalRequest, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return r, nil
}

// ToProto serializes the typed request into a gRPC EvaluateRequest, attaching
// the supplied JWT token.
// Implements EvalRequest.
func (r *OrganizationUpdateEvalRequest) ToProto(token string) *authzv1.EvaluateRequest {
	return &authzv1.EvaluateRequest{
		Token:  token,
		Action: "org:update",
		Resource: &authzv1.Resource{
			Type: "org",
			Id:   r.Resource.ID,
		},
	}
}

// OrganizationUpdateEvalRequestFromProto converts a gRPC EvaluateRequest into
// a validated OrganizationUpdateEvalRequest.
func OrganizationUpdateEvalRequestFromProto(req *authzv1.EvaluateRequest) (*OrganizationUpdateEvalRequest, error) {
	if req == nil {
		return nil, fmt.Errorf("org:update: EvaluateRequest is nil")
	}
	if req.Action != "org:update" {
		return nil, fmt.Errorf("org:update: action must be \"org:update\", got %q", req.Action)
	}
	if req.Resource == nil {
		return nil, fmt.Errorf("org:update: resource is nil")
	}
	if req.Resource.Type != "org" {
		return nil, fmt.Errorf("org:update: resource type must be \"org\", got %q", req.Resource.Type)
	}
	r := &OrganizationUpdateEvalRequest{
		Resource: OrganizationResource{ID: req.Resource.Id},
	}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return r, nil
}

// Validate checks the request against the org:update contract.
// Implements EvalRequest.
func (r *OrganizationUpdateEvalRequest) Validate() error {
	if r.Resource.ID == "" {
		return fmt.Errorf("org:update: resource ID (organization name) is required")
	}
	return nil
}

// init registers a capability probe for every org domain action. See
// CapabilityCheck and registerCapabilityCheck in capability.go.
func init() {
	registerCapabilityCheck(CapabilityCheck{
		Action: "org:list", Package: "org", Scope: "org:list",
		Build: func(ctx CapabilityContext) (EvalRequest, error) {
			return NewOrganizationListEvalRequest().Build()
		},
	})
	registerCapabilityCheck(CapabilityCheck{
		Action: "org:read", Package: "org", Scope: "org:read",
		Build: func(ctx CapabilityContext) (EvalRequest, error) {
			return NewOrganizationReadEvalRequest(capabilityWildcardOrg).Build()
		},
	})
	registerCapabilityCheck(CapabilityCheck{
		Action: "org:create", Package: "org", Scope: "org:create",
		Build: func(ctx CapabilityContext) (EvalRequest, error) {
			return NewOrganizationCreateEvalRequest(capabilityWildcardOrg).Build()
		},
	})
	registerCapabilityCheck(CapabilityCheck{
		Action: "org:delete", Package: "org", Scope: "org:delete",
		Build: func(ctx CapabilityContext) (EvalRequest, error) {
			return NewOrganizationDeleteEvalRequest(capabilityWildcardOrg).Build()
		},
	})
	registerCapabilityCheck(CapabilityCheck{
		Action: "org:update", Package: "org", Scope: "org:update",
		Build: func(ctx CapabilityContext) (EvalRequest, error) {
			return NewOrganizationUpdateEvalRequest(capabilityWildcardOrg).Build()
		},
	})
}
