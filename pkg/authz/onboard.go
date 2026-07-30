// Copyright 2026 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package authz

// Contract: onboardrule:list
//
// Resource  type="onboardrule"
//   org  organization the rules are scoped to (required) — the HTTP route
//        is nested under /organizations/{org}/onboard-rules, so a caller
//        only ever lists/queries one org's rules at a time.
//
// Context   (none)
//
// Subject   injected by the backend from JWT claims (username, roles, email, ...)
//
// Obligations  (none) — allow/deny only.
//
// ---
//
// Contract: onboardrule:create
//
// Resource  type="onboardrule"
//   id   proposed username pattern (required)
//   org  organization the rule will be scoped to (required)
//   idp  identity provider the rule applies to (required)
//
// Context   (none)
//
// Subject   injected by the backend from JWT claims (username, roles, email, ...)
//
// Obligations  (none) — allow/deny only
//
// ---
//
// Contract: onboardrule:update
//
// Resource  type="onboardrule"
//   id   rule id, as a decimal string (required)
//   org  organization the rule is scoped to (required)
//
// Also gates ApproveOnboardRequest/RejectOnboardRequest — flipping a
// waitlist row to "allow"/"reject" is a write to the rule, same
// authorization weight as replacing its mutable fields via
// UpdateOnboardRule, so it shares this contract rather than getting a
// bespoke action.
//
// Context   (none)
//
// Subject   injected by the backend from JWT claims (username, roles, email, ...)
//
// Obligations  (none) — allow/deny only
//
// ---
//
// Contract: onboardrule:delete
//
// Resource  type="onboardrule"
//   id   rule id, as a decimal string (required)
//   org  organization the rule is scoped to (required)
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

const onboardRuleResourceType = "onboardrule"

// OnboardRuleResource holds the resource-scoped attributes for an onboard
// rule policy check.
type OnboardRuleResource struct {
	// ID is the resource id (resource.id in the EvaluateRequest) — the
	// rule's numeric id (as a decimal string) for update/delete, or the
	// proposed username pattern for create, where no id exists yet.
	ID string

	// Org is the organization the rule is (or will be) scoped to
	// (resource.attributes["org"]). Always required.
	Org string

	// IDP is the identity provider the rule applies to
	// (resource.attributes["idp"]). Only set for onboardrule:create.
	IDP string
}

func onboardRuleResourceToAttrs(r OnboardRuleResource) map[string]string {
	attrs := map[string]string{}
	if r.Org != "" {
		attrs["org"] = r.Org
	}
	if r.IDP != "" {
		attrs["idp"] = r.IDP
	}
	return attrs
}

// OnboardRuleListEvalRequest is the validated, typed model for
// onboardrule:list policy evaluation. Use NewOnboardRuleListEvalRequest to
// start building, then call Build to get a validated instance.
type OnboardRuleListEvalRequest struct {
	Resource OnboardRuleResource
}

var _ EvalRequest = (*OnboardRuleListEvalRequest)(nil)

// NewOnboardRuleListEvalRequest begins building an OnboardRuleListEvalRequest
// for the given organization. Call Build to validate and obtain the final struct.
func NewOnboardRuleListEvalRequest(org string) *OnboardRuleListEvalRequest {
	return &OnboardRuleListEvalRequest{Resource: OnboardRuleResource{Org: org}}
}

// Build validates the request and returns it if all constraints are satisfied.
// It is the required terminator for the builder chain.
func (r *OnboardRuleListEvalRequest) Build() (*OnboardRuleListEvalRequest, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return r, nil
}

// ToProto serializes the typed request into a gRPC EvaluateRequest, attaching
// the supplied JWT token.
// Implements EvalRequest.
func (r *OnboardRuleListEvalRequest) ToProto(token string) *authzv1.EvaluateRequest {
	return &authzv1.EvaluateRequest{
		Token:  token,
		Action: "onboardrule:list",
		Resource: &authzv1.Resource{
			Type:       onboardRuleResourceType,
			Attributes: onboardRuleResourceToAttrs(r.Resource),
		},
	}
}

// OnboardRuleListEvalRequestFromProto converts a gRPC EvaluateRequest into a
// validated OnboardRuleListEvalRequest.
func OnboardRuleListEvalRequestFromProto(req *authzv1.EvaluateRequest) (*OnboardRuleListEvalRequest, error) {
	if req == nil {
		return nil, fmt.Errorf("onboardrule:list: EvaluateRequest is nil")
	}
	if req.Action != "onboardrule:list" {
		return nil, fmt.Errorf("onboardrule:list: action must be \"onboardrule:list\", got %q", req.Action)
	}
	if req.Resource == nil {
		return nil, fmt.Errorf("onboardrule:list: resource is nil")
	}
	if req.Resource.Type != onboardRuleResourceType {
		return nil, fmt.Errorf("onboardrule:list: resource type must be %q, got %q", onboardRuleResourceType, req.Resource.Type)
	}
	r := &OnboardRuleListEvalRequest{
		Resource: OnboardRuleResource{Org: req.Resource.Attributes["org"]},
	}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return r, nil
}

// Validate checks the request against the onboardrule:list contract.
// Implements EvalRequest.
func (r *OnboardRuleListEvalRequest) Validate() error {
	if r.Resource.Org == "" {
		return fmt.Errorf("onboardrule:list: resource org is required")
	}
	return nil
}

// OnboardRuleCreateEvalRequest is the validated, typed model for
// onboardrule:create policy evaluation. Use NewOnboardRuleCreateEvalRequest
// to start building, then chain With* methods and call Build to get a
// validated instance.
type OnboardRuleCreateEvalRequest struct {
	Resource OnboardRuleResource
}

var _ EvalRequest = (*OnboardRuleCreateEvalRequest)(nil)

// NewOnboardRuleCreateEvalRequest begins building an
// OnboardRuleCreateEvalRequest for the given proposed username pattern.
// Chain With* methods to supply additional fields, then call Build to
// validate and obtain the final struct.
func NewOnboardRuleCreateEvalRequest(usernamePattern string) *OnboardRuleCreateEvalRequest {
	return &OnboardRuleCreateEvalRequest{Resource: OnboardRuleResource{ID: usernamePattern}}
}

// WithOrg sets the organization the new rule will be scoped to.
func (r *OnboardRuleCreateEvalRequest) WithOrg(org string) *OnboardRuleCreateEvalRequest {
	r.Resource.Org = org
	return r
}

// WithIDP sets the identity provider the new rule applies to.
func (r *OnboardRuleCreateEvalRequest) WithIDP(idp string) *OnboardRuleCreateEvalRequest {
	r.Resource.IDP = idp
	return r
}

// Build validates the request and returns it if all constraints are satisfied.
// It is the required terminator for the builder chain.
func (r *OnboardRuleCreateEvalRequest) Build() (*OnboardRuleCreateEvalRequest, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return r, nil
}

// ToProto serializes the typed request into a gRPC EvaluateRequest, attaching
// the supplied JWT token.
// Implements EvalRequest.
func (r *OnboardRuleCreateEvalRequest) ToProto(token string) *authzv1.EvaluateRequest {
	return &authzv1.EvaluateRequest{
		Token:  token,
		Action: "onboardrule:create",
		Resource: &authzv1.Resource{
			Type:       onboardRuleResourceType,
			Id:         r.Resource.ID,
			Attributes: onboardRuleResourceToAttrs(r.Resource),
		},
	}
}

// OnboardRuleCreateEvalRequestFromProto converts a gRPC EvaluateRequest into
// a validated OnboardRuleCreateEvalRequest.
func OnboardRuleCreateEvalRequestFromProto(req *authzv1.EvaluateRequest) (*OnboardRuleCreateEvalRequest, error) {
	if req == nil {
		return nil, fmt.Errorf("onboardrule:create: EvaluateRequest is nil")
	}
	if req.Action != "onboardrule:create" {
		return nil, fmt.Errorf("onboardrule:create: action must be \"onboardrule:create\", got %q", req.Action)
	}
	if req.Resource == nil {
		return nil, fmt.Errorf("onboardrule:create: resource is nil")
	}
	if req.Resource.Type != onboardRuleResourceType {
		return nil, fmt.Errorf("onboardrule:create: resource type must be %q, got %q", onboardRuleResourceType, req.Resource.Type)
	}
	r := &OnboardRuleCreateEvalRequest{
		Resource: OnboardRuleResource{
			ID:  req.Resource.Id,
			Org: req.Resource.Attributes["org"],
			IDP: req.Resource.Attributes["idp"],
		},
	}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return r, nil
}

// Validate checks the request against the onboardrule:create contract.
// Implements EvalRequest.
func (r *OnboardRuleCreateEvalRequest) Validate() error {
	if r.Resource.ID == "" {
		return fmt.Errorf("onboardrule:create: resource ID (username pattern) is required")
	}
	if r.Resource.Org == "" {
		return fmt.Errorf("onboardrule:create: resource org is required")
	}
	if r.Resource.IDP == "" {
		return fmt.Errorf("onboardrule:create: resource idp is required")
	}
	return nil
}

// OnboardRuleUpdateEvalRequest is the validated, typed model for
// onboardrule:update policy evaluation. Use NewOnboardRuleUpdateEvalRequest
// to start building, then chain WithOrg and call Build to get a validated
// instance.
type OnboardRuleUpdateEvalRequest struct {
	Resource OnboardRuleResource
}

var _ EvalRequest = (*OnboardRuleUpdateEvalRequest)(nil)

// NewOnboardRuleUpdateEvalRequest begins building an
// OnboardRuleUpdateEvalRequest for the given rule id (as a decimal string).
// Chain WithOrg to supply the rule's organization, then call Build to
// validate and obtain the final struct.
func NewOnboardRuleUpdateEvalRequest(id string) *OnboardRuleUpdateEvalRequest {
	return &OnboardRuleUpdateEvalRequest{Resource: OnboardRuleResource{ID: id}}
}

// WithOrg sets the organization the rule being updated is scoped to.
func (r *OnboardRuleUpdateEvalRequest) WithOrg(org string) *OnboardRuleUpdateEvalRequest {
	r.Resource.Org = org
	return r
}

// Build validates the request and returns it if all constraints are satisfied.
// It is the required terminator for the builder chain.
func (r *OnboardRuleUpdateEvalRequest) Build() (*OnboardRuleUpdateEvalRequest, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return r, nil
}

// ToProto serializes the typed request into a gRPC EvaluateRequest, attaching
// the supplied JWT token.
// Implements EvalRequest.
func (r *OnboardRuleUpdateEvalRequest) ToProto(token string) *authzv1.EvaluateRequest {
	return &authzv1.EvaluateRequest{
		Token:  token,
		Action: "onboardrule:update",
		Resource: &authzv1.Resource{
			Type:       onboardRuleResourceType,
			Id:         r.Resource.ID,
			Attributes: onboardRuleResourceToAttrs(r.Resource),
		},
	}
}

// OnboardRuleUpdateEvalRequestFromProto converts a gRPC EvaluateRequest into
// a validated OnboardRuleUpdateEvalRequest.
func OnboardRuleUpdateEvalRequestFromProto(req *authzv1.EvaluateRequest) (*OnboardRuleUpdateEvalRequest, error) {
	if req == nil {
		return nil, fmt.Errorf("onboardrule:update: EvaluateRequest is nil")
	}
	if req.Action != "onboardrule:update" {
		return nil, fmt.Errorf("onboardrule:update: action must be \"onboardrule:update\", got %q", req.Action)
	}
	if req.Resource == nil {
		return nil, fmt.Errorf("onboardrule:update: resource is nil")
	}
	if req.Resource.Type != onboardRuleResourceType {
		return nil, fmt.Errorf("onboardrule:update: resource type must be %q, got %q", onboardRuleResourceType, req.Resource.Type)
	}
	r := &OnboardRuleUpdateEvalRequest{
		Resource: OnboardRuleResource{
			ID:  req.Resource.Id,
			Org: req.Resource.Attributes["org"],
		},
	}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return r, nil
}

// Validate checks the request against the onboardrule:update contract.
// Implements EvalRequest.
func (r *OnboardRuleUpdateEvalRequest) Validate() error {
	if r.Resource.ID == "" {
		return fmt.Errorf("onboardrule:update: resource ID (rule id) is required")
	}
	if r.Resource.Org == "" {
		return fmt.Errorf("onboardrule:update: resource org is required")
	}
	return nil
}

// OnboardRuleDeleteEvalRequest is the validated, typed model for
// onboardrule:delete policy evaluation. Use NewOnboardRuleDeleteEvalRequest
// to start building, then chain WithOrg and call Build to get a validated
// instance.
type OnboardRuleDeleteEvalRequest struct {
	Resource OnboardRuleResource
}

var _ EvalRequest = (*OnboardRuleDeleteEvalRequest)(nil)

// NewOnboardRuleDeleteEvalRequest begins building an
// OnboardRuleDeleteEvalRequest for the given rule id (as a decimal string).
// Chain WithOrg to supply the rule's organization, then call Build to
// validate and obtain the final struct.
func NewOnboardRuleDeleteEvalRequest(id string) *OnboardRuleDeleteEvalRequest {
	return &OnboardRuleDeleteEvalRequest{Resource: OnboardRuleResource{ID: id}}
}

// WithOrg sets the organization the rule being deleted is scoped to.
func (r *OnboardRuleDeleteEvalRequest) WithOrg(org string) *OnboardRuleDeleteEvalRequest {
	r.Resource.Org = org
	return r
}

// Build validates the request and returns it if all constraints are satisfied.
// It is the required terminator for the builder chain.
func (r *OnboardRuleDeleteEvalRequest) Build() (*OnboardRuleDeleteEvalRequest, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return r, nil
}

// ToProto serializes the typed request into a gRPC EvaluateRequest, attaching
// the supplied JWT token.
// Implements EvalRequest.
func (r *OnboardRuleDeleteEvalRequest) ToProto(token string) *authzv1.EvaluateRequest {
	return &authzv1.EvaluateRequest{
		Token:  token,
		Action: "onboardrule:delete",
		Resource: &authzv1.Resource{
			Type:       onboardRuleResourceType,
			Id:         r.Resource.ID,
			Attributes: onboardRuleResourceToAttrs(r.Resource),
		},
	}
}

// OnboardRuleDeleteEvalRequestFromProto converts a gRPC EvaluateRequest into
// a validated OnboardRuleDeleteEvalRequest.
func OnboardRuleDeleteEvalRequestFromProto(req *authzv1.EvaluateRequest) (*OnboardRuleDeleteEvalRequest, error) {
	if req == nil {
		return nil, fmt.Errorf("onboardrule:delete: EvaluateRequest is nil")
	}
	if req.Action != "onboardrule:delete" {
		return nil, fmt.Errorf("onboardrule:delete: action must be \"onboardrule:delete\", got %q", req.Action)
	}
	if req.Resource == nil {
		return nil, fmt.Errorf("onboardrule:delete: resource is nil")
	}
	if req.Resource.Type != onboardRuleResourceType {
		return nil, fmt.Errorf("onboardrule:delete: resource type must be %q, got %q", onboardRuleResourceType, req.Resource.Type)
	}
	r := &OnboardRuleDeleteEvalRequest{
		Resource: OnboardRuleResource{
			ID:  req.Resource.Id,
			Org: req.Resource.Attributes["org"],
		},
	}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return r, nil
}

// Validate checks the request against the onboardrule:delete contract.
// Implements EvalRequest.
func (r *OnboardRuleDeleteEvalRequest) Validate() error {
	if r.Resource.ID == "" {
		return fmt.Errorf("onboardrule:delete: resource ID (rule id) is required")
	}
	if r.Resource.Org == "" {
		return fmt.Errorf("onboardrule:delete: resource org is required")
	}
	return nil
}

// capabilityWildcardOnboardRule is a representative resource value used by
// the onboardrule capability probes below — the result reports what could
// be done to a rule of ctx.Org's in general, not the state of any specific
// existing one.
const capabilityWildcardOnboardRule = "*"

// init registers a capability probe for every onboardrule domain action.
// See CapabilityCheck and registerCapabilityCheck in capability.go.
func init() {
	registerCapabilityCheck(CapabilityCheck{
		Action: "onboardrule:list", Package: "onboardrule", Scope: "onboardrule:list",
		Build: func(ctx CapabilityContext) (EvalRequest, error) {
			return NewOnboardRuleListEvalRequest(ctx.Org).Build()
		},
	})
	registerCapabilityCheck(CapabilityCheck{
		Action: "onboardrule:create", Package: "onboardrule", Scope: "onboardrule:create",
		Build: func(ctx CapabilityContext) (EvalRequest, error) {
			return NewOnboardRuleCreateEvalRequest(capabilityWildcardOnboardRule).WithOrg(ctx.Org).WithIDP(ctx.IDP).Build()
		},
	})
	registerCapabilityCheck(CapabilityCheck{
		Action: "onboardrule:update", Package: "onboardrule", Scope: "onboardrule:update",
		Build: func(ctx CapabilityContext) (EvalRequest, error) {
			return NewOnboardRuleUpdateEvalRequest(capabilityWildcardOnboardRule).WithOrg(ctx.Org).Build()
		},
	})
	registerCapabilityCheck(CapabilityCheck{
		Action: "onboardrule:delete", Package: "onboardrule", Scope: "onboardrule:delete",
		Build: func(ctx CapabilityContext) (EvalRequest, error) {
			return NewOnboardRuleDeleteEvalRequest(capabilityWildcardOnboardRule).WithOrg(ctx.Org).Build()
		},
	})
}
