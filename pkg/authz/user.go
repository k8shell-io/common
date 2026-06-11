// Copyright 2026 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package authz

import (
	"fmt"

	authzv1 "github.com/k8shell-io/common/pkg/api/gen/go/authz/v1"
)

// UserAction is the typed representation of a user policy action.
type UserAction string

const (
	// UserActionOnboard is the action evaluated when a user is created via an
	// identity provider. The policy result may carry obligations (e.g. sudo)
	// that the enforcer must apply to the stored user record.
	UserActionOnboard UserAction = "user:onboard"
)

// validUserActions is the set of recognized user actions for fast lookup.
var validUserActions = map[UserAction]struct{}{
	UserActionOnboard: {},
}

// UserResource holds the resource-scoped attributes for a user policy check.
type UserResource struct {
	// ID is the username (resource.id in the EvaluateRequest).
	ID string

	// IDP is the identity provider through which the user was onboarded
	// (resource.attributes["idp"]).
	IDP string

	// Org is the user's organization (resource.attributes["org"]).
	Org string
}

// UserEvalRequest is the validated, typed model for user policy evaluation.
// Use NewUserEvalRequest to start building, then chain With* methods and call
// Build to get a validated instance. Use UserEvalRequestFromProto to convert
// directly from a gRPC EvaluateRequest.
type UserEvalRequest struct {
	Action   UserAction
	Resource UserResource
}

var _ EvalRequest = (*UserEvalRequest)(nil)

// NewUserEvalRequest begins building a UserEvalRequest for the given action and
// username. Chain With* methods to supply additional fields, then call Build to
// validate and obtain the final struct.
func NewUserEvalRequest(action UserAction, username string) *UserEvalRequest {
	return &UserEvalRequest{
		Action:   action,
		Resource: UserResource{ID: username},
	}
}

// WithIDP sets the identity provider name on the resource.
func (r *UserEvalRequest) WithIDP(idp string) *UserEvalRequest {
	r.Resource.IDP = idp
	return r
}

// WithOrg sets the organization on the resource.
func (r *UserEvalRequest) WithOrg(org string) *UserEvalRequest {
	r.Resource.Org = org
	return r
}

// Build validates the request and returns it if all constraints are satisfied.
// It is the required terminator for the builder chain.
func (r *UserEvalRequest) Build() (*UserEvalRequest, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return r, nil
}

// ToProto serializes the typed request into a gRPC EvaluateRequest, attaching
// the supplied JWT token. Only non-empty resource attributes are included.
// Implements EvalRequest.
func (r *UserEvalRequest) ToProto(token string) *authzv1.EvaluateRequest {
	attrs := map[string]string{}
	if r.Resource.IDP != "" {
		attrs["idp"] = r.Resource.IDP
	}
	if r.Resource.Org != "" {
		attrs["org"] = r.Resource.Org
	}

	return &authzv1.EvaluateRequest{
		Token:  token,
		Action: string(r.Action),
		Resource: &authzv1.Resource{
			Type:       "user",
			Id:         r.Resource.ID,
			Attributes: attrs,
		},
	}
}

// UserEvalRequestFromProto converts a gRPC EvaluateRequest into a validated
// UserEvalRequest. Returns an error if the request does not conform to the
// user policy contract.
func UserEvalRequestFromProto(req *authzv1.EvaluateRequest) (*UserEvalRequest, error) {
	if req == nil {
		return nil, fmt.Errorf("user: EvaluateRequest is nil")
	}
	if req.Resource == nil {
		return nil, fmt.Errorf("user: resource is nil")
	}
	if req.Resource.Type != "user" {
		return nil, fmt.Errorf("user: resource type must be \"user\", got %q", req.Resource.Type)
	}

	attrs := req.Resource.Attributes

	r := &UserEvalRequest{
		Action: UserAction(req.Action),
		Resource: UserResource{
			ID:  req.Resource.Id,
			IDP: attrs["idp"],
			Org: attrs["org"],
		},
	}

	if err := r.Validate(); err != nil {
		return nil, err
	}
	return r, nil
}

// Validate checks the request against the user policy contract: the action
// must be recognized, and both ID and source are required.
// Implements EvalRequest.
func (r *UserEvalRequest) Validate() error {
	if _, ok := validUserActions[r.Action]; !ok {
		return fmt.Errorf("user: unknown action %q", r.Action)
	}
	if r.Resource.ID == "" {
		return fmt.Errorf("user: resource ID (username) is required")
	}
	if r.Resource.IDP == "" {
		return fmt.Errorf("user: resource attribute \"idp\" is required")
	}
	return nil
}
