// Copyright 2026 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package authz

import (
	"fmt"
	"strings"

	authzv1 "github.com/k8shell-io/common/pkg/api/gen/go/authz/v1"
)

// PolicyInput is the assembled input to a policy evaluation engine (e.g. OPA).
// It combines the decoded JWT subject with the validated, normalized fields from
// the gRPC EvaluateRequest. Construct via BuildPolicyInput.
type PolicyInput struct {
	Username string
	Roles    []string
	Action   string
	Resource PolicyResource
	Context  map[string]string
}

// PolicyResource holds the resource fields for policy evaluation,
// mirroring the proto Resource message.
type PolicyResource struct {
	Type       string
	ID         string
	Attributes map[string]string
}

// PolicyResult holds the outcome of a single policy evaluation.
type PolicyResult struct {
	Allowed     bool
	Reason      string
	Obligations map[string]string
}

// BuildPolicyInput parses the JWT from req, validates the request against the
// appropriate domain contract, and assembles the PolicyInput for the policy
// engine. It is the single entry point for all incoming EvaluateRequests on the
// server side — no per-domain routing is needed at the call site.
func BuildPolicyInput(req *authzv1.EvaluateRequest) (*PolicyInput, error) {
	claims, err := ParseUnverifiedClaims(req.GetToken(), true)
	if err != nil {
		return nil, fmt.Errorf("authz: parse token: %w", err)
	}

	roles := make([]string, 0, len(claims.Roles))
	for _, r := range claims.Roles {
		roles = append(roles, string(r))
	}

	normalized, err := normalizeByDomain(req)
	if err != nil {
		return nil, err
	}

	return policyInputFromProto(normalized, claims.GetUsername(), roles), nil
}

// normalizeByDomain routes req to its domain contract for validation, then
// re-serializes the typed result via ToProto so policyInputFromProto can treat
// all domains uniformly. Unknown domains pass through unchanged.
func normalizeByDomain(req *authzv1.EvaluateRequest) (*authzv1.EvaluateRequest, error) {
	action := req.GetAction()
	switch {
	case strings.HasPrefix(action, "ssh:"):
		sshReq, err := SSHEvalRequestFromProto(req)
		if err != nil {
			return nil, err
		}
		return sshReq.ToProto(""), nil
	default:
		return req, nil
	}
}

// policyInputFromProto assembles a PolicyInput from a (possibly normalized)
// proto and the already-decoded JWT subject fields.
func policyInputFromProto(req *authzv1.EvaluateRequest, username string, roles []string) *PolicyInput {
	input := &PolicyInput{
		Username: username,
		Roles:    roles,
		Action:   req.GetAction(),
		Context:  req.GetContext(),
	}
	if r := req.GetResource(); r != nil {
		input.Resource = PolicyResource{
			Type:       r.GetType(),
			ID:         r.GetId(),
			Attributes: r.GetAttributes(),
		}
	}
	return input
}

// PolicyResultFromProto converts a gRPC EvaluateResponse into a PolicyResult.
func PolicyResultFromProto(resp *authzv1.EvaluateResponse) *PolicyResult {
	if resp == nil {
		return &PolicyResult{}
	}
	return &PolicyResult{
		Allowed:     resp.GetAllowed(),
		Reason:      resp.GetReason(),
		Obligations: resp.GetObligations(),
	}
}

// ToProto converts a PolicyResult into a gRPC EvaluateResponse.
func (r *PolicyResult) ToProto() *authzv1.EvaluateResponse {
	return &authzv1.EvaluateResponse{
		Allowed:     r.Allowed,
		Reason:      r.Reason,
		Obligations: r.Obligations,
	}
}
