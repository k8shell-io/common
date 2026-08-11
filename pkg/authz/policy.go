// Copyright 2026 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package authz

import (
	"fmt"
	"strings"

	authzv1 "github.com/k8shell-io/common/pkg/api/gen/go/authz/v1"
	"gopkg.in/yaml.v3"
)

// PolicyInput is the assembled input to a policy evaluation engine (e.g. OPA).
// It combines the decoded JWT subject with the validated, normalized fields from
// the gRPC EvaluateRequest. Construct via BuildPolicyInput.
type PolicyInput struct {
	Username  string
	Roles     []string
	Package   string
	Action    string
	Resource  PolicyResource
	Context   map[string]string
	Blueprint map[string]any // non-nil for workspace:* actions; decoded from context["blueprint"]

	// Scope is the compound "domain:action[:qualifier]" display form of
	// Action for actions whose qualifier (auth surface, credential type,
	// connect type, ...) is folded in for display — the same convention
	// CapabilityCheck.Action uses for the synthetic probe registry (see
	// capability.go), computed here from this request's actual context
	// instead of a fixed representative value. Equal to Action for actions
	// with no such qualifier.
	//
	// This is a display/audit convenience only — it must never be used for
	// policy routing or PAT scope matching, both of which stay keyed on the
	// base Action. The two can legitimately diverge: workspace:create's PAT
	// Scope stays "workspace:create" regardless of provision mode (a token
	// scoped for it may create either), while Scope here still distinguishes
	// "workspace:create:inject" from "workspace:create:standalone" so a
	// capability listing or audit trail can show which was actually used.
	Scope string

	// CapabilityCheck marks this evaluation as a synthetic "what can I do"
	// probe rather than a real access attempt. It is not set by
	// BuildPolicyInput — since capability_check is a BatchEvaluateRequest-level
	// flag, the caller of BatchEvaluate must propagate it onto each request's
	// PolicyInput after construction. Policy-decision audit logging should
	// record and classify these separately from genuine authorization
	// decisions.
	CapabilityCheck bool
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

	input := policyInputFromProto(normalized, claims.GetUsername(), roles)
	input.Scope = scopeForRequest(normalized)
	return input, nil
}

// scopeForRequest computes PolicyInput.Scope for req: the compound
// "domain:action[:qualifier]" display form CapabilityCheck.Action uses for
// the synthetic probe registry (capability.go), derived here from a real
// request's actual context rather than a fixed representative value.
// Actions with no qualifier — including ones normalizeByDomain doesn't
// route through a typed contract at all, like user:create/delete — return
// their base action unchanged. See PolicyInput.Scope's doc for why this must
// never be used for policy routing or PAT scope matching.
func scopeForRequest(req *authzv1.EvaluateRequest) string {
	action := req.GetAction()
	ctx := req.GetContext()

	fold := func(qualifier string) string {
		if qualifier == "" {
			return action
		}
		return action + ":" + qualifier
	}

	switch action {
	case "user:auth":
		return fold(ctx["surface"])
	case "user:exists":
		return fold(ctx["field"])
	case "user:read", "user:write":
		dataType := ctx["data_type"]
		if dataType == "credentials" {
			if credType := ctx["credential_type"]; credType != "" {
				return action + ":" + dataType + ":" + credType
			}
		}
		return fold(dataType)
	case "workspace:create":
		return fold(ctx["mode"])
	case "workspace:connect":
		return fold(ctx["type"])
	case "workspace:files", "workspace:app":
		return fold(ctx["op"])
	default:
		return action
	}
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
		normalized := sshReq.ToProto("")
		normalized.Package = req.Package
		return normalized, nil
	case action == "user:auth":
		authReq, err := UserAuthEvalRequestFromProto(req)
		if err != nil {
			return nil, err
		}
		normalized := authReq.ToProto("")
		normalized.Package = req.Package
		return normalized, nil
	case action == "user:read":
		readReq, err := UserReadEvalRequestFromProto(req)
		if err != nil {
			return nil, err
		}
		normalized := readReq.ToProto("")
		normalized.Package = req.Package
		return normalized, nil
	case action == "user:list":
		listReq, err := UserListEvalRequestFromProto(req)
		if err != nil {
			return nil, err
		}
		normalized := listReq.ToProto("")
		normalized.Package = req.Package
		return normalized, nil
	case action == "session:list":
		sessionListReq, err := SessionListEvalRequestFromProto(req)
		if err != nil {
			return nil, err
		}
		normalized := sessionListReq.ToProto("")
		normalized.Package = req.Package
		return normalized, nil
	case action == "session:start":
		sessionReq, err := SessionStartEvalRequestFromProto(req)
		if err != nil {
			return nil, err
		}
		normalized := sessionReq.ToProto("")
		normalized.Package = req.Package
		return normalized, nil
	case action == "workspace:provision":
		workspaceReq, err := WorkspaceEvalRequestFromProto(req)
		if err != nil {
			return nil, err
		}
		normalized := workspaceReq.ToProto("")
		normalized.Package = req.Package
		return normalized, nil
	case action == "workspace:list", action == "workspace:create":
		ownerReq, err := WorkspaceOwnerEvalRequestFromProto(req)
		if err != nil {
			return nil, err
		}
		normalized := ownerReq.ToProto("")
		normalized.Package = req.Package
		return normalized, nil
	case action == "workspace:read", action == "workspace:delete":
		accessReq, err := WorkspaceAccessEvalRequestFromProto(req)
		if err != nil {
			return nil, err
		}
		normalized := accessReq.ToProto("")
		normalized.Package = req.Package
		return normalized, nil
	case action == "workspace:connect":
		connectReq, err := WorkspaceConnectEvalRequestFromProto(req)
		if err != nil {
			return nil, err
		}
		normalized := connectReq.ToProto("")
		normalized.Package = req.Package
		return normalized, nil
	case action == "workspace:files":
		filesReq, err := WorkspaceFilesEvalRequestFromProto(req)
		if err != nil {
			return nil, err
		}
		normalized := filesReq.ToProto("")
		normalized.Package = req.Package
		return normalized, nil
	case action == "workspace:app":
		appReq, err := WorkspaceAppEvalRequestFromProto(req)
		if err != nil {
			return nil, err
		}
		normalized := appReq.ToProto("")
		normalized.Package = req.Package
		return normalized, nil
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
		Package:  req.GetPackage(),
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
	if strings.HasPrefix(req.GetAction(), "workspace:") {
		if raw, ok := req.GetContext()["blueprint"]; ok {
			var bp map[string]any
			if err := yaml.Unmarshal([]byte(raw), &bp); err == nil {
				input.Blueprint = bp
			}
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
