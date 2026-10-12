// Copyright 2026 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package authz

// Contract: threat:detect
//
// Decides which attack categories worktrace watches on a workspace; it is NOT
// an access check. Callers must not gate on PolicyResult.Allowed — only the
// obligations are consumed. The provisioner evaluates it when it provisions a
// workspace, as the provisioning subject, and stores the result for the
// workspace (see nats.ResolveDetectObligation). A missing "detect" obligation
// means the enforcer's default: worktrace then applies its global rule
// rollout. threat:detect is not a grantable PAT scope and has no capability
// probe.
//
// Resource  type="workspace"
//   id         workspace name            (required)
//   owner      workspace owner username  (required)
//   blueprint  blueprint name            (optional)
//
// Context
//   blueprint           YAML-encoded blueprint struct (optional): the full
//                       blueprint being provisioned, encoded exactly as in
//                       workspace:provision. Callers should pass the blueprint
//                       after provisioning patches are applied, so the policy
//                       sees what actually runs. A missing blueprint means the
//                       policy can match on the blueprint name only.
//   mode                standalone | inject  (required)
//   namespace           namespace the workspace pod runs in (required): the
//                       provisioner's target namespace for standalone, the
//                       workload's namespace for inject. Together with mode,
//                       this is always available to tell standalone from
//                       injected workspaces and injected namespaces apart.
//   workload_name       target workload name  (required for inject)
//   workload_kind       target workload kind  (required for inject)
//
// Subject   injected by the backend from JWT claims (username, roles, email, ...)
//
// Obligations
//   detect  none | all | <category>[,<category>...]
//     none        detect nothing on the workspace
//     all         detect every category, including ones added later
//     <category>  a worktrace rule category (threat.Categories), comma-separated
//   A present detect obligation decides every category: an absent one is not
//   watched. The obligation only selects categories; whether a category's
//   detections alert or are only recorded (shadow) stays with worktrace's
//   rule rollout. A workspace's detection override, when one is stored,
//   replaces this obligation entirely (see threat:detection:override);
//   enforcers apply it after evaluating.
//
// ---
//
// Contract: threat:detection:override
//
// Grants reading, setting and clearing a workspace's detection override: a
// stored "detect" value that replaces the threat:detect obligation for the
// workspace from then on, until it is cleared. One action covers all three
// operations; there is no separate read permission. It is a real access check:
// Allowed gates the request. Because an override can switch detection off,
// policy should grant it narrowly (typically admins only), and not to the
// workspace owner by default.
//
// Resource  type="workspace"
//   id     workspace name           (required, except in a capability probe)
//   owner  workspace owner username (required)
//
// Context   (none)
//
// Subject   injected by the backend from JWT claims (username, roles, email, ...)
//
// Obligations  none defined; the enforcer ignores any returned.
//
// Scope matrix:
//   id set,    owner set   → the override of one workspace (every API call)
//   id empty,  owner set   → capability probe: may the subject override
//                            workspaces of that owner in general
//
// PAT scope: threat:detection:override (flat, no per-category granularity).
//
// ---
//
// Example policy (package threat). The policies are not part of this module;
// this sketch shows one way to write them against the contracts above.
//
//	package threat
//
//	import rego.v1
//	import data.common
//
//	default allow := false
//
//	# admins can perform any threat action
//	allow if common.is_admin(input.subject)
//
//	# --- threat:detect ---
//
//	# threat:detect decides what to detect; it is not an access check, so any
//	# well-formed request is allowed
//	allow if input.action == "threat:detect"
//
//	deny if {
//	    input.action == "threat:detect"
//	    not valid_detect_input
//	}
//
//	valid_detect_input if {
//	    input.resource.type == "workspace"
//	    input.resource.id != ""
//	    input.resource.attributes.owner != ""
//	    input.context.mode in {"standalone", "inject"}
//	    input.context.namespace != ""
//	}
//
//	# the full blueprint, when the caller sent one (same encoding as
//	# workspace:provision)
//	blueprint := yaml.unmarshal(input.context.blueprint) if input.context.blueprint
//
//	obligations["detect"] := detect if input.action == "threat:detect"
//
//	# standalone workspaces: every category
//	detect := "all" if input.context.mode == "standalone"
//
//	# injected workspaces: the first matching detect_rules entry, else nothing
//	detect := concat(",", matching[0].categories) if {
//	    input.context.mode == "inject"
//	    count(matching) > 0
//	}
//
//	detect := "none" if {
//	    input.context.mode == "inject"
//	    count(matching) == 0
//	}
//
//	# an entry matches on namespace, and on org and blueprint when it sets them
//	matching := [rule |
//	    some rule in detect_rules
//	    rule.namespace == input.context.namespace
//	    object.get(rule, "org", input.subject.org) == input.subject.org
//	    object.get(rule, "blueprint", input.resource.attributes.blueprint) == input.resource.attributes.blueprint
//	]
//
//	detect_rules := [
//	    {"namespace": "k8shell-test", "categories": ["container-escape", "reverse-shells-and-execution"]},
//	]
//
//	# --- threat:detection:override ---
//
//	# an org-admin or <group>-admin may override detection on a workspace owned
//	# by an account they manage, but not on their own workspaces; with no
//	# resource id this answers the capability probe for that owner
//	allow if {
//	    input.action == "threat:detection:override"
//	    input.resource.type == "workspace"
//	    owner := input.resource.attributes.owner
//	    owner != ""
//	    owner != input.subject.username
//	    common.managed_by_group_admin(input.subject, enrich.user(owner))
//	}

import (
	"fmt"
	"strings"

	authzv1 "github.com/k8shell-io/common/pkg/api/gen/go/authz/v1"
	"github.com/k8shell-io/common/pkg/models"
	"github.com/k8shell-io/common/pkg/threat"
	"gopkg.in/yaml.v3"
)

// ThreatAction is the typed representation of a threat policy action.
type ThreatAction string

const (
	// ThreatActionDetect is the action evaluated when a workspace is
	// provisioned, solely to learn which attack categories worktrace watches
	// on it. The policy result carries a "detect" obligation; Allowed is not a
	// gate (see the contract above).
	ThreatActionDetect ThreatAction = "threat:detect"

	// ThreatActionDetectionOverride is the action evaluated when reading,
	// setting or clearing a workspace's detection override, which replaces
	// the threat:detect obligation for that workspace. The resource is always
	// one workspace (id and owner set), except in a capability probe, which
	// sets the owner only.
	ThreatActionDetectionOverride ThreatAction = "threat:detection:override"
)

// ThreatDetectContext holds the ambient attributes supplied by the caller in
// the context map of a threat:detect EvaluateRequest.
type ThreatDetectContext struct {
	// Blueprint is the full blueprint being provisioned (optional). It is
	// carried YAML-encoded in context["blueprint"].
	Blueprint    *models.Blueprint
	Mode         WorkspaceProvisionMode
	Namespace    string
	WorkloadName string
	WorkloadKind string
}

// ThreatDetectEvalRequest is the validated, typed model for threat:detect
// policy evaluation. Use NewThreatDetectEvalRequest to start building, then
// chain With* methods and call Build to get a validated instance. Use
// ThreatDetectEvalRequestFromProto to convert from a gRPC EvaluateRequest.
type ThreatDetectEvalRequest struct {
	Resource WorkspaceResource
	Context  ThreatDetectContext
}

var _ EvalRequest = (*ThreatDetectEvalRequest)(nil)

// NewThreatDetectEvalRequest begins building a ThreatDetectEvalRequest for
// the named workspace. Chain With* methods, then call Build.
func NewThreatDetectEvalRequest(workspaceID string) *ThreatDetectEvalRequest {
	return &ThreatDetectEvalRequest{Resource: WorkspaceResource{ID: workspaceID}}
}

// WithOwner sets the workspace owner on the resource.
func (r *ThreatDetectEvalRequest) WithOwner(owner string) *ThreatDetectEvalRequest {
	r.Resource.Owner = owner
	return r
}

// WithBlueprintName sets the blueprint name on the resource attributes.
func (r *ThreatDetectEvalRequest) WithBlueprintName(name string) *ThreatDetectEvalRequest {
	r.Resource.Blueprint = name
	return r
}

// WithBlueprint sets the full blueprint struct in the context; it is optional.
// Pass the blueprint after provisioning patches have been applied.
func (r *ThreatDetectEvalRequest) WithBlueprint(bp *models.Blueprint) *ThreatDetectEvalRequest {
	r.Context.Blueprint = bp
	return r
}

// WithMode sets the provisioning mode and the namespace the workspace pod
// runs in.
func (r *ThreatDetectEvalRequest) WithMode(mode WorkspaceProvisionMode, namespace string) *ThreatDetectEvalRequest {
	r.Context.Mode = mode
	r.Context.Namespace = namespace
	return r
}

// WithWorkload sets the target workload; required when mode is
// WorkspaceProvisionModeInject.
func (r *ThreatDetectEvalRequest) WithWorkload(name, kind string) *ThreatDetectEvalRequest {
	r.Context.WorkloadName = name
	r.Context.WorkloadKind = kind
	return r
}

// Build validates the request and returns it if all constraints are satisfied.
func (r *ThreatDetectEvalRequest) Build() (*ThreatDetectEvalRequest, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return r, nil
}

// ToProto serializes the typed request into a gRPC EvaluateRequest, attaching
// the supplied JWT token. Only non-empty optional fields are included.
// Implements EvalRequest.
func (r *ThreatDetectEvalRequest) ToProto(token string) *authzv1.EvaluateRequest {
	attrs := map[string]string{"owner": r.Resource.Owner}
	if r.Resource.Blueprint != "" {
		attrs["blueprint"] = r.Resource.Blueprint
	}
	ctx := map[string]string{
		"mode":      string(r.Context.Mode),
		"namespace": r.Context.Namespace,
	}
	if r.Context.Blueprint != nil {
		if data, err := yaml.Marshal(r.Context.Blueprint); err == nil {
			ctx["blueprint"] = string(data)
		}
	}
	if r.Context.WorkloadName != "" {
		ctx["workload_name"] = r.Context.WorkloadName
	}
	if r.Context.WorkloadKind != "" {
		ctx["workload_kind"] = r.Context.WorkloadKind
	}
	return &authzv1.EvaluateRequest{
		Token:  token,
		Action: string(ThreatActionDetect),
		Resource: &authzv1.Resource{
			Type:       "workspace",
			Id:         r.Resource.ID,
			Attributes: attrs,
		},
		Context: ctx,
	}
}

// ThreatDetectEvalRequestFromProto converts a gRPC EvaluateRequest into a
// validated ThreatDetectEvalRequest.
func ThreatDetectEvalRequestFromProto(req *authzv1.EvaluateRequest) (*ThreatDetectEvalRequest, error) {
	if req == nil {
		return nil, fmt.Errorf("threat:detect: EvaluateRequest is nil")
	}
	if req.Action != string(ThreatActionDetect) {
		return nil, fmt.Errorf("threat:detect: action must be %q, got %q", ThreatActionDetect, req.Action)
	}
	if req.Resource == nil {
		return nil, fmt.Errorf("threat:detect: resource is nil")
	}
	if req.Resource.Type != "workspace" {
		return nil, fmt.Errorf("threat:detect: resource type must be \"workspace\", got %q", req.Resource.Type)
	}
	attrs := req.Resource.Attributes
	ctx := req.Context
	r := &ThreatDetectEvalRequest{
		Resource: WorkspaceResource{
			ID:        req.Resource.Id,
			Owner:     attrs["owner"],
			Blueprint: attrs["blueprint"],
		},
		Context: ThreatDetectContext{
			Mode:         WorkspaceProvisionMode(ctx["mode"]),
			Namespace:    ctx["namespace"],
			WorkloadName: ctx["workload_name"],
			WorkloadKind: ctx["workload_kind"],
		},
	}
	if raw, ok := ctx["blueprint"]; ok {
		var bp models.Blueprint
		if err := yaml.Unmarshal([]byte(raw), &bp); err != nil {
			return nil, fmt.Errorf("threat:detect: failed to decode blueprint context: %w", err)
		}
		r.Context.Blueprint = &bp
	}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return r, nil
}

// Validate checks the request against the threat:detect contract.
// Implements EvalRequest.
func (r *ThreatDetectEvalRequest) Validate() error {
	if r.Resource.ID == "" {
		return fmt.Errorf("threat:detect: resource ID (workspace name) is required")
	}
	if r.Resource.Owner == "" {
		return fmt.Errorf("threat:detect: resource attribute \"owner\" is required")
	}
	if _, ok := validWorkspaceProvisionModes[r.Context.Mode]; !ok {
		return fmt.Errorf("threat:detect: context \"mode\" must be %q or %q, got %q",
			WorkspaceProvisionModeStandalone, WorkspaceProvisionModeInject, r.Context.Mode)
	}
	if r.Context.Namespace == "" {
		return fmt.Errorf("threat:detect: context \"namespace\" is required")
	}
	if r.Context.Mode == WorkspaceProvisionModeInject && (r.Context.WorkloadName == "" || r.Context.WorkloadKind == "") {
		return fmt.Errorf("threat:detect: context \"workload_name\" and \"workload_kind\" are required for inject")
	}
	return nil
}

// --- threat:detection:override ---

// ThreatDetectionOverrideEvalRequest is the typed authorization request for
// threat:detection:override. The resource is the workspace whose override is
// read or written.
type ThreatDetectionOverrideEvalRequest struct {
	Resource WorkspaceResource
}

var _ EvalRequest = (*ThreatDetectionOverrideEvalRequest)(nil)

// NewThreatDetectionOverrideEvalRequest returns a
// ThreatDetectionOverrideEvalRequest for the named workspace. Chain WithOwner,
// then call Build.
func NewThreatDetectionOverrideEvalRequest(workspaceID string) *ThreatDetectionOverrideEvalRequest {
	return &ThreatDetectionOverrideEvalRequest{Resource: WorkspaceResource{ID: workspaceID}}
}

// WithOwner sets the workspace owner's username.
func (r *ThreatDetectionOverrideEvalRequest) WithOwner(owner string) *ThreatDetectionOverrideEvalRequest {
	r.Resource.Owner = owner
	return r
}

// Build validates the request and returns it if all constraints are satisfied.
func (r *ThreatDetectionOverrideEvalRequest) Build() (*ThreatDetectionOverrideEvalRequest, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return r, nil
}

// ToProto serializes the typed request into a gRPC EvaluateRequest.
// Implements EvalRequest.
func (r *ThreatDetectionOverrideEvalRequest) ToProto(token string) *authzv1.EvaluateRequest {
	return &authzv1.EvaluateRequest{
		Token:  token,
		Action: string(ThreatActionDetectionOverride),
		Resource: &authzv1.Resource{
			Type:       "workspace",
			Id:         r.Resource.ID,
			Attributes: map[string]string{"owner": r.Resource.Owner},
		},
	}
}

// ThreatDetectionOverrideEvalRequestFromProto converts a gRPC EvaluateRequest
// into a validated ThreatDetectionOverrideEvalRequest.
func ThreatDetectionOverrideEvalRequestFromProto(req *authzv1.EvaluateRequest) (*ThreatDetectionOverrideEvalRequest, error) {
	if req == nil {
		return nil, fmt.Errorf("threat:detection:override: EvaluateRequest is nil")
	}
	if req.Action != string(ThreatActionDetectionOverride) {
		return nil, fmt.Errorf("threat:detection:override: action must be %q, got %q", ThreatActionDetectionOverride, req.Action)
	}
	if req.Resource == nil {
		return nil, fmt.Errorf("threat:detection:override: resource is nil")
	}
	if req.Resource.Type != "workspace" {
		return nil, fmt.Errorf("threat:detection:override: resource type must be \"workspace\", got %q", req.Resource.Type)
	}
	r := &ThreatDetectionOverrideEvalRequest{
		Resource: WorkspaceResource{
			ID:    req.Resource.Id,
			Owner: req.Resource.Attributes["owner"],
		},
	}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return r, nil
}

// Validate checks the request: owner is required; the workspace id may be
// empty only in a capability probe. Implements EvalRequest.
func (r *ThreatDetectionOverrideEvalRequest) Validate() error {
	if r.Resource.Owner == "" {
		return fmt.Errorf("threat:detection:override: resource attribute \"owner\" is required")
	}
	return nil
}

// --- detect obligation ---

const (
	// ObligationKeyDetect is the key the policy engine writes for
	// threat:detect: which categories worktrace watches on the workspace.
	ObligationKeyDetect = "detect"

	// ObligationDetectNone disables detection on the workspace.
	ObligationDetectNone = "none"

	// ObligationDetectAll enables every category, including ones added after
	// the decision was made.
	ObligationDetectAll = "all"
)

// DetectObligation is the typed representation of the "detect" obligation.
// The zero value detects nothing.
type DetectObligation struct {
	// All enables every category; Categories is then empty.
	All bool

	// Categories lists the enabled categories when All is false, in the order
	// given. It may hold categories this module does not know yet.
	Categories []threat.Category
}

// Includes reports whether category c is detected.
func (o DetectObligation) Includes(c threat.Category) bool {
	if o.All {
		return true
	}
	for _, have := range o.Categories {
		if have == c {
			return true
		}
	}
	return false
}

// None reports whether nothing is detected.
func (o DetectObligation) None() bool {
	return !o.All && len(o.Categories) == 0
}

// String returns the obligation as a "detect" value: "all", "none", or the
// comma-separated categories. ParseDetectObligation reads it back.
func (o DetectObligation) String() string {
	switch {
	case o.All:
		return ObligationDetectAll
	case len(o.Categories) == 0:
		return ObligationDetectNone
	}
	tokens := make([]string, len(o.Categories))
	for i, c := range o.Categories {
		tokens[i] = string(c)
	}
	return strings.Join(tokens, ",")
}

// ValidateDetectObligation checks a "detect" value strictly, for enforcers
// that accept one from a user rather than from the policy engine: every
// comma-separated token must be a known category, at least one must be
// given, and "none" or "all" must stand alone. ParseDetectObligation itself
// keeps unknown categories.
func ValidateDetectObligation(v string) error {
	tokens := strings.Split(v, ",")
	for _, t := range tokens {
		switch t = strings.TrimSpace(t); t {
		case ObligationDetectNone, ObligationDetectAll:
			if len(tokens) > 1 {
				return fmt.Errorf("detect: %q cannot be combined with other values", t)
			}
		case "":
			return fmt.Errorf("detect: empty value")
		default:
			if !threat.Known(threat.Category(t)) {
				return fmt.Errorf("detect: unknown category %q", t)
			}
		}
	}
	return nil
}

// ParseDetectObligation reads the "detect" key from the obligations map. The
// value is "none", "all", or comma-separated categories; "all" anywhere wins,
// and empty and duplicate tokens are dropped. Unknown categories are kept, so
// a category worktrace adds before this module knows it still applies.
// Returns (obligation, true) when the key is present, (zero, false) when the
// policy set no detect obligation — the enforcer then applies its default.
func ParseDetectObligation(obligations map[string]string) (DetectObligation, bool) {
	v, ok := obligations[ObligationKeyDetect]
	if !ok {
		return DetectObligation{}, false
	}
	var ob DetectObligation
	seen := map[threat.Category]struct{}{}
	for t := range strings.SplitSeq(v, ",") {
		switch t = strings.TrimSpace(t); t {
		case ObligationDetectAll:
			return DetectObligation{All: true}, true
		case ObligationDetectNone, "":
		default:
			c := threat.Category(t)
			if _, dup := seen[c]; !dup {
				seen[c] = struct{}{}
				ob.Categories = append(ob.Categories, c)
			}
		}
	}
	return ob, true
}

// init registers the capability probe for threat:detection:override.
// threat:detect is not a permission (it only yields obligations), so it has
// no probe. See CapabilityCheck and registerCapabilityCheck in capability.go.
func init() {
	registerCapabilityCheck(CapabilityCheck{
		Action: string(ThreatActionDetectionOverride), Package: "threat", Scope: string(ThreatActionDetectionOverride),
		Build: func(ctx CapabilityContext) (EvalRequest, error) {
			return NewThreatDetectionOverrideEvalRequest("").WithOwner(ctx.ResourceOwner).Build()
		},
	})
}
