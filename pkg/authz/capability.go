// Copyright 2026 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package authz

import "github.com/k8shell-io/common/pkg/models"

// capabilityWildcardWorkspace/App/Command/Host/Port/SocketPath are
// representative resource values used by workspace/session/ssh capability
// probes — the result reports what could be done to a workspace/app of
// ResourceOwner's in general, not the state of any specific existing one.
const (
	capabilityWildcardWorkspace  = "*"
	capabilityWildcardApp        = "*"
	capabilityWildcardCommand    = "*"
	capabilityWildcardHost       = "*"
	capabilityWildcardPort       = "0"
	capabilityWildcardSocketPath = "/*"
)

// CapabilityContext carries every synthetic/representative value a
// capability probe might need to build a syntactically valid EvalRequest
// without a real resource existing. Not every action uses every field — each
// CapabilityCheck.Build pulls only what its contract requires.
type CapabilityContext struct {
	// ResourceOwner is the username whose resources the check is scoped to —
	// workspace/session/ssh owner, or the target user record itself.
	ResourceOwner string

	// IDP and Org are ResourceOwner's real identity source and organization,
	// required by user:onboard, user:auth, and used by user:create/delete.
	// Leave empty when unknown (e.g. ResourceOwner doesn't exist yet) — the
	// affected Build funcs then fail Validate() and the check is reported as
	// unevaluated rather than answered against a fabricated identity.
	IDP, Org string

	// BlueprintName and Blueprint feed workspace:provision. BlueprintName
	// empty means "not supplied" — Build leaves the request's required
	// blueprint context unset on purpose, so Validate() fails and the check
	// comes back unevaluated rather than silently denied.
	BlueprintName string
	Blueprint     *models.Blueprint
}

// CapabilityCheck is a self-describing, representative probe for one authz
// action: enough metadata to build a syntactically valid (if synthetic)
// EvalRequest for a "what can I do" report, without needing a real resource
// to exist.
type CapabilityCheck struct {
	// Action is the display action label, e.g. "workspace:connect:webshell".
	// Matches the literal action string except for compound actions where the
	// qualifier (connect type, app op, data type, auth surface) is folded in,
	// mirroring the PAT scope convention in scope.go.
	Action string

	// Package is the OPA policy package this action is evaluated under.
	Package string

	// Scope is the PAT token_scopes string that caps this action, in the same
	// "domain:action[:qualifier]" form ScopeAllows expects.
	Scope string

	// SelfOnly marks an action whose contract only makes sense when the
	// subject is the resource itself — user:auth (you can only authenticate
	// as yourself) and user:onboard (onboarding is bootstrapping your own
	// account). Callers building a report for a resource owner other than
	// the subject should skip SelfOnly checks entirely: there is no honest
	// answer to "can Z authenticate as X" for Z != X.
	SelfOnly bool

	// Build constructs the representative EvalRequest for this action from
	// ctx. It may return an error when required data isn't available in
	// ctx — callers should treat that as "unevaluated", not "denied".
	Build func(ctx CapabilityContext) (EvalRequest, error)
}

// capabilityChecks is the exhaustive registry of every action's capability
// probe. Each contract file in this package registers its own entries via
// registerCapabilityCheck in an init() next to the action constants it
// defines, so the probe travels with the contract instead of living in a
// downstream repo where it's easy to forget to update.
var capabilityChecks []CapabilityCheck

// registerCapabilityCheck adds c to the capability registry. Called from
// init() functions colocated with each contract's action definitions.
func registerCapabilityCheck(c CapabilityCheck) {
	capabilityChecks = append(capabilityChecks, c)
}

// CapabilityChecks returns every registered capability probe. The slice is a
// copy; callers may filter/reorder freely without affecting the registry.
func CapabilityChecks() []CapabilityCheck {
	out := make([]CapabilityCheck, len(capabilityChecks))
	copy(out, capabilityChecks)
	return out
}
