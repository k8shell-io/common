// Copyright 2026 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package authz

import (
	"fmt"
	"strings"
)

// Scope is a PAT access token scope string. It is either an exact action string
// from the registry (e.g. "workspace:list") or a wildcard pattern with "*" as
// the last segment (e.g. "workspace:connect:*"), optionally narrowed by a
// trailing constraint (e.g. "user:read:profile:self").
//
// Grammar:
//
//	scope      = "*"
//	           | domain ":" action
//	           | domain ":" action ":" qualifier
//	           | domain ":" action ":" qualifier ":" constraint
//	           | domain ":" action ":" "*"
//	           | domain ":" action ":" "*" ":" constraint
//	           | domain ":" "*"
//
// Matching is strict (Option A): a scope without a wildcard matches only its
// exact action string. To cover all qualifiers of an action, the scope must
// carry an explicit ":*" suffix (e.g. "workspace:connect:*").
//
// A constraint is an additional, orthogonal condition evaluated against the
// request rather than the action string — it doesn't change which action the
// scope matches, only whether the scope applies to this particular request.
// A plain (unconstrained) scope keeps matching regardless of any constraint
// state, so a token already holding the broad "user:read:profile" scope is
// unaffected by a caller also being able to satisfy "self". See
// ScopeConstraint for the constraint vocabulary and ScopeAllows for how
// constraint satisfaction is supplied by the caller.
type Scope string

const scopeWildcard = "*"

// ScopeConstraint is the optional 4th segment of a scope string. It narrows
// a scope to requests that satisfy some condition the scope grammar alone
// can't express — one the caller must evaluate against the actual request
// and report back to ScopeAllows (e.g. "is the resource being accessed the
// token's own subject?"). New constraints are added to validScopeConstraints;
// domains opt individual domain:action prefixes into accepting a constraint
// suffix via scopeConstrainablePrefixes.
type ScopeConstraint string

const (
	// ScopeConstraintSelf restricts a scope to requests where the resource
	// being accessed belongs to the token's own subject, i.e.
	// resource.id == subject.username. Callers determine this themselves
	// (the scope layer has no resource awareness) and pass ScopeConstraintSelf
	// to ScopeAllows when true.
	ScopeConstraintSelf ScopeConstraint = "self"
)

// validScopeConstraints is the exhaustive registry of recognized constraint
// values.
var validScopeConstraints = map[ScopeConstraint]struct{}{
	ScopeConstraintSelf: {},
}

// scopeConstrainablePrefixes lists which "domain:action" or
// "domain:action:qualifier" prefixes may carry a trailing ":constraint"
// segment — i.e. actions (or specific qualifiers of an action) whose
// resource addresses a single owned target, where "self" narrowing is
// meaningful. A "domain:action" entry opts in every qualifier of that
// action at once, including the qualifier wildcard (equivalent to also
// allowing "domain:action:*:constraint"); see scopeConstrainable for the
// fallback rule. A "domain:action:qualifier" entry opts in only that one
// qualifier. This is deliberately coarse in one other respect (a listed
// prefix accepts every registered constraint, not a curated subset per
// prefix) since there is only one constraint today.
var scopeConstrainablePrefixes = map[string]struct{}{
	// user:read — every data type addresses the resource owner's own
	// record, so the whole action is opted in at once.
	"user:read": {}, // profile | credentials | blueprints | roles | keys

	// user:write — opted in per data type, deliberately excluding sudo,
	// locked, org, and posix: the user:write contract (see user.go) forbids
	// self writes to those groups unconditionally, so a ":self" scope for
	// them would validate a token that could never do anything.
	"user:write:profile":     {},
	"user:write:credentials": {},
	"user:write:blueprints":  {},
	"user:write:roles":       {},
	"user:write:keys":        {},
	"user:write:password":    {},

	// workspace — every action, including "list", addresses a resource with
	// an owner attribute the API server sets to the actual target of the
	// request (the queried username, or the caller's own username when no
	// explicit target is given — see workspace:list's contract for the
	// owner-optional listing scope). "self" is meaningful whenever that
	// target is the token's own subject.
	"workspace":           {}, // enables "workspace:*:self"
	"workspace:provision": {},
	"workspace:create":    {},
	"workspace:read":      {},
	"workspace:delete":    {},
	"workspace:files":     {},
	"workspace:connect":   {}, // webshell | webfiles | portforward
	"workspace:app":       {}, // read | install | start | stop
	"workspace:list":      {},

	// session:list — same reasoning as workspace:list: the API server sets
	// the owner attribute to the actual queried username, so "self" is
	// meaningful whenever that's the token's own subject. session:start
	// isn't listed here — it isn't a listing at all, and self-ness for it is
	// already implicit (a session is always started as the caller).
	"session:list": {},
}

// scopeConstrainable reports whether prefix — a "domain:action" or
// "domain:action:qualifier" string with any wildcard suffix already
// stripped — may carry a trailing ":constraint". A "domain:action:qualifier"
// prefix that isn't itself listed falls back to its "domain:action" prefix,
// so a blanket entry like "user:read" opts in every qualifier without an
// entry per qualifier; a flat "domain:action" prefix (no qualifier segment
// to fall back from) must be listed explicitly.
func scopeConstrainable(prefix string) bool {
	if _, ok := scopeConstrainablePrefixes[prefix]; ok {
		return true
	}
	segments := strings.Split(prefix, ":")
	if len(segments) > 2 {
		if _, ok := scopeConstrainablePrefixes[strings.Join(segments[:2], ":")]; ok {
			return true
		}
	}
	return false
}

// validExactScopes is the exhaustive registry of recognized exact scope strings.
// These mirror the action strings the API server constructs for PAT scope checks.
//
// For actions where the qualifier is embedded in the action string
// (workspace:connect:<type>, workspace:app:<op>, user:read:<dataType>),
// each concrete qualifier is its own entry. For flat actions (workspace:list,
// session:start, ssh:shell, …), the 2-segment string is the entry.
var validExactScopes = map[string]struct{}{
	// workspace — flat
	string(WorkspaceActionProvision): {},
	string(WorkspaceActionList):      {},
	string(WorkspaceActionCreate):    {},
	string(WorkspaceActionRead):      {},
	string(WorkspaceActionDelete):    {},
	string(WorkspaceActionFiles):     {},

	// workspace:connect — one entry per connect type
	string(WorkspaceActionConnect) + ":" + string(WorkspaceConnectTypeWebshell):    {},
	string(WorkspaceActionConnect) + ":" + string(WorkspaceConnectTypeWebfiles):    {},
	string(WorkspaceActionConnect) + ":" + string(WorkspaceConnectTypePortForward): {},

	// workspace:app — one entry per app op
	string(WorkspaceActionApp) + ":" + string(WorkspaceAppOpRead):    {},
	string(WorkspaceActionApp) + ":" + string(WorkspaceAppOpInstall): {},
	string(WorkspaceActionApp) + ":" + string(WorkspaceAppOpStart):   {},
	string(WorkspaceActionApp) + ":" + string(WorkspaceAppOpStop):    {},

	// session — flat
	string(SessionActionList): {},

	// user — flat
	"user:list": {},

	// user:read — one entry per data type
	"user:read:" + string(UserDataTypeProfile):     {},
	"user:read:" + string(UserDataTypeCredentials): {},
	"user:read:" + string(UserDataTypeBlueprints):  {},
	"user:read:" + string(UserDataTypeRoles):       {},
	"user:read:" + string(UserDataTypeKeys):        {},

	// user:write — one entry per data type
	"user:write:" + string(UserDataTypeProfile):     {},
	"user:write:" + string(UserDataTypeCredentials): {},
	"user:write:" + string(UserDataTypeBlueprints):  {},
	"user:write:" + string(UserDataTypeRoles):       {},
	"user:write:" + string(UserDataTypeKeys):        {},
	"user:write:" + string(UserDataTypeSudo):        {},
	"user:write:" + string(UserDataTypeLocked):      {},
	"user:write:" + string(UserDataTypeOrg):         {},
	"user:write:" + string(UserDataTypePosix):       {},
	"user:write:" + string(UserDataTypePassword):    {},
}

// validWildcardPrefixes is the set of prefixes that may appear before ":*".
// Only prefixes that have at least two concrete qualifiers are listed — there
// is no value in "workspace:provision:*" when there are no qualifiers.
var validWildcardPrefixes = map[string]struct{}{
	"workspace":         {}, // all workspace actions
	"workspace:connect": {}, // webshell | webfiles | portforward
	"workspace:app":     {}, // install | start | stop
	"session":           {}, // all session actions
	"user":              {}, // all user actions
	"user:read":         {}, // profile | credentials | blueprints | roles | keys
}

// ValidateScope reports whether s is a well-formed, recognized scope string.
// A scope is valid when it is:
//   - the bare wildcard "*"
//   - a known exact action string from the registry
//   - a known wildcard prefix followed by ":*"
//   - any of the above (except the bare wildcard) followed by ":constraint",
//     provided the "domain:action" prefix accepts a constraint suffix
func ValidateScope(s string) error {
	if s == "" {
		return fmt.Errorf("scope: empty string is not valid")
	}
	if s == scopeWildcard {
		return nil
	}
	base, constraint, hasConstraint := cutConstraint(s)
	if hasConstraint {
		if _, valid := validScopeConstraints[ScopeConstraint(constraint)]; !valid {
			return fmt.Errorf("scope: %q is not a recognized constraint", constraint)
		}
		prefix := base
		if p, ok := strings.CutSuffix(base, ":*"); ok {
			prefix = p
		}
		if !scopeConstrainable(prefix) {
			return fmt.Errorf("scope: %q does not accept a :%s constraint", prefix, constraint)
		}
	}
	if prefix, ok := strings.CutSuffix(base, ":*"); ok {
		if _, valid := validWildcardPrefixes[prefix]; !valid {
			return fmt.Errorf("scope: %q is not a recognized wildcard prefix", prefix)
		}
		return nil
	}
	if _, ok := validExactScopes[base]; !ok {
		return fmt.Errorf("scope: %q is not a recognized action scope", base)
	}
	return nil
}

// cutConstraint splits a trailing ":constraint" segment off s, where
// constraint is a recognized ScopeConstraint value. It returns s unchanged
// with ok=false when the last segment isn't a known constraint — that keeps
// an unconstrained scope whose qualifier happens to collide with a
// constraint name (none do today) from being misparsed, and lets callers
// tell a genuinely malformed constraint apart from "no constraint present"
// via the subsequent validScopeConstraints check on the raw last segment
// when the prefix is constrainable.
func cutConstraint(s string) (base, constraint string, ok bool) {
	i := strings.LastIndex(s, ":")
	if i < 0 {
		return s, "", false
	}
	last := s[i+1:]
	if last == scopeWildcard {
		return s, "", false
	}
	if _, known := validScopeConstraints[ScopeConstraint(last)]; !known {
		return s, "", false
	}
	return s[:i], last, true
}

// ValidateScopes validates every scope in the slice. Returns the first error
// encountered, or nil when all scopes are valid. At least one scope is required.
func ValidateScopes(scopes []string) error {
	if len(scopes) == 0 {
		return fmt.Errorf("scope: at least one scope is required")
	}
	for _, s := range scopes {
		if err := ValidateScope(s); err != nil {
			return err
		}
	}
	return nil
}

// ScopeAllows reports whether any scope in the list permits action. satisfied
// lists the constraints the caller has determined the current request meets
// (e.g. pass ScopeConstraintSelf when resource.id == subject.username) — the
// scope layer has no resource awareness of its own, so this is how a caller
// tells it "self" applies here.
//
// Matching rules (strict):
//   - "*" matches any action
//   - "prefix:*" matches any action that starts with "prefix:"
//   - an exact scope matches only when scope == action
//   - a scope with a trailing ":constraint" additionally requires that
//     constraint to be present in satisfied; an unconstrained scope matches
//     regardless of satisfied, so a token holding the broad
//     "user:read:profile" scope still covers its own profile
func ScopeAllows(scopes []string, action string, satisfied ...ScopeConstraint) bool {
	for _, s := range scopes {
		if s == scopeWildcard {
			return true
		}
		base := s
		if b, constraint, ok := cutConstraint(s); ok {
			if !hasConstraint(satisfied, ScopeConstraint(constraint)) {
				continue
			}
			base = b
		}
		if prefix, ok := strings.CutSuffix(base, ":*"); ok {
			if strings.HasPrefix(action, prefix+":") {
				return true
			}
			continue
		}
		if base == action {
			return true
		}
	}
	return false
}

// hasConstraint reports whether c is present in satisfied.
func hasConstraint(satisfied []ScopeConstraint, c ScopeConstraint) bool {
	for _, s := range satisfied {
		if s == c {
			return true
		}
	}
	return false
}
