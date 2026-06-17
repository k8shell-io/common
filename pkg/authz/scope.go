// Copyright 2026 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package authz

import (
	"fmt"
	"strings"
)

// Scope is a PAT access token scope string. It is either an exact action string
// from the registry (e.g. "workspace:list") or a wildcard pattern with "*" as
// the last segment (e.g. "workspace:connect:*").
//
// Grammar:
//
//	scope     = "*"
//	          | domain ":" action
//	          | domain ":" action ":" qualifier
//	          | domain ":" action ":" "*"
//	          | domain ":" "*"
//
// Matching is strict (Option A): a scope without a wildcard matches only its
// exact action string. To cover all qualifiers of an action, the scope must
// carry an explicit ":*" suffix (e.g. "workspace:connect:*").
type Scope string

const scopeWildcard = "*"

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

	// user — flat
	"user:list": {},

	// user:read — one entry per data type
	"user:read:" + string(UserDataTypeProfile):     {},
	"user:read:" + string(UserDataTypeSessions):    {},
	"user:read:" + string(UserDataTypeCredentials): {},
	"user:read:" + string(UserDataTypeBlueprints):  {},

	// session:read — one entry per data type
	string(SessionActionRead) + ":" + string(SessionReadDataTypeLog):       {},
	string(SessionActionRead) + ":" + string(SessionReadDataTypeRecording): {},
}

// validWildcardPrefixes is the set of prefixes that may appear before ":*".
// Only prefixes that have at least two concrete qualifiers are listed — there
// is no value in "workspace:provision:*" when there are no qualifiers.
var validWildcardPrefixes = map[string]struct{}{
	"workspace":         {}, // all workspace actions
	"workspace:connect": {}, // webshell | webfiles | portforward
	"workspace:app":     {}, // install | start | stop
	"user":              {}, // all user actions
	"user:read":         {}, // profile | sessions | credentials | blueprints
	"session":           {}, // all session actions
	"session:read":      {}, // log | recording
}

// ValidateScope reports whether s is a well-formed, recognized scope string.
// A scope is valid when it is:
//   - the bare wildcard "*"
//   - a known exact action string from the registry
//   - a known wildcard prefix followed by ":*"
func ValidateScope(s string) error {
	if s == "" {
		return fmt.Errorf("scope: empty string is not valid")
	}
	if s == scopeWildcard {
		return nil
	}
	if prefix, ok := strings.CutSuffix(s, ":*"); ok {
		if _, valid := validWildcardPrefixes[prefix]; !valid {
			return fmt.Errorf("scope: %q is not a recognized wildcard prefix", prefix)
		}
		return nil
	}
	if _, ok := validExactScopes[s]; !ok {
		return fmt.Errorf("scope: %q is not a recognized action scope", s)
	}
	return nil
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

// ScopeAllows reports whether any scope in the list permits action.
// Matching rules (strict):
//   - "*" matches any action
//   - "prefix:*" matches any action that starts with "prefix:"
//   - an exact scope matches only when scope == action
func ScopeAllows(scopes []string, action string) bool {
	for _, s := range scopes {
		if s == scopeWildcard {
			return true
		}
		if prefix, ok := strings.CutSuffix(s, ":*"); ok {
			if strings.HasPrefix(action, prefix+":") {
				return true
			}
			continue
		}
		if s == action {
			return true
		}
	}
	return false
}
