// Copyright 2026 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package authz

import "testing"

func TestValidateScope(t *testing.T) {
	valid := []string{
		"*",
		"user:list",
		"user:read:profile",
		"user:read:*",
		"user:*",
		"workspace:connect:webshell",
		"workspace:connect:*",
		"user:read:profile:self",
		"user:read:credentials:self",
		"user:read:*:self",
		// user:write — self-eligible data types, individually and via the
		// qualifier wildcard.
		"user:write:profile:self",
		"user:write:credentials:self",
		"user:write:blueprints:self",
		"user:write:roles:self",
		"user:write:keys:self",
		"user:write:password:self",
		// workspace — every level of the hierarchy accepts :self.
		"workspace:read:self",
		"workspace:delete:self",
		"workspace:create:self",
		"workspace:provision:self",
		"workspace:files:self",
		"workspace:connect:webshell:self",
		"workspace:connect:*:self",
		"workspace:app:install:self",
		"workspace:app:*:self",
		"workspace:*:self",
		"workspace:list:self",
		"session:list:self",
	}
	for _, s := range valid {
		if err := ValidateScope(s); err != nil {
			t.Errorf("ValidateScope(%q) = %v, want nil", s, err)
		}
	}

	invalid := []string{
		"",
		"bogus",
		"user:read:profile:bogus", // unrecognized constraint
		"user:list:self",          // prefix not constrainable (no qualifier)
		"*:self",                  // bare wildcard can't carry a constraint
		"user:read:profile:*",     // constraint position doesn't take "*"
		// user:write — admin-managed-only data types never accept :self,
		// individually or via the qualifier wildcard.
		"user:write:sudo:self",
		"user:write:locked:self",
		"user:write:org:self",
		"user:write:posix:self",
		"user:write:*:self",  // wildcard can't cover a partial exclusion set
		"session:start:self", // not a listing; self is already implicit
	}
	for _, s := range invalid {
		if err := ValidateScope(s); err == nil {
			t.Errorf("ValidateScope(%q) = nil, want error", s)
		}
	}
}

func TestScopeAllowsConstraint(t *testing.T) {
	tests := []struct {
		name      string
		scopes    []string
		action    string
		satisfied []ScopeConstraint
		want      bool
	}{
		{
			name:      "self scope allows self request",
			scopes:    []string{"user:read:profile:self"},
			action:    "user:read:profile",
			satisfied: []ScopeConstraint{ScopeConstraintSelf},
			want:      true,
		},
		{
			name:      "self scope denies non-self request",
			scopes:    []string{"user:read:profile:self"},
			action:    "user:read:profile",
			satisfied: nil,
			want:      false,
		},
		{
			name:      "unconstrained scope allows self request too",
			scopes:    []string{"user:read:profile"},
			action:    "user:read:profile",
			satisfied: []ScopeConstraint{ScopeConstraintSelf},
			want:      true,
		},
		{
			name:      "unconstrained scope allows non-self request",
			scopes:    []string{"user:read:profile"},
			action:    "user:read:profile",
			satisfied: nil,
			want:      true,
		},
		{
			name:      "self wildcard covers any data type for self",
			scopes:    []string{"user:read:*:self"},
			action:    "user:read:credentials",
			satisfied: []ScopeConstraint{ScopeConstraintSelf},
			want:      true,
		},
		{
			name:      "self wildcard denies non-self request",
			scopes:    []string{"user:read:*:self"},
			action:    "user:read:credentials",
			satisfied: nil,
			want:      false,
		},
		{
			name:      "self scope does not leak to a different data type",
			scopes:    []string{"user:read:profile:self"},
			action:    "user:read:credentials",
			satisfied: []ScopeConstraint{ScopeConstraintSelf},
			want:      false,
		},
		{
			name:      "user:write self scope allows own profile write",
			scopes:    []string{"user:write:profile:self"},
			action:    "user:write:profile",
			satisfied: []ScopeConstraint{ScopeConstraintSelf},
			want:      true,
		},
		{
			name:      "user:write self scope denies non-self write",
			scopes:    []string{"user:write:profile:self"},
			action:    "user:write:profile",
			satisfied: nil,
			want:      false,
		},
		{
			name:      "workspace self scope allows own workspace read",
			scopes:    []string{"workspace:read:self"},
			action:    "workspace:read",
			satisfied: []ScopeConstraint{ScopeConstraintSelf},
			want:      true,
		},
		{
			name:      "workspace domain wildcard self covers connect for own workspace",
			scopes:    []string{"workspace:*:self"},
			action:    "workspace:connect:webshell",
			satisfied: []ScopeConstraint{ScopeConstraintSelf},
			want:      true,
		},
		{
			name:      "workspace domain wildcard self denies non-self connect",
			scopes:    []string{"workspace:*:self"},
			action:    "workspace:connect:webshell",
			satisfied: nil,
			want:      false,
		},
		{
			name:      "workspace connect self scope does not leak to app",
			scopes:    []string{"workspace:connect:*:self"},
			action:    "workspace:app:install",
			satisfied: []ScopeConstraint{ScopeConstraintSelf},
			want:      false,
		},
		{
			name:      "session list self scope allows own sessions",
			scopes:    []string{"session:list:self"},
			action:    "session:list",
			satisfied: []ScopeConstraint{ScopeConstraintSelf},
			want:      true,
		},
		{
			name:      "session list self scope denies unfiltered/other listing",
			scopes:    []string{"session:list:self"},
			action:    "session:list",
			satisfied: nil,
			want:      false,
		},
		{
			name:      "workspace list self scope allows own listing",
			scopes:    []string{"workspace:list:self"},
			action:    "workspace:list",
			satisfied: []ScopeConstraint{ScopeConstraintSelf},
			want:      true,
		},
		{
			name:      "workspace list self scope denies unfiltered/other listing",
			scopes:    []string{"workspace:list:self"},
			action:    "workspace:list",
			satisfied: nil,
			want:      false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ScopeAllows(tt.scopes, tt.action, tt.satisfied...); got != tt.want {
				t.Errorf("ScopeAllows(%v, %q, %v) = %v, want %v",
					tt.scopes, tt.action, tt.satisfied, got, tt.want)
			}
		})
	}
}
