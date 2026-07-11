// Copyright 2026 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package authz

import (
	"testing"
)

// expectedCapabilityActions is the pinned, exhaustive set of actions every
// contract in this package is expected to register a CapabilityCheck for.
//
// This list is deliberately maintained by hand, not derived from the action
// type enums (WorkspaceAction, UserDataType, ...) — several of those are
// validated with switch statements rather than an enumerable set, so there's
// no single reflectable source of truth to check against. Add or remove an
// entry here in the same change that adds or removes a registerCapabilityCheck
// call: that's what makes this test fail loudly instead of the capability
// report silently going out of sync with the contracts.
var expectedCapabilityActions = []string{
	"user:list",
	"user:onboard",
	"user:create",
	"user:delete",
	"user:auth:web",
	"user:auth:ssh",
	"user:read:profile",
	"user:read:credentials",
	"user:read:blueprints",
	"user:read:roles",
	"user:read:keys",
	"user:write:profile",
	"user:write:credentials",
	"user:write:blueprints",
	"user:write:roles",
	"user:write:keys",
	"user:write:sudo",
	"user:write:locked",
	"user:write:org",
	"user:write:posix",
	"user:write:password",
	"token:create",
	"token:read",
	"session:list",
	"session:start",
	"workspace:list",
	"workspace:create",
	"workspace:provision",
	"workspace:read",
	"workspace:delete",
	"workspace:connect:webshell",
	"workspace:connect:webfiles",
	"workspace:connect:portforward",
	"workspace:files:download",
	"workspace:files:upload",
	"workspace:app:read",
	"workspace:app:install",
	"workspace:app:start",
	"workspace:app:stop",
	"ssh:shell",
	"ssh:exec",
	"ssh:sftp",
	"ssh:direct-tcpip",
	"ssh:direct-streamlocal",
	"ssh:agent-forward",
}

func TestCapabilityChecksCompleteness(t *testing.T) {
	registered := map[string]int{}
	for _, c := range CapabilityChecks() {
		registered[c.Action]++
	}

	for action, count := range registered {
		if count > 1 {
			t.Errorf("action %q is registered %d times", action, count)
		}
	}

	expected := map[string]bool{}
	for _, action := range expectedCapabilityActions {
		expected[action] = true
		if _, ok := registered[action]; !ok {
			t.Errorf("expected action %q has no registered CapabilityCheck", action)
		}
	}

	for action := range registered {
		if !expected[action] {
			t.Errorf("action %q is registered but not in expectedCapabilityActions — add it there, "+
				"or remove the registration if it was a mistake", action)
		}
	}
}

// TestCapabilityCheckBuildable exercises every registered check's Build func
// with a fully-populated CapabilityContext, to catch a check that can never
// succeed even when every optional field is supplied (a real bug, unlike the
// deliberate "unevaluated" case tested separately below).
func TestCapabilityCheckBuildable(t *testing.T) {
	ctx := CapabilityContext{
		ResourceOwner: "alice",
		IDP:           "local",
		Org:           "acme",
		BlueprintName: "python",
	}

	for _, c := range CapabilityChecks() {
		if _, err := c.Build(ctx); err != nil {
			t.Errorf("action %q: Build failed with a fully-populated context: %v", c.Action, err)
		}
	}
}

// TestCapabilityCheckSelfOnly pins which actions are marked SelfOnly, so a
// change to that classification is a deliberate, reviewed edit rather than an
// accidental one.
func TestCapabilityCheckSelfOnly(t *testing.T) {
	wantSelfOnly := map[string]bool{
		"user:onboard":  true,
		"user:auth:web": true,
		"user:auth:ssh": true,
	}

	for _, c := range CapabilityChecks() {
		if c.SelfOnly != wantSelfOnly[c.Action] {
			t.Errorf("action %q: SelfOnly = %v, want %v", c.Action, c.SelfOnly, wantSelfOnly[c.Action])
		}
	}
}
