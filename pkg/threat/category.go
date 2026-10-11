// Copyright 2026 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package threat holds the threat detection vocabulary shared across the
// fleet: the worktrace rule categories. It is a leaf package, so both authz
// (the detect obligation) and models (the API schema) can depend on it.
package threat

// Category is a worktrace rule category: every detection rule and attack
// path belongs to exactly one, set by the category key of its rule file.
type Category string

const (
	ContainerEscape              Category = "container-escape"
	PrivilegeEscalationAndKernel Category = "privilege-escalation-and-kernel"
	ContainerRuntimeAndK8sAPI    Category = "container-runtime-and-k8s-api"
	CredentialAccess             Category = "credential-access"
	ReverseShellsAndExecution    Category = "reverse-shells-and-execution"
	Persistence                  Category = "persistence"
	DefenseEvasion               Category = "defense-evasion"
	Discovery                    Category = "discovery"
	LateralMovementAndNetwork    Category = "lateral-movement-and-network"
	Cryptomining                 Category = "cryptomining"
)

// Categories lists every category, in display order. It is the single source
// of the category list: the detect obligation validates against it, the API
// schema enumerates it, and the worktrace controller rejects rule files with
// a category not in it. Adding a category means adding it here, releasing
// this module and bumping it in its consumers.
var Categories = []Category{
	ContainerEscape,
	PrivilegeEscalationAndKernel,
	ContainerRuntimeAndK8sAPI,
	CredentialAccess,
	ReverseShellsAndExecution,
	Persistence,
	DefenseEvasion,
	Discovery,
	LateralMovementAndNetwork,
	Cryptomining,
}

var known = func() map[Category]struct{} {
	m := make(map[Category]struct{}, len(Categories))
	for _, c := range Categories {
		m[c] = struct{}{}
	}
	return m
}()

// Known reports whether c is in Categories.
func Known(c Category) bool {
	_, ok := known[c]
	return ok
}

// Strings returns Categories as strings, in the same order.
func Strings() []string {
	out := make([]string, len(Categories))
	for i, c := range Categories {
		out[i] = string(c)
	}
	return out
}
