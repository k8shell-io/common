// Copyright 2026 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package authz

import (
	"strings"

	"github.com/k8shell-io/common/pkg/models"
)

const (
	// ObligationKeySudo is the key the policy engine writes when expressing a
	// sudo obligation. The enforcer reads this key and applies the value to the
	// user record before completing onboarding.
	ObligationKeySudo = "sudo"

	// ObligationSudoTrue is the obligation value that grants sudo access.
	ObligationSudoTrue = "true"

	// ObligationSudoFalse is the obligation value that explicitly denies sudo access.
	ObligationSudoFalse = "false"
)

// SudoObligation is the typed representation of the "sudo" obligation key
// returned by the policy engine in a PolicyResult.
type SudoObligation struct {
	// Granted is true when the policy grants sudo access, false when it denies it.
	Granted bool
}

const (
	// ObligationKeyRoles is the key the policy engine writes to assign roles
	// during onboarding. The value is a comma-separated list of role names.
	ObligationKeyRoles = "roles"
)

// RolesObligation is the typed representation of the "roles" obligation key
// returned by the policy engine in a PolicyResult.
type RolesObligation struct {
	// Roles is the list of roles the policy assigns to the user.
	Roles []models.Role
}

// ParseRolesObligation reads the "roles" key from the obligations map.
// Returns (obligation, true) when the key is present, (zero value, false) when
// the policy did not set a roles obligation — in that case the enforcer should
// preserve its existing default rather than overwriting it.
func ParseRolesObligation(obligations map[string]string) (RolesObligation, bool) {
	v, ok := obligations[ObligationKeyRoles]
	if !ok {
		return RolesObligation{}, false
	}
	var roles []models.Role
	for r := range strings.SplitSeq(v, ",") {
		if r = strings.TrimSpace(r); r != "" {
			roles = append(roles, models.Role(r))
		}
	}
	return RolesObligation{Roles: roles}, true
}

// ParseSudoObligation reads the "sudo" key from the obligations map.
// Returns (obligation, true) when the key is present, (zero value, false) when
// the policy did not set a sudo obligation — in that case the enforcer should
// preserve its existing default rather than overwriting it.
func ParseSudoObligation(obligations map[string]string) (SudoObligation, bool) {
	v, ok := obligations[ObligationKeySudo]
	if !ok {
		return SudoObligation{}, false
	}
	return SudoObligation{Granted: v == ObligationSudoTrue}, true
}
