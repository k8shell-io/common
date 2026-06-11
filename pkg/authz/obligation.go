// Copyright 2026 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package authz

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
