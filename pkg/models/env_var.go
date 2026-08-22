// Copyright 2025 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import "time"

// EnvVar is a single environment variable belonging to an organization or a
// user. Keys are case-insensitive and normalized to upper case before being
// stored or looked up.
type EnvVar struct {
	Key       string    `json:"key"`
	Value     string    `json:"value"`
	IsSecret  bool      `json:"isSecret"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`

	// Redacted is true when Value is empty because this entry was returned
	// by a list call and IsSecret is true — Value is only ever populated for
	// a secret by a single-key get, or by the create/update response for the
	// write that just set it.
	Redacted bool `json:"redacted,omitempty"`

	// Origin is "org" or "user", identifying which table this entry's
	// effective value came from. Set only when building a user's merged
	// effective env var view; empty for organization-scoped reads.
	Origin string `json:"origin,omitempty"`
}
