// Copyright 2026 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import "time"

// AccessToken is a Personal Access Token (PAT) tied to a user.
// It carries an explicit scopes list that caps what actions the token may perform.
// The raw token value is never stored here; only the DB layer holds the hash.
type AccessToken struct {
	ID         int64
	Username   string
	Name       string
	Scopes     []string
	ExpiresAt  *time.Time
	CreatedAt  time.Time
	LastUsedAt *time.Time
	IsActive   bool
}
