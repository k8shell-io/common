// Copyright 2026 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import "time"

// UserSettings is a user's opaque settings blob plus the subset of settings
// Identity itself validates and enforces (see ControlledSettings in
// identity.proto). A user with no row is represented by the zero value of
// this type, not a nil/not-found signal — GetUserSettings never errors on a
// missing row.
type UserSettings struct {
	Username  string    `json:"username"`
	Version   int32     `json:"version"`
	Data      []byte    `json:"data"`
	UpdatedAt time.Time `json:"updatedAt"`

	// SessionIdleTimeoutSeconds is nil when unset (use the platform
	// default).
	SessionIdleTimeoutSeconds *int32 `json:"sessionIdleTimeoutSeconds,omitempty"`
}
