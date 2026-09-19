// Copyright 2026 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"encoding/json"
	"time"
)

// UserSettings is a user's opaque settings blob. A user with no row is
// represented by the zero value of this type, not a nil/not-found signal —
// GetUserSettings never errors on a missing row. Data is json.RawMessage
// (not []byte) so it serializes as an embedded JSON value rather than a
// base64 string.
type UserSettings struct {
	Username  string          `json:"username"`
	Version   int32           `json:"version"`
	Data      json.RawMessage `json:"data,omitempty"`
	UpdatedAt time.Time       `json:"updatedAt"`
}
