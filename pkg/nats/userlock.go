// Copyright 2026 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package nats

// UserLockState is the JSON value stored in LOCKED_USERS_BUCKET for a
// username.
//
// api-server is the sole producer: it writes an entry whenever a user is
// locked or unlocked (see its setUserLocked), and its own AuthMiddleware
// reads the bucket directly on every request as a fast-path check.
//
// ssh-proxy is a consumer: it subscribes to bucket changes (see
// NATSClient.NewKVSubscriber, which delivers a KVEvent per write) and, on any
// event decoding to UserLockState.Locked == true, closes its live SSH
// connection(s) for that username. It should ignore Locked == false —
// unlocking a web account doesn't imply an SSH session should be allowed to
// resume; the user reconnects normally on their next attempt.
type UserLockState struct {
	// Locked is whether the account is currently locked. Consumers should
	// treat any request/connection for this username as denied while true.
	Locked bool `json:"locked,omitempty"`

	// SessionsInvalidBefore is the unix time (seconds) of the most recent
	// lock. Unlike Locked, it survives the account being unlocked again, so
	// api-server can keep rejecting a web session that predates the lock
	// even after unlock — forcing a fresh login rather than silently
	// resuming. ssh-proxy has no equivalent persistent session concept and
	// can ignore this field.
	SessionsInvalidBefore int64 `json:"sessionsInvalidBefore,omitempty"`
}
