// Copyright 2026 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package nats

// PasswordLockoutState is the JSON value stored in PASSWORD_LOCKOUT_BUCKET
// for a username, tracking password-authentication failures.
//
// identity is the sole producer and consumer: AuthUserPassword reads and
// writes this bucket directly on every call, regardless of which caller
// (ssh-proxy, api-server, or any other gRPC client) invoked it, so the
// lockout is enforced consistently no matter which auth surface is used.
// This is distinct from UserLockState/LOCKED_USERS_BUCKET, which tracks an
// administrative lock set by api-server and observed by ssh-proxy.
type PasswordLockoutState struct {
	// FailedAttempts is the number of consecutive failed password attempts
	// since the last success or lockout expiry.
	FailedAttempts int `json:"failedAttempts,omitempty"`

	// LockedUntil is the unix time (seconds) the account remains locked
	// until. Zero means not currently locked.
	LockedUntil int64 `json:"lockedUntil,omitempty"`
}
