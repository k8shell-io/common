package nats

const (
	WORKSPACE_PROVISION_JOBS_BUCKET = "workspace-provision-jobs"

	// LOCKED_USERS_BUCKET holds per-user account lock state, keyed by
	// username. See UserLockState (userlock.go) for the value type stored in
	// it and the producer/consumer contract between api-server and ssh-proxy.
	LOCKED_USERS_BUCKET = "locked-users"

	// PASSWORD_LOCKOUT_BUCKET holds per-username password brute-force
	// tracking state, keyed by username. See PasswordLockoutState
	// (passwordlockout.go) for the value type stored in it. Unlike
	// LOCKED_USERS_BUCKET, identity is the sole producer and consumer: it
	// reads and writes this bucket directly inside AuthUserPassword, so the
	// lockout applies consistently no matter which caller (ssh-proxy,
	// api-server, or any other gRPC client) invoked it.
	PASSWORD_LOCKOUT_BUCKET = "password-lockouts"

	// PASSWORD_RESET_TOKEN_BUCKET holds single-use password-reset tokens,
	// keyed by hex(sha256(token)), value = username. Identity is the sole
	// producer and consumer. TTL bounds how long an issued reset link stays
	// valid; ConfirmPasswordReset deletes a token immediately on successful
	// use, but the bucket-wide TTL also cleans up abandoned tokens.
	PASSWORD_RESET_TOKEN_BUCKET = "password-reset-tokens"

	// PASSWORD_RESET_COOLDOWN_BUCKET holds a per-username marker created by
	// RequestPasswordReset to throttle repeat requests. Keyed by username,
	// empty value. A separate bucket from PASSWORD_RESET_TOKEN_BUCKET
	// because JetStream KV TTL is bucket-wide and the two need very
	// different lifetimes (short cooldown vs. longer token validity).
	PASSWORD_RESET_COOLDOWN_BUCKET = "password-reset-cooldown"
)
