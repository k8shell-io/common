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
)
