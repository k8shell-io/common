package models

// UserCreateRequest is the HTTP request body for POST /users, which creates a
// new local user record with no backing identity provider (unlike onboarding).
// Note: proto counterpart is identityv1.CreateUserRequest (different wire format, no json tags).
type UserCreateRequest struct {
	Username   string   `json:"username"`
	Org        string   `json:"org"`
	Fullname   string   `json:"fullname,omitempty"`
	Email      string   `json:"email,omitempty"`
	Password   string   `json:"password,omitempty"`
	Roles      []Role   `json:"roles,omitempty"`
	Blueprints []string `json:"blueprints,omitempty"`
	Shell      string   `json:"shell,omitempty"`
	Sudo       bool     `json:"sudo,omitempty"`
	Locked     bool     `json:"locked,omitempty"`
	UID        uint32   `json:"uid,omitempty"`
	GID        uint32   `json:"gid,omitempty"`
}

// UserUpdateRequest is the HTTP request body for PATCH /users/{username}.
// Only non-nil pointer fields and non-empty slices are applied (PATCH semantics).
// Note: proto counterpart is identityv1.UpdateUserRequest (different wire format, no json tags).
type UserUpdateRequest struct {
	Fullname   *string  `json:"fullname,omitempty"`
	Shell      *string  `json:"shell,omitempty"`
	Email      *string  `json:"email,omitempty"`
	Org        *string  `json:"org,omitempty"`
	Roles      []Role   `json:"roles,omitempty"`
	Sudo       *bool    `json:"sudo,omitempty"`
	Blueprints []string `json:"blueprints,omitempty"`
	Locked     *bool    `json:"locked,omitempty"`
	UID        *uint32  `json:"uid,omitempty"`
	GID        *uint32  `json:"gid,omitempty"`
}

// UserRolesRequest is the HTTP request body for adding or removing roles on a user.
// Note: proto counterpart is identityv1.UserRolesRequest.
type UserRolesRequest struct {
	Roles []Role `json:"roles"`
}

// UserBlueprintsRequest is the HTTP request body for adding or removing blueprints on a user.
// Note: proto counterpart is identityv1.UserBlueprintsRequest.
type UserBlueprintsRequest struct {
	Blueprints []string `json:"blueprints"`
}

// UserKeysRequest is the HTTP request body for adding SSH public keys on a user.
// Note: proto counterpart is identityv1.UserAuthKeysRequest.
type UserKeysRequest struct {
	Keys []string `json:"keys"`
}

// UserPasswordRequest is the HTTP request body for setting or clearing a user's
// local password. Password is a pointer so an explicit empty string (clear the
// password) can be distinguished from an absent field.
// Note: proto counterpart is identityv1.SetUserPasswordRequest.
type UserPasswordRequest struct {
	Password        *string `json:"password"`
	CurrentPassword *string `json:"current_password,omitempty"`
}

// UserLoginRequest is the HTTP request body for POST /auth/login, which
// authenticates a user against the identity service's "local" password provider.
type UserLoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Capability describes whether a single policy-governed action is permitted for
// the authenticated user, as returned by GET /me/capabilities.
type Capability struct {
	Action      string            `json:"action"`
	Allowed     bool              `json:"allowed"`
	Reason      string            `json:"reason"`
	Obligations map[string]string `json:"obligations,omitempty"`
}

// UserProfile is the HTTP response body for GET /me/profile and
// GET /users/{username}/profile — the frontend's canonical view of a user
// account. Fields are copied explicitly rather than reusing models.User
// directly, so this contract only changes when a profile field is
// deliberately added or removed here, independent of what models.User
// carries for other (non-HTTP-facing) consumers.
type UserProfile struct {
	Username     string   `json:"username"`
	Organization string   `json:"organization"`
	Fullname     string   `json:"fullname"`
	Email        string   `json:"email"`
	UID          uint32   `json:"uid"`
	GID          uint32   `json:"gid"`
	Shell        string   `json:"shell"`
	Sudo         bool     `json:"sudo"`
	Source       string   `json:"source"`
	Roles        []Role   `json:"roles"`
	Blueprints   []string `json:"blueprints"`

	// AccountLocked is the administrative lock an admin sets explicitly; it
	// blocks all auth surfaces (SSH, PAT, session, password).
	AccountLocked bool `json:"account_locked"`

	// PasswordLocked reflects api-server's local, transient brute-force
	// lockout for password-based auth specifically — other auth surfaces
	// (e.g. SSH publickey) keep working while this is true.
	PasswordLocked      bool   `json:"password_locked"`
	PasswordLockedUntil string `json:"password_locked_until,omitempty"`
}

// UserKubernetesCredentialRequest is the HTTP request body for POST
// /users/{username}/credentials/kubernetes, which provisions a Kubernetes
// service-account credential for a user.
// Note: proto counterpart is identityv1.AddKubernetesUserCredentialRequest.
type UserKubernetesCredentialRequest struct {
	Scope   string `json:"scope"`
	Subject string `json:"subject"`
}

// UserGitCredentialRequest is the HTTP request body for POST
// /users/{username}/credentials/git, which stores a Git credential for a user.
// Note: proto counterpart is identityv1.AddGitUserCredentialRequest.
type UserGitCredentialRequest struct {
	Scope   string `json:"scope"`
	Subject string `json:"subject"`
	Secret  string `json:"secret"`
}

// UserRegistryCredentialRequest is the HTTP request body for POST
// /users/{username}/credentials/registry, which stores a container registry
// credential for a user.
// Note: proto counterpart is identityv1.AddRegistryUserCredentialRequest.
type UserRegistryCredentialRequest struct {
	Scope   string `json:"scope"`
	Subject string `json:"subject"`
	Secret  string `json:"secret"`
}

// UserCredentialUpdateRequest is the HTTP request body for PATCH
// /users/{username}/credentials/{id}, which partially updates a credential.
// Only non-nil pointer fields are applied (PATCH semantics).
// Note: proto counterpart is identityv1.UpdateUserCredentialRequest.
type UserCredentialUpdateRequest struct {
	Scope   *string `json:"scope,omitempty"`
	Subject *string `json:"subject,omitempty"`
	Secret  *string `json:"secret,omitempty"`
	Active  *bool   `json:"active,omitempty"`
}

// AccessTokenCreateRequest is the HTTP request body for POST
// /users/{username}/tokens (and /me/tokens), which issues a new Personal
// Access Token for a user. Name and Scopes are required. Renew, when true,
// rotates an existing active token with the same name in place instead of
// creating a new one. Active, when set to false, creates the token disabled.
// Note: proto counterpart is identityv1.CreateAccessTokenRequest.
type AccessTokenCreateRequest struct {
	Name      string   `json:"name"`
	Scopes    []string `json:"scopes"`
	ExpiresAt *string  `json:"expires_at,omitempty"` // RFC3339, omit for non-expiring
	Renew     bool     `json:"renew,omitempty"`
	Active    *bool    `json:"active,omitempty"`
}

// AccessTokenCreated is the HTTP response body for POST /users/{username}/tokens
// (and /me/tokens). Token is the raw secret value; it is returned exactly once
// and cannot be retrieved again.
// Note: proto counterpart is identityv1.CreateAccessTokenResponse.
type AccessTokenCreated struct {
	ID    int64  `json:"id"`
	Token string `json:"token"`
}

// AccessTokenUpdateRequest is the HTTP request body for PATCH
// /users/{username}/tokens/{id} (and /me/tokens/{id}), which partially updates
// an access token's active state and/or scopes. Only non-nil fields are
// applied (PATCH semantics); name and expiry are immutable after creation.
// Scopes set to a non-nil, possibly-empty slice replaces the token's scopes;
// a nil Scopes leaves them unchanged.
// Note: proto counterpart is identityv1.UpdateAccessTokenRequest.
type AccessTokenUpdateRequest struct {
	Active *bool     `json:"active,omitempty"`
	Scopes *[]string `json:"scopes,omitempty"`
}
