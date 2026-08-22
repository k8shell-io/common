package models

// UserCreateRequest is the HTTP request body for POST /users, which creates a
// new local user record with no backing identity provider (unlike onboarding).
// Note: proto counterpart is identityv1.CreateUserRequest (different wire format, no json tags).
type UserCreateRequest struct {
	Username string `json:"username"`
	Org      string `json:"org"`
	Fullname string `json:"fullname,omitempty"`
	Email    string `json:"email,omitempty"`
	Password string `json:"password,omitempty"`
	Roles    []Role `json:"roles,omitempty"`
	Shell    string `json:"shell,omitempty"`
	Sudo     bool   `json:"sudo,omitempty"`
	Locked   bool   `json:"locked,omitempty"`
	UID      uint32 `json:"uid,omitempty"`
	GID      uint32 `json:"gid,omitempty"`
}

// UserUpdateRequest is the HTTP request body for PATCH /users/{username}.
// Only non-nil pointer fields and non-empty slices are applied (PATCH semantics).
// Note: proto counterpart is identityv1.UpdateUserRequest (different wire format, no json tags) —
// PreserveWorkspaces has no proto counterpart at all; it's an api-server-only
// orchestration flag, never sent to identity.
type UserUpdateRequest struct {
	Fullname *string `json:"fullname,omitempty"`
	Shell    *string `json:"shell,omitempty"`
	Email    *string `json:"email,omitempty"`
	Org      *string `json:"org,omitempty"`
	Roles    []Role  `json:"roles,omitempty"`
	Sudo     *bool   `json:"sudo,omitempty"`
	Locked   *bool   `json:"locked,omitempty"`
	UID      *uint32 `json:"uid,omitempty"`
	GID      *uint32 `json:"gid,omitempty"`

	// PreserveWorkspaces, when true, keeps a user's workspaces intact across
	// an org change. Ignored unless Org is set and actually differs from the
	// user's current organization — the default (false) is destructive: on a
	// real org move, api-server deletes every workspace the user owns via
	// provisioner.DeleteUserWorkspaces.
	PreserveWorkspaces bool `json:"preserveWorkspaces,omitempty"`
}

// UserDeleteRequest is the optional HTTP request body for DELETE
// /users/{username}. An empty/absent body is equivalent to the zero value
// (PreserveWorkspaces: false).
// Note: no proto counterpart — PreserveWorkspaces is an api-server-only
// orchestration flag, never sent to identity.
type UserDeleteRequest struct {
	// PreserveWorkspaces, when true, skips the workspace cleanup that
	// otherwise runs unconditionally when a user is deleted (see
	// provisioner.DeleteUserWorkspaces). Default false — deleting a user
	// deletes their workspaces too, unless this is set.
	PreserveWorkspaces bool `json:"preserveWorkspaces,omitempty"`
}

// UserRolesRequest is the HTTP request body for adding or removing roles on a user.
// Note: proto counterpart is identityv1.UserRolesRequest.
type UserRolesRequest struct {
	Roles []Role `json:"roles"`
}

// RoleCreateRequest is the HTTP request body for POST /roles (global roles)
// and POST /organizations/{name}/roles (org-scoped roles) — org is always
// taken from the route, never from this body.
// Note: proto counterpart is identityv1.CreateRoleRequest.
type RoleCreateRequest struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

// RoleUpdateRequest is the HTTP request body for PATCH /roles/{name} (global
// roles) and PATCH /organizations/{org}/roles/{name} (org-scoped roles).
// Name and org are immutable — both are taken from the route, never from
// this body.
// Note: proto counterpart is identityv1.UpdateRoleRequest.
type RoleUpdateRequest struct {
	Description *string `json:"description,omitempty"`
}

// RoleBlueprintsRequest is the HTTP request body for adding or removing
// blueprints on a role (POST/DELETE /organizations/{org}/roles/{name}/blueprints).
// Note: proto counterpart is identityv1.RoleBlueprintsRequest.
type RoleBlueprintsRequest struct {
	Blueprints []string `json:"blueprints"`
}

// OrganizationCreateRequest is the HTTP request body for POST /organizations,
// which registers a new organization.
// Note: proto counterpart is identityv1.CreateOrganizationRequest.
type OrganizationCreateRequest struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

// OrganizationUpdateRequest is the HTTP request body for PATCH
// /organizations/{name}, which partially updates an organization's
// description. Name is immutable and cannot be changed through this
// endpoint — it is taken from the route, never from this body.
// Note: proto counterpart is identityv1.UpdateOrganizationRequest.
type OrganizationUpdateRequest struct {
	Description *string `json:"description,omitempty"`
}

// UserKeysRequest is the HTTP request body for adding SSH public keys on a user.
// Note: proto counterpart is identityv1.UserAuthKeysRequest.
type UserKeysRequest struct {
	Keys []string `json:"keys"`
}

// OnboardRuleCreateRequest is the HTTP request body for POST
// /organizations/{org}/onboard-rules, which registers a new onboard rule (a
// standing pattern policy, or a one-off decision for a specific username).
// Org is always taken from the route, never from this body.
// Note: proto counterpart is identityv1.CreateOnboardRuleRequest.
type OnboardRuleCreateRequest struct {
	IDP             string   `json:"idp"`
	UsernamePattern string   `json:"usernamePattern"`
	Action          string   `json:"action"`
	Priority        int32    `json:"priority,omitempty"`
	Roles           []string `json:"roles,omitempty"`
	Sudo            bool     `json:"sudo,omitempty"`
	Note            string   `json:"note,omitempty"`
}

// OnboardRuleUpdateRequest is the HTTP request body for PATCH
// /organizations/{org}/onboard-rules/{id}, which fully replaces the mutable
// fields of an onboard rule. Idp/UsernamePattern/Org are immutable — taken
// from the existing row, never from this body; delete and recreate the rule
// to change them.
// Note: proto counterpart is identityv1.UpdateOnboardRuleRequest.
type OnboardRuleUpdateRequest struct {
	Action   string   `json:"action"`
	Priority int32    `json:"priority,omitempty"`
	Roles    []string `json:"roles,omitempty"`
	Sudo     bool     `json:"sudo,omitempty"`
	Note     string   `json:"note,omitempty"`

	// Fullname/Email let an admin correct the display metadata recorded for
	// system-inserted (waitlist-hit) rows; see OnboardRule.Fullname/Email.
	Fullname string `json:"fullname,omitempty"`
	Email    string `json:"email,omitempty"`
}

// OnboardRuleRejectRequest is the optional HTTP request body for POST
// /organizations/{org}/onboard-rules/{id}/reject. DecidedBy is never taken
// from the body — it's always the authenticated caller's own username.
// Note: proto counterpart is identityv1.RejectOnboardRuleRequest, minus DecidedBy.
type OnboardRuleRejectRequest struct {
	Note string `json:"note,omitempty"`
}

// OrganizationDeleteRequest is the optional HTTP request body for DELETE
// /organizations/{name}. identity.DeleteOrganization always fails closed
// (rejects deletion while any user remains), so api-server always resolves
// the org's users first — either deleting them or, if MoveUsersToOrg is set,
// re-homing them to another org — before deleting the org itself (which
// also removes its now-unreferenced roles).
// Note: no proto counterpart — these are api-server-only orchestration
// flags.
type OrganizationDeleteRequest struct {
	// MoveUsersToOrg, when set, moves every user out of the org being
	// deleted into this org instead of deleting them — the same mechanism
	// as PATCH /users/{username}/profile's org field. Mutually exclusive
	// with plain deletion: when set, no user in the org is deleted.
	MoveUsersToOrg string `json:"moveUsersToOrg,omitempty"`

	// PreserveWorkspaces, when true, skips workspace cleanup. Its meaning
	// depends on MoveUsersToOrg:
	//   - unset: each user being deleted keeps their workspaces instead of
	//     having them deleted via provisioner.DeleteUserWorkspaces.
	//   - set: each moved user keeps their workspaces even though their new
	//     org's roles may not match those workspaces — normally an org
	//     change deletes them (see UserUpdateRequest.PreserveWorkspaces)
	//     precisely because of that mismatch; this opts back out of it.
	PreserveWorkspaces bool `json:"preserveWorkspaces,omitempty"`
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

// PasswordResetRequest is the HTTP request body for POST
// /auth/password/reset, which starts a forgot-password flow by emailing a
// single-use reset link to the account associated with Email, if one exists.
type PasswordResetRequest struct {
	Email string `json:"email"`
}

// PasswordResetConfirmRequest is the HTTP request body for POST
// /auth/password/reset/confirm, which exchanges a reset token (from the
// emailed link) for setting Password as the account's new local password.
type PasswordResetConfirmRequest struct {
	Token    string `json:"token"`
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

	// IsValid mirrors models.User.IsValid: false means the backing identity
	// provider (Source) no longer confirms this account exists, or its
	// session couldn't be freshly re-verified (e.g. an expired OAuth
	// refresh token) — distinct from AccountLocked, which is an explicit
	// admin action rather than a provider-driven state.
	IsValid bool `json:"is_valid"`

	// AccountLocked is the administrative lock an admin sets explicitly; it
	// blocks all auth surfaces (SSH, PAT, session, password).
	AccountLocked bool `json:"account_locked"`

	// PasswordLocked reflects api-server's local, transient brute-force
	// lockout for password-based auth specifically — other auth surfaces
	// (e.g. SSH publickey) keep working while this is true.
	PasswordLocked      bool   `json:"password_locked"`
	PasswordLockedUntil string `json:"password_locked_until,omitempty"`

	// ManageRepos is an optional management link to present to the user,
	// e.g. prompting a GitHub user to install the GitHub App.
	ManageRepos string `json:"manage_repos,omitempty"`
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

// EnvVarCreateRequest is the HTTP request body for POST
// /organizations/{name}/envvars, /users/{username}/envvars, and /me/envvars,
// which creates a new environment variable. Key and Value are required. Key
// is case-insensitive and normalized to upper case by identity, which also
// rejects anything but a valid POSIX environment variable name.
// Note: proto counterpart is identityv1.AddOrganizationEnvVarRequest /
// identityv1.AddUserEnvVarRequest.
type EnvVarCreateRequest struct {
	Key      string `json:"key"`
	Value    string `json:"value"`
	IsSecret bool   `json:"isSecret,omitempty"`
}

// EnvVarUpdateRequest is the HTTP request body for PATCH
// /organizations/{name}/envvars/{key} (and the /users/{username}/envvars/{key}
// and /me/envvars/{key} equivalents), which partially updates an environment
// variable's value and/or is_secret flag. Only non-nil fields are applied
// (PATCH semantics); the key is immutable.
// Note: proto counterpart is identityv1.UpdateOrganizationEnvVarRequest /
// identityv1.UpdateUserEnvVarRequest.
type EnvVarUpdateRequest struct {
	Value    *string `json:"value,omitempty"`
	IsSecret *bool   `json:"isSecret,omitempty"`
}
