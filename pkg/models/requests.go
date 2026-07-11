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
