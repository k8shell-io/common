package models

// UserUpdateRequest is the HTTP request body for PATCH /users/{username}.
// Only non-nil pointer fields and non-empty slices are applied (PATCH semantics).
// Note: proto counterpart is identityv1.UpdateUserRequest (different wire format, no json tags).
type UserUpdateRequest struct {
	Fullname   *string  `json:"fullname,omitempty"`
	Shell      *string  `json:"shell,omitempty"`
	Org        *string  `json:"org,omitempty"`
	Roles      []Role   `json:"roles,omitempty"`
	Sudo       *bool    `json:"sudo,omitempty"`
	Blueprints []string `json:"blueprints,omitempty"`
	Locked     *bool    `json:"locked,omitempty"`
	Keys       []string `json:"keys,omitempty"`
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

// UserKeysRequest is the HTTP request body for adding or removing SSH public keys on a user.
// Note: proto counterpart is identityv1.UserAuthKeysRequest.
type UserKeysRequest struct {
	Keys []string `json:"keys"`
}
