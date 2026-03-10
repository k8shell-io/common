package authz

import "time"

type TokenType string

const (
	TokenTypeAPIAccess TokenType = "api"
	// future: "ssh", "web", etc., if you want distinct token flavors
)

type TokenSpec struct {
	// Owner of the token (who it belongs to)
	Username string    `yaml:"username" json:"username"`
	Type     TokenType `yaml:"type"     json:"type"`

	// When Mode == "full", the token represents the full set of permissions
	// the user has according to policy evaluation.
	//
	// When Mode == "restricted", the token is a *subset* of user permissions
	// chosen by the admin/user, enforced by extra narrowing rules below.
	Mode TokenMode `yaml:"mode" json:"mode"`

	// Optional metadata
	Name        string     `yaml:"name"        json:"name"`
	Description string     `yaml:"description" json:"description"`
	ExpiresAt   *time.Time `yaml:"expiresAt,omitempty" json:"expiresAt,omitempty"`

	// Restrictions (only meaningful when Mode == restricted; safe to apply even in full mode)
	Restrictions TokenRestrictions `yaml:"restrictions,omitempty" json:"restrictions,omitempty"`
}

type TokenMode string

const (
	TokenModeFull       TokenMode = "full"
	TokenModeRestricted TokenMode = "restricted"
)

type TokenRestrictions struct {
	// Narrow what resources this token can be used on (subset of what policy allows).
	// These selectors are intersected with the policy-selected resources.
	Workspaces []string `yaml:"workspaces,omitempty" json:"workspaces,omitempty"`
	Blueprints []string `yaml:"blueprints,omitempty" json:"blueprints,omitempty"`
	Owner      string   `yaml:"owner,omitempty" json:"owner,omitempty"` // e.g. "self"

	// Narrow what actions can be performed with this token (subset of what policy allows).
	Actions []Action `yaml:"actions,omitempty" json:"actions,omitempty"`

	// Narrow by grant selection (optional).
	// If specified, only these grants (by name) are considered during evaluation.
	GrantNames []string `yaml:"grantNames,omitempty" json:"grantNames,omitempty"`
}
