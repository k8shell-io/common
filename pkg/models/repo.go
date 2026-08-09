package models

// RepoOwner is an entity that can own repositories on a user's identity
// provider: their own personal account, or an organization/group they
// belong to. Its Login is passed as the owner of a subsequent Repo listing.
type RepoOwner struct {
	Login string `json:"login"`
	// Kind is "user" for the caller's personal account or "organization" for a group.
	Kind        string `json:"kind"`
	Description string `json:"description,omitempty"`
	AvatarURL   string `json:"avatarUrl,omitempty"`
}

// Repo is a repository owned by a RepoOwner, as seen on a user's identity
// provider.
type Repo struct {
	Name string `json:"name"`
	// FullName is "<owner_login>/<name>".
	FullName      string `json:"fullName"`
	Description   string `json:"description,omitempty"`
	Private       bool   `json:"private,omitempty"`
	DefaultBranch string `json:"defaultBranch,omitempty"`
	HTMLURL       string `json:"htmlUrl,omitempty"`
}
