// Copyright 2026 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package authz

// ScopeCatalogEntry describes one selectable PAT scope for UI rendering.
type ScopeCatalogEntry struct {
	// Scope is the literal scope string to store, e.g. "workspace:connect:webshell"
	// or "workspace:connect:*".
	Scope       string `json:"scope"`
	Label       string `json:"label"`
	Description string `json:"description,omitempty"`
	// Wildcard is true when Scope ends in ":*" and covers every sibling
	// entry in the same action group.
	Wildcard bool `json:"wildcard"`
	// Constraints lists the constraint suffixes this scope accepts (today,
	// only "self"). A UI may offer these as a toggle that appends
	// ":<constraint>" to Scope rather than exposing the raw syntax.
	Constraints []string `json:"constraints,omitempty"`
}

// ScopeCatalogAction groups the scope entries for one "domain:action" prefix,
// e.g. every workspace:connect:* qualifier.
type ScopeCatalogAction struct {
	Action  string              `json:"action"`
	Label   string              `json:"label"`
	Entries []ScopeCatalogEntry `json:"entries"`
}

// ScopeCatalogDomain groups all actions under one scope domain (workspace,
// user, token, ...). Wildcard, when non-nil, is the "domain:*" entry that
// grants every action in the domain at once.
type ScopeCatalogDomain struct {
	Domain      string               `json:"domain"`
	Label       string               `json:"label"`
	Description string               `json:"description,omitempty"`
	Wildcard    *ScopeCatalogEntry   `json:"wildcard,omitempty"`
	Actions     []ScopeCatalogAction `json:"actions"`
}

// ScopeCatalog is the full set of selectable PAT scopes, grouped for
// rendering as a checkbox tree. Global is the bare "*" scope — it grants
// every action across every domain and is surfaced separately since it
// doesn't belong to any one domain.
type ScopeCatalog struct {
	Global  *ScopeCatalogEntry   `json:"global"`
	Domains []ScopeCatalogDomain `json:"domains"`
}

// entrySpec/actionSpec/domainSpec are the hand-authored catalog source; unlike
// validExactScopes/validWildcardPrefixes (which are unordered sets used only
// for validation) these need a stable, human-curated order and labels, so
// they're kept separate and cross-checked against the validation registry by
// TestScopeCatalogDoc_MatchesRegistry rather than generated from it.
type entrySpec struct {
	scope       string
	label       string
	description string
}

type actionSpec struct {
	action   string
	label    string
	entries  []entrySpec
	wildcard *entrySpec
}

type domainSpec struct {
	domain      string
	label       string
	description string
	actions     []actionSpec
	wildcard    *entrySpec
}

var scopeCatalogSource = []domainSpec{
	{
		domain:      "workspace",
		label:       "Workspaces",
		description: "Create, inspect, and connect to workspaces.",
		wildcard:    &entrySpec{scope: "workspace:*", label: "All workspace actions"},
		actions: []actionSpec{
			{action: "workspace:list", label: "List", entries: []entrySpec{
				{scope: "workspace:list", label: "List", description: "List workspaces."},
			}},
			{action: "workspace:create", label: "Create", entries: []entrySpec{
				{scope: "workspace:create", label: "Create", description: "Create a workspace record."},
			}},
			{action: "workspace:read", label: "Read", entries: []entrySpec{
				{scope: "workspace:read", label: "Read", description: "Read a workspace's details."},
			}},
			{action: "workspace:delete", label: "Delete", entries: []entrySpec{
				{scope: "workspace:delete", label: "Delete", description: "Delete a workspace."},
			}},
			{action: "workspace:files", label: "Files", entries: []entrySpec{
				{scope: "workspace:files", label: "Files", description: "Browse and edit files inside a workspace."},
			}},
			{action: "workspace:connect", label: "Connect", wildcard: &entrySpec{scope: "workspace:connect:*", label: "Any connect type"}, entries: []entrySpec{
				{scope: "workspace:connect:webshell", label: "Web shell", description: "Open an interactive terminal session in the browser."},
				{scope: "workspace:connect:webfiles", label: "Web files", description: "Open the browser-based file manager."},
				{scope: "workspace:connect:portforward", label: "Port forward", description: "Proxy HTTP traffic to a port inside the workspace."},
			}},
			{action: "workspace:app", label: "Apps", wildcard: &entrySpec{scope: "workspace:app:*", label: "Any app operation"}, entries: []entrySpec{
				{scope: "workspace:app:read", label: "Read", description: "List installed apps and their status."},
				{scope: "workspace:app:install", label: "Install", description: "Install an app into the workspace."},
				{scope: "workspace:app:start", label: "Start", description: "Start an installed app."},
				{scope: "workspace:app:stop", label: "Stop", description: "Stop a running app."},
			}},
		},
	},
	{
		domain:      "session",
		label:       "Sessions",
		description: "Shell sessions run inside workspaces.",
		wildcard:    &entrySpec{scope: "session:*", label: "All session actions"},
		actions: []actionSpec{
			{action: "session:list", label: "List", entries: []entrySpec{
				{scope: "session:list", label: "List", description: "List a user's shell sessions."},
			}},
		},
	},
	{
		domain:      "user",
		label:       "Users",
		description: "Read and manage user accounts.",
		wildcard:    &entrySpec{scope: "user:*", label: "All user actions"},
		actions: []actionSpec{
			{action: "user:list", label: "List", entries: []entrySpec{
				{scope: "user:list", label: "List", description: "List user accounts."},
			}},
			{action: "user:read", label: "Read", wildcard: &entrySpec{scope: "user:read:*", label: "Any data type"}, entries: []entrySpec{
				{scope: "user:read:profile", label: "Profile", description: "Read a user's profile."},
				{scope: "user:read:blueprints", label: "Blueprints", description: "Read a user's assigned workspace blueprints."},
				{scope: "user:read:roles", label: "Roles", description: "Read a user's assigned roles."},
				{scope: "user:read:keys", label: "Keys", description: "Read a user's SSH/API keys."},
				{scope: "user:read:repos", label: "Repos", description: "Browse a user's identity-provider repository owners and repos."},
			}},
			{action: "user:read:credentials", label: "Credentials (read)", wildcard: &entrySpec{scope: "user:read:credentials:*", label: "Any credential type"}, entries: []entrySpec{
				{scope: "user:read:credentials:kubernetes", label: "Kubernetes", description: "Read a user's stored Kubernetes service-account credentials."},
				{scope: "user:read:credentials:git", label: "Git", description: "Read a user's stored Git credentials."},
				{scope: "user:read:credentials:registry", label: "Registry", description: "Read a user's stored container registry credentials."},
			}},
			{action: "user:write", label: "Write", wildcard: &entrySpec{scope: "user:write:*", label: "Any data type", description: "Any data type (including sensitive ones)"}, entries: []entrySpec{
				{scope: "user:write:profile", label: "Profile", description: "Update a user's profile."},
				{scope: "user:write:roles", label: "Roles", description: "Grant or revoke a user's roles."},
				{scope: "user:write:keys", label: "Keys", description: "Add or remove a user's SSH/API keys."},
				{scope: "user:write:password", label: "Password", description: "Change a user's password."},
				{scope: "user:write:sudo", label: "Sudo", description: "Grant or revoke sudo access."},
				{scope: "user:write:locked", label: "Locked", description: "Lock or unlock a user account."},
				{scope: "user:write:org", label: "Organization", description: "Change a user's organization membership."},
				{scope: "user:write:posix", label: "POSIX", description: "Update a user's POSIX (uid/gid/shell) attributes."},
			}},
			{action: "user:write:credentials", label: "Credentials (write)", wildcard: &entrySpec{scope: "user:write:credentials:*", label: "Any credential type"}, entries: []entrySpec{
				{scope: "user:write:credentials:kubernetes", label: "Kubernetes", description: "Add or remove a user's stored Kubernetes service-account credentials."},
				{scope: "user:write:credentials:git", label: "Git", description: "Add or remove a user's stored Git credentials."},
				{scope: "user:write:credentials:registry", label: "Registry", description: "Add or remove a user's stored container registry credentials."},
			}},
		},
	},
	{
		domain:      "token",
		label:       "Access tokens",
		description: "Manage a user's personal access tokens.",
		wildcard:    &entrySpec{scope: "token:*", label: "All token actions"},
		actions: []actionSpec{
			{action: "token:read", label: "Read", entries: []entrySpec{
				{scope: "token:read", label: "Read", description: "List a user's access tokens."},
			}},
			{action: "token:create", label: "Create", entries: []entrySpec{
				{scope: "token:create", label: "Create", description: "Issue a new access token."},
			}},
			{action: "token:write", label: "Write", entries: []entrySpec{
				{scope: "token:write", label: "Write", description: "Update an access token (e.g. its scopes or active state)."},
			}},
			{action: "token:delete", label: "Delete", entries: []entrySpec{
				{scope: "token:delete", label: "Delete", description: "Revoke or delete an access token."},
			}},
		},
	},
	{
		domain:      "role",
		label:       "Roles",
		description: "Manage roles that bundle authz permissions and blueprint access.",
		wildcard:    &entrySpec{scope: "role:*", label: "All role actions"},
		actions: []actionSpec{
			{action: "role:list", label: "List", entries: []entrySpec{
				{scope: "role:list", label: "List", description: "List roles."},
			}},
			{action: "role:create", label: "Create", entries: []entrySpec{
				{scope: "role:create", label: "Create", description: "Create a role."},
			}},
			{action: "role:delete", label: "Delete", entries: []entrySpec{
				{scope: "role:delete", label: "Delete", description: "Delete a role."},
			}},
			{action: "role:update", label: "Update", entries: []entrySpec{
				{scope: "role:update", label: "Update", description: "Update a role's permissions or blueprint access."},
			}},
		},
	},
	{
		domain:      "org",
		label:       "Organizations",
		description: "Manage organizations.",
		wildcard:    &entrySpec{scope: "org:*", label: "All organization actions"},
		actions: []actionSpec{
			{action: "org:list", label: "List", entries: []entrySpec{
				{scope: "org:list", label: "List", description: "List organizations."},
			}},
			{action: "org:create", label: "Create", entries: []entrySpec{
				{scope: "org:create", label: "Create", description: "Create an organization."},
			}},
			{action: "org:delete", label: "Delete", entries: []entrySpec{
				{scope: "org:delete", label: "Delete", description: "Delete an organization."},
			}},
			{action: "org:update", label: "Update", entries: []entrySpec{
				{scope: "org:update", label: "Update", description: "Update an organization."},
			}},
		},
	},
	{
		domain:      "blueprints",
		label:       "Blueprints",
		description: "Workspace blueprint definitions.",
		actions: []actionSpec{
			{action: "blueprints:read", label: "Read", entries: []entrySpec{
				{scope: "blueprints:read", label: "Read", description: "Read blueprint definitions."},
			}},
		},
	},
}

// buildEntry converts spec into a ScopeCatalogEntry, deriving Wildcard and
// Constraints from the same rules ValidateScope enforces so the catalog can't
// silently drift from what's actually accepted.
func buildEntry(spec entrySpec) ScopeCatalogEntry {
	prefix, wildcard := trimWildcardSuffix(spec.scope)
	entry := ScopeCatalogEntry{
		Scope:       spec.scope,
		Label:       spec.label,
		Description: spec.description,
		Wildcard:    wildcard,
	}
	if scopeConstrainable(prefix) {
		entry.Constraints = []string{string(ScopeConstraintSelf)}
	}
	return entry
}

func trimWildcardSuffix(scope string) (prefix string, wildcard bool) {
	if p, ok := cutSuffixColonStar(scope); ok {
		return p, true
	}
	return scope, false
}

func cutSuffixColonStar(s string) (string, bool) {
	const suffix = ":*"
	if len(s) > len(suffix) && s[len(s)-len(suffix):] == suffix {
		return s[:len(s)-len(suffix)], true
	}
	return s, false
}

// ScopeCatalogDoc returns the full, ordered catalog of selectable PAT scopes
// for UI rendering and editing.
func ScopeCatalogDoc() ScopeCatalog {
	catalog := ScopeCatalog{
		Global: &ScopeCatalogEntry{
			Scope: scopeWildcard,
			Label: "Everything",
		},
	}
	for _, d := range scopeCatalogSource {
		domain := ScopeCatalogDomain{
			Domain:      d.domain,
			Label:       d.label,
			Description: d.description,
		}
		if d.wildcard != nil {
			e := buildEntry(*d.wildcard)
			domain.Wildcard = &e
		}
		for _, a := range d.actions {
			action := ScopeCatalogAction{Action: a.action, Label: a.label}
			for _, es := range a.entries {
				action.Entries = append(action.Entries, buildEntry(es))
			}
			if a.wildcard != nil {
				action.Entries = append(action.Entries, buildEntry(*a.wildcard))
			}
			domain.Actions = append(domain.Actions, action)
		}
		catalog.Domains = append(catalog.Domains, domain)
	}
	return catalog
}
