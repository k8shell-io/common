// Copyright 2026 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import "time"

// AnnouncementTranslation carries an Announcement's body in a single
// language. Every Announcement has at least one.
type AnnouncementTranslation struct {
	Lang string `json:"lang"` // BCP 47 language tag, e.g. "en", "en-US"
	Body string `json:"body"` // markdown content
}

// Announcement is a platform message rendered as markdown by clients. It is
// either global (Orgs empty) or scoped to one or more organizations/roles,
// and optionally bounded to a validity period (StartsAt/EndsAt).
type Announcement struct {
	ID int32 `json:"id"`

	// Name is an admin-facing label only — not translated, not shown to end
	// users — so admins can tell announcements apart in a listing.
	Name string `json:"name"`

	// Translations carries the announcement's body in one or more
	// languages; every announcement has at least one.
	Translations []AnnouncementTranslation `json:"translations"`

	CreatedBy string `json:"createdBy"` // username of the author

	// Orgs names the organizations this announcement applies to; empty
	// means every organization (global).
	Orgs []string `json:"orgs,omitempty"`

	// Roles further scopes the announcement to users holding at least one
	// of these roles within the applicable org(s); empty means every role.
	Roles []string `json:"roles,omitempty"`

	// Active toggles whether this announcement is shown in the user-facing
	// listings without deleting it; it always remains visible via the
	// admin-facing Get/List calls.
	Active bool `json:"active"`

	// StartsAt/EndsAt bound the announcement's optional validity period. A
	// nil bound is open on that side. An announcement outside its period is
	// excluded from an unread listing even when a user hasn't read it yet,
	// but remains retrievable through a full listing.
	StartsAt *time.Time `json:"startsAt,omitempty"`
	EndsAt   *time.Time `json:"endsAt,omitempty"`

	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`

	// ReadCount is computed — the number of distinct users who have read
	// this announcement. Populated by the admin-facing Get/List calls, zero
	// elsewhere.
	ReadCount int32 `json:"readCount,omitempty"`

	// IsRead/ReadAt are computed per requesting user — populated only by a
	// user-facing listing that reports read status, empty otherwise.
	IsRead bool       `json:"isRead,omitempty"`
	ReadAt *time.Time `json:"readAt,omitempty"`
}
