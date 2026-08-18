// Copyright 2026 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import "time"

// OnboardAction is the decision an OnboardRule resolves to.
type OnboardAction string

const (
	OnboardActionAllow    OnboardAction = "allow"
	OnboardActionReject   OnboardAction = "reject"
	OnboardActionWaitlist OnboardAction = "waitlist"

	// OnboardActionNotDefined means no rule resolved to a concrete decision
	// for the user, e.g. an OnboardUserRule CEL template did not set one.
	OnboardActionNotDefined OnboardAction = "not-defined"
)

// OnboardStatus tracks the outcome of an actual onboarding attempt against
// an OnboardRule, separate from Action (the configured policy/decision).
type OnboardStatus string

const (
	// OnboardStatusNone is the default: no onboarding attempt has resolved
	// against this row yet (e.g. a standing pattern rule, or a proactive
	// admin-authored one-off nobody has attempted to onboard through yet).
	OnboardStatusNone OnboardStatus = "none"
	// OnboardStatusPending means a user hit this row as a "waitlist"
	// decision and no admin decision has been made yet.
	OnboardStatusPending OnboardStatus = "pending"
	// OnboardStatusApproved means an admin approved a previously-waitlisted
	// request (Action is now "allow"), but the user has not yet actually
	// onboarded — they haven't logged in / completed a web flow since being
	// approved, so no identity.users row exists for them yet. Transitions to
	// OnboardStatusOnboarded the moment they do.
	OnboardStatusApproved OnboardStatus = "approved"
	// OnboardStatusRejected means a user was rejected, either directly by
	// an OnboardActionReject rule at attempt time, or by an admin
	// rejecting a previously-waitlisted request.
	OnboardStatusRejected OnboardStatus = "rejected"
	// OnboardStatusOnboarded means the user was actually created in
	// identity.users (and exists in Org's user list).
	OnboardStatusOnboarded OnboardStatus = "onboarded"
)

// OnboardRule controls whether a new user may onboard, and what they get
// when they do. A row is either a pattern rule (UsernamePattern contains
// '*'), an admin-authored standing policy, or a concrete decision
// (UsernamePattern has no '*'): a one-off admin-authored allow/reject for a
// specific person, or a row the system inserted the first time that exact
// user hit a "waitlist" pattern rule. There is no separate waitlist table —
// approving a pending row is simply flipping its Action from "waitlist" to
// "allow".
type OnboardRule struct {
	ID              int32  `json:"id"`
	IDP             string `json:"idp"`             // provider name, "local", or "*" (any)
	UsernamePattern string `json:"usernamePattern"` // exact username, or a pattern containing '*'

	// Org is the destination organization a matching user is placed into —
	// not a scope filter — replacing whatever the identity provider itself
	// reported. Always set; there is no "global" org for this table.
	Org string `json:"org"`

	Action   OnboardAction `json:"action"`
	Status   OnboardStatus `json:"status"`   // outcome of an actual onboarding attempt; see OnboardStatus*
	Priority int32         `json:"priority"` // lower wins among matching rows of the same specificity

	// Roles/Sudo are the attributes applied to the user when this row
	// resolves to OnboardActionAllow (replacing what OPA's onboarding
	// obligations used to grant). Roles must be valid within Org
	// (org-scoped-or-global).
	Roles []string `json:"roles,omitempty"`
	Sudo  bool     `json:"sudo,omitempty"`

	// Fullname/Email are display metadata for system-inserted (waitlist-hit)
	// rows, so an admin can see who's asking without a fresh provider
	// round-trip.
	Fullname string `json:"fullname,omitempty"`
	Email    string `json:"email,omitempty"`

	Note string `json:"note,omitempty"` // admin comment / rejection reason

	RequestedAt *time.Time `json:"requestedAt,omitempty"` // set only for system-inserted rows
	DecidedAt   *time.Time `json:"decidedAt,omitempty"`   // set when Action moves out of "waitlist"
	DecidedBy   string     `json:"decidedBy,omitempty"`   // admin username who approved/rejected

	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// OnboardUserRule is the onboarding decision an identity provider computes
// for a single user, typically by evaluating a CEL template against the
// identity data it holds for that user (see models.User, built the same
// way). Unlike OnboardRule, it is not a persisted policy row: it is the
// provider's proposed disposition for this one user, returned inline from a
// flow such as CompleteUserWebFlow.
type OnboardUserRule struct {
	Username     string        `json:"username"`
	Fullname     string        `json:"fullname,omitempty"`
	Email        string        `json:"email,omitempty"`
	Organization string        `json:"organization,omitempty"`
	UID          uint32        `json:"uid,omitempty"`
	GID          uint32        `json:"gid,omitempty"`
	Sudo         *bool         `json:"sudo,omitempty"`
	Action       OnboardAction `json:"action"`
	Roles        []string      `json:"roles,omitempty"`
}

// UserResult is an identity provider's onboarding decision for a user,
// returned by FindUser (re-evaluated for an already-onboarded user) and by
// CompleteUserWebFlow (evaluated for a user who just completed the
// provider's web onboarding flow).
type UserResult struct {
	OnboardRule OnboardUserRule `json:"onboardRule"`
	// ManageRepos is a link the client should present to the user for
	// managing their repository access on the provider, e.g. prompting a
	// GitHub user to install the GitHub App now that they've authorized it.
	// Empty when the provider has no such link.
	ManageRepos string `json:"manageRepos,omitempty"`
	// GitAddress is the address the identity provider has defined for git
	// operations, e.g. "https://github.com".
	GitAddress string `json:"gitAddress"`
}
