// Copyright 2026 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import "time"

// AuditRecord is a single recorded policy-evaluation decision, as returned
// by authz's QueryAudit RPC. Repeated calls that resolved to the identical
// decision within a short window are folded server-side into one
// AuditRecord rather than returned as separate entries — see DupCount/
// LastOccurredAt.
type AuditRecord struct {
	ID         int64     `json:"id"`
	ReqID      string    `json:"reqId"`
	OccurredAt time.Time `json:"occurredAt"`

	Package string `json:"package"`
	Action  string `json:"action"`

	// Scope is the compound "domain:action[:qualifier]" display form of
	// Action — e.g. "user:auth:ssh" — the same convention
	// authz.CapabilityCheck.Action uses. Equal to Action for actions with no
	// qualifier. Display/audit convenience only; never used for policy
	// routing or PAT scope matching, both of which stay keyed on Action.
	Scope string `json:"scope,omitempty"`

	Subject AuditSubject `json:"subject"`

	// PATPreview is the display prefix of the Personal Access Token
	// exchanged for the caller's JWT, when the request came in that way.
	PATPreview string `json:"patPreview,omitempty"`

	// Resource mirrors the authz Resource: the owner is Attributes["owner"].
	Resource AuditResource `json:"resource"`

	// Context mirrors EvaluateRequest.context. Scope (above) is derived from
	// a subset of its keys for display. Oversized values are replaced by a
	// "<truncated: N bytes, sha256:...>" marker.
	Context map[string]string `json:"context,omitempty"`

	// Result mirrors EvaluateResponse, plus Error.
	Result AuditResult `json:"result"`

	// DurationUS is how long the OPA evaluation itself took, in microseconds.
	DurationUS int64 `json:"durationUs"`

	// DupCount is how many identical decisions were folded into this row
	// within its dedup window, including the one that created it.
	DupCount int32 `json:"dupCount"`

	// LastOccurredAt is the most recent occurrence folded into this row.
	// OccurredAt remains the first occurrence.
	LastOccurredAt time.Time `json:"lastOccurredAt"`
}

// AuditSubject is the caller of an audited evaluation, from the JWT claims.
type AuditSubject struct {
	Username string   `json:"username"`
	Roles    []string `json:"roles"`
	Org      string   `json:"org"`
}

// AuditResource mirrors the authz Resource of the evaluated request.
type AuditResource struct {
	Type       string            `json:"type"`
	ID         string            `json:"id"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

// AuditResult mirrors the authz EvaluateResponse, plus Error.
type AuditResult struct {
	Allowed     bool              `json:"allowed"`
	Reason      string            `json:"reason,omitempty"`
	Obligations map[string]string `json:"obligations,omitempty"`

	// Error is populated when policy evaluation itself failed (compile/eval
	// error, no result returned), rather than reflecting a normal deny.
	Error string `json:"error,omitempty"`
}
