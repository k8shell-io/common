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

	Username string   `json:"username"`
	Roles    []string `json:"roles"`
	Org      string   `json:"org"`

	// PATPreview is the display prefix of the Personal Access Token
	// exchanged for the caller's JWT, when the request came in that way.
	PATPreview string `json:"patPreview,omitempty"`

	ResourceType       string            `json:"resourceType"`
	ResourceID         string            `json:"resourceId"`
	ResourceOwner      string            `json:"resourceOwner,omitempty"`
	ResourceAttributes map[string]string `json:"resourceAttributes,omitempty"`

	// Context carries ambient attributes not present in the JWT or resource —
	// the same map passed to Evaluate/BatchEvaluate as EvaluateRequest's
	// context (auth surface, credential type, connect type, ...). Scope
	// (above) is derived from a subset of these keys for display; Context
	// itself is returned in full for investigative completeness.
	Context map[string]string `json:"context,omitempty"`

	Allowed     bool              `json:"allowed"`
	Obligations map[string]string `json:"obligations,omitempty"`

	// Error is populated when policy evaluation itself failed (compile/eval
	// error, no result returned), rather than reflecting a normal deny.
	Error string `json:"error,omitempty"`

	// DurationUS is how long the OPA evaluation itself took, in microseconds.
	DurationUS int64 `json:"durationUs"`

	// DupCount is how many identical decisions were folded into this row
	// within its dedup window, including the one that created it.
	DupCount int32 `json:"dupCount"`

	// LastOccurredAt is the most recent occurrence folded into this row.
	// OccurredAt remains the first occurrence.
	LastOccurredAt time.Time `json:"lastOccurredAt"`
}
