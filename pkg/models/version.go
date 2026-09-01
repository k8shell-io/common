// Copyright 2026 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package models

// ServiceVersionInfo is a backend service's build metadata, as reported by
// its common.v1 GetVersionInfo RPC and surfaced by the api-server's
// GET /api/v1/version endpoint.
type ServiceVersionInfo struct {
	// Version is the service's released semantic version, or a caller-chosen
	// fallback (e.g. "0.0.0") when the service did not report one.
	Version string `json:"version"`
	// CommitID is the git commit the service binary was built from.
	CommitID string `json:"commit_id,omitempty"`
	// Description is a short human-readable summary of what the service does.
	Description string `json:"description,omitempty"`
	// Error is set when the GetVersionInfo call itself failed; Version then
	// carries the fallback and CommitID/Description are empty.
	Error string `json:"error,omitempty"`
}
