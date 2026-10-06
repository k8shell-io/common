// Copyright 2026 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package nats

import "github.com/k8shell-io/common/pkg/authz"

// RecordingOverride is the JSON value stored in RECORDING_OVERRIDES_BUCKET for
// a workspace name. It replaces the "record" obligation the policy engine
// returns for session:record, for every session to that workspace.
//
// api-server is the sole producer: it writes and deletes entries through its
// /workspaces/{name}/recording-override endpoints, guarded by
// session:recording:override.
//
// api-server (webshell) and ssh-proxy (SSH sessions) are consumers: each
// looks up the workspace's entry when a session starts, after evaluating
// session:record, and passes both to ResolveRecordObligation. A session
// already running keeps the recording it started with.
type RecordingOverride struct {
	// Record is the replacement "record" obligation value: a comma-separated
	// list of authz.ObligationRecord* tokens, or "none" to disable recording.
	// Producers validate it with authz.ValidateRecordObligation.
	Record string `json:"record"`

	// SetBy is the username that set the override, for auditing.
	SetBy string `json:"setBy,omitempty"`

	// SetAt is the unix time (seconds) the override was set.
	SetAt int64 `json:"setAt,omitempty"`
}

// ResolveRecordObligation applies a workspace's recording override to the
// session:record policy result. policy and policyFound are what
// authz.ParseRecordObligation returned; override is nil when the workspace
// has none. An override replaces the policy result entirely, so the result
// is then always found, even for "none".
func ResolveRecordObligation(policy authz.RecordObligation, policyFound bool, override *RecordingOverride) (authz.RecordObligation, bool) {
	if override == nil {
		return policy, policyFound
	}
	return authz.ParseRecordObligation(map[string]string{authz.ObligationKeyRecord: override.Record})
}
