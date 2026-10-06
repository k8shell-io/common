// Copyright 2026 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package models

// RecordingOverrideRequest is the body of
// PUT /workspaces/{name}/recording-override. Record lists the recording types
// to apply to every new session to the workspace, replacing what the
// session:record policy would decide; ["none"] disables recording.
type RecordingOverrideRequest struct {
	Record []string `json:"record" binding:"required,min=1" jsonschema:"required,enum=shell,enum=exec,enum=direct-tcpip,enum=sftp,enum=vscode-terminals,enum=vscode-input,enum=none"`
}

// RecordingOverride is a workspace's recording override as returned by the
// API.
type RecordingOverride struct {
	Workspace string `json:"workspace"`
	// Record lists the recording types applied to every new session to the
	// workspace; ["none"] means recording is disabled.
	Record []string `json:"record"`
	// SetBy is the username that set the override.
	SetBy string `json:"setBy,omitempty"`
	// SetAt is the unix time (seconds) the override was set.
	SetAt int64 `json:"setAt,omitempty"`
}

// WorkspaceRecording describes what is recorded in new sessions to a
// workspace: the stored override when there is one, otherwise the
// session:record policy evaluated as the workspace's owner. The policy result
// is exact only for sessions the owner opens; the policy may record other
// users' sessions differently.
type WorkspaceRecording struct {
	Workspace string `json:"workspace"`
	// Source is "override" when a recording override is set for the
	// workspace, "policy" when the session:record policy decides.
	Source string `json:"source" jsonschema:"enum=override,enum=policy"`
	// EvaluatedFor is the user the policy was evaluated as: the workspace
	// owner. Set only when Source is "policy".
	EvaluatedFor string `json:"evaluatedFor,omitempty"`
	// Record lists the recording types applied, with the same values as
	// RecordingOverrideRequest.Record except "none": an empty list means
	// nothing is recorded. It applies to SSH and webshell alike; webshell
	// sessions only ever use "shell".
	Record []string `json:"record"`
	// Override is the stored override; set only when Source is "override".
	Override *RecordingOverride `json:"override,omitempty"`
}
