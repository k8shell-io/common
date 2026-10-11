// Copyright 2026 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"github.com/invopop/jsonschema"

	"github.com/k8shell-io/common/pkg/threat"
)

// DetectionOverrideRequest is the body of
// PUT /workspaces/{name}/detection-override. Detect lists the threat
// categories worktrace watches on the workspace, replacing what the
// threat:detect policy decided; ["all"] watches every category and ["none"]
// disables detection.
type DetectionOverrideRequest struct {
	Detect []string `json:"detect" binding:"required,min=1" jsonschema:"required"`
}

// JSONSchemaExtend enumerates the accepted detect values from
// threat.Categories, so the schema follows the category list.
func (DetectionOverrideRequest) JSONSchemaExtend(s *jsonschema.Schema) {
	setDetectEnum(s, true)
}

// DetectionOverride is a workspace's detection override as returned by the
// API.
type DetectionOverride struct {
	Workspace string `json:"workspace"`
	// Detect lists the categories watched on the workspace: ["all"], ["none"]
	// or category names.
	Detect []string `json:"detect"`
	// SetBy is the username that set the override.
	SetBy string `json:"setBy,omitempty"`
	// SetAt is the unix time (seconds) the override was set.
	SetAt int64 `json:"setAt,omitempty"`
}

// JSONSchemaExtend enumerates the detect values from threat.Categories.
func (DetectionOverride) JSONSchemaExtend(s *jsonschema.Schema) {
	setDetectEnum(s, true)
}

// WorkspaceDetection describes which threat categories worktrace watches on a
// workspace: the stored override when there is one, otherwise the
// threat:detect policy result stored when the workspace was provisioned.
type WorkspaceDetection struct {
	Workspace string `json:"workspace"`
	// Source is "override" when a detection override is set, "policy" when
	// the stored threat:detect result decides, and "default" when neither
	// does and worktrace applies its configured default.
	Source string `json:"source" jsonschema:"enum=override,enum=policy,enum=default"`
	// Detect lists the categories watched, with the same values as
	// DetectionOverrideRequest.Detect except "none": an empty list means
	// nothing is watched. Empty when Source is "default".
	Detect []string `json:"detect"`
	// EvaluatedFor is the subject the policy was evaluated as when the
	// workspace was provisioned. Set when a policy result is stored.
	EvaluatedFor string `json:"evaluatedFor,omitempty"`
	// EvaluatedAt is the unix time (seconds) of that evaluation.
	EvaluatedAt int64 `json:"evaluatedAt,omitempty"`
	// Override is the stored override; set only when Source is "override".
	Override *DetectionOverride `json:"override,omitempty"`
}

// JSONSchemaExtend enumerates the detect values from threat.Categories;
// "none" is never listed, an empty list means nothing is watched.
func (WorkspaceDetection) JSONSchemaExtend(s *jsonschema.Schema) {
	setDetectEnum(s, false)
}

// DetectValues returns the values a detect list may hold: "all", "none" when
// withNone is set, and every category in threat.Categories.
func DetectValues(withNone bool) []string {
	values := []string{"all"}
	if withNone {
		values = append(values, "none")
	}
	return append(values, threat.Strings()...)
}

// setDetectEnum sets the item enum of the schema's "detect" property.
func setDetectEnum(s *jsonschema.Schema, withNone bool) {
	if s.Properties == nil {
		return
	}
	detect, ok := s.Properties.Get("detect")
	if !ok || detect.Items == nil {
		return
	}
	detect.Items.Enum = nil
	for _, v := range DetectValues(withNone) {
		detect.Items.Enum = append(detect.Items.Enum, v)
	}
}
