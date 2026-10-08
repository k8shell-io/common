package models

import "time"

// ThreatEvent is a threat reported by a worktrace detector over NATS and
// consumed by the worktrace controller. It is the JSON payload of messages on
// the subjects built by nats.ThreatSubject.
type ThreatEvent struct {
	// ID uniquely identifies the threat; it is also the NATS message ID, which
	// lets JetStream drop redelivered duplicates, and the key consumers should
	// use to make their handling idempotent.
	ID         string    `json:"id"`
	DetectedAt time.Time `json:"detectedAt"`
	Confidence float64   `json:"confidence"`

	Title       string `json:"title"`
	Description string `json:"description,omitempty"`

	// DetectionPipeline is the detector pipeline that produced the threat
	// ("direct", "correlation" or "behavioral").
	DetectionPipeline string `json:"detectionPipeline"`

	// RuleID is the detection rule (direct pipeline) or attack path
	// (correlation pipeline) that fired. Empty for behavioral anomalies.
	RuleID string `json:"ruleId,omitempty"`

	// Where the threat was observed. WorkspaceID is empty for events without
	// pod context (e.g. node-level activity).
	Namespace     string `json:"namespace,omitempty"`
	WorkspaceID   string `json:"workspaceId,omitempty"`
	NodeName      string `json:"nodeName,omitempty"`
	ContainerName string `json:"containerName,omitempty"`

	// Evidence carries rule-specific details (process, file path, occurrences).
	Evidence map[string]any `json:"evidence,omitempty"`
}
