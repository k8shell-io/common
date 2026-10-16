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

// Threat is a threat as stored by the worktrace controller, returned by its
// QueryThreats RPC. It differs from ThreatEvent by what the controller adds:
// severity, the time it stored the threat, and its deduplication state.
type Threat struct {
	ID         string    `json:"id"`
	DetectedAt time.Time `json:"detectedAt"`
	ReceivedAt time.Time `json:"receivedAt"`

	// Severity is "low", "medium", "high" or "critical", derived from
	// Confidence when the controller stored the threat.
	Severity   string  `json:"severity"`
	Confidence float64 `json:"confidence"`

	Title       string `json:"title"`
	Description string `json:"description,omitempty"`

	// DetectionPipeline is "direct", "correlation" or "behavioral".
	DetectionPipeline string `json:"detectionPipeline"`

	// RuleID is the detection rule or attack path that fired. Empty for
	// behavioral anomalies.
	RuleID string `json:"ruleId,omitempty"`

	Namespace     string `json:"namespace,omitempty"`
	WorkspaceID   string `json:"workspaceId,omitempty"`
	NodeName      string `json:"nodeName,omitempty"`
	ContainerName string `json:"containerName,omitempty"`

	// Mode is "shadow" for a threat of a rule rolled out in shadow mode
	// (recorded, never alerted on); empty otherwise.
	Mode string `json:"mode,omitempty"`

	// MergedInto is the ID of the threat this one was merged into (same
	// process, within the dedup window). Empty for a reported threat.
	MergedInto string `json:"mergedInto,omitempty"`

	// Occurrences is set on a dedup summary: how many threats for the same
	// rule and workspace its window saw.
	Occurrences int32 `json:"occurrences,omitempty"`

	// Evidence carries rule-specific details (process, file path, syscall
	// arguments, ...).
	Evidence map[string]any `json:"evidence,omitempty"`
}
