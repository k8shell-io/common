// Copyright 2026 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package nats

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/nats-io/nats.go"

	"github.com/k8shell-io/common/pkg/authz"
)

// ThreatDetection is the JSON value stored in THREAT_DETECTION_BUCKET for a
// workspace name: which attack categories worktrace watches on the workspace.
// It keeps the policy result and the override apart, so clearing an override
// falls back to the policy result without evaluating the policy again.
//
// Producers, each writing only its own field with UpdateThreatDetection:
//   - the provisioner evaluates threat:detect when it provisions a workspace
//     and sets Policy; it deletes the entry when it deletes the workspace.
//   - api-server sets and clears Override through its
//     /workspaces/{name}/detection-override endpoints, guarded by
//     threat:detection:override.
//
// Consumer: every worktrace detector watches the bucket and applies Resolve
// to each workspace's events as they arrive, so a change applies at once to
// a running workspace. A workspace without an entry gets the detector's
// configured default.
type ThreatDetection struct {
	// Policy is the threat:detect result; nil when the policy has not been
	// evaluated for the workspace (yet).
	Policy *ThreatDetectionPolicy `json:"policy,omitempty"`

	// Override replaces Policy while set.
	Override *ThreatDetectionOverride `json:"override,omitempty"`
}

// ThreatDetectionPolicy is a stored threat:detect policy result.
type ThreatDetectionPolicy struct {
	// Detect is the "detect" obligation value; empty when the policy returned
	// none, which leaves the workspace to the detector's default.
	Detect string `json:"detect,omitempty"`

	// EvaluatedFor is the subject the policy was evaluated as.
	EvaluatedFor string `json:"evaluatedFor,omitempty"`

	// EvaluatedAt is the unix time (seconds) of the evaluation.
	EvaluatedAt int64 `json:"evaluatedAt,omitempty"`
}

// ThreatDetectionOverride is a stored detection override.
type ThreatDetectionOverride struct {
	// Detect is the replacement "detect" obligation value: "none", "all" or
	// comma-separated categories. Producers validate it with
	// authz.ValidateDetectObligation.
	Detect string `json:"detect"`

	// SetBy is the username that set the override, for auditing.
	SetBy string `json:"setBy,omitempty"`

	// SetAt is the unix time (seconds) the override was set.
	SetAt int64 `json:"setAt,omitempty"`
}

// ThreatDetectionBucketOptions are the options THREAT_DETECTION_BUCKET is
// created with. Only the worktrace controller creates the bucket; producers
// (provisioner, api-server) open it by name with NATSClient.OpenKV and treat
// a missing bucket as worktrace not being installed.
func ThreatDetectionBucketOptions(replicas int) BucketOptions {
	return BucketOptions{Bucket: THREAT_DETECTION_BUCKET, BucketTTL: NoBucketTTL, Replicas: replicas}
}

// Resolve returns the workspace's effective detect obligation: the override
// when one is set, else the policy result. found is false when neither
// decides, and the consumer then applies its default.
func (d *ThreatDetection) Resolve() (ob authz.DetectObligation, found bool) {
	if d == nil {
		return authz.DetectObligation{}, false
	}
	var policy authz.DetectObligation
	var policyFound bool
	if d.Policy != nil && d.Policy.Detect != "" {
		policy, policyFound = authz.ParseDetectObligation(map[string]string{authz.ObligationKeyDetect: d.Policy.Detect})
	}
	return ResolveDetectObligation(policy, policyFound, d.Override)
}

// ResolveDetectObligation applies a workspace's detection override to the
// threat:detect policy result. policy and policyFound are what
// authz.ParseDetectObligation returned; override is nil when the workspace
// has none. An override replaces the policy result entirely, so the result
// is then always found, even for "none".
func ResolveDetectObligation(policy authz.DetectObligation, policyFound bool, override *ThreatDetectionOverride) (authz.DetectObligation, bool) {
	if override == nil {
		return policy, policyFound
	}
	return authz.ParseDetectObligation(map[string]string{authz.ObligationKeyDetect: override.Detect})
}

// ParseThreatDetection decodes a THREAT_DETECTION_BUCKET value.
func ParseThreatDetection(value []byte) (*ThreatDetection, error) {
	var d ThreatDetection
	if err := json.Unmarshal(value, &d); err != nil {
		return nil, fmt.Errorf("threat detection: %w", err)
	}
	return &d, nil
}

// UpdateThreatDetection changes the workspace's entry with compare-and-set,
// so the provisioner (Policy) and api-server (Override) never overwrite each
// other's field. mutate receives the current value (zero when there is none)
// and changes it in place; an entry left with neither field is deleted.
func UpdateThreatDetection(kv *JetStreamKV, workspace string, mutate func(*ThreatDetection)) error {
	const attempts = 5
	for range attempts {
		var cur ThreatDetection
		var rev uint64
		entry, err := kv.Get(workspace)
		switch {
		case err == nil:
			d, perr := ParseThreatDetection(entry.Value())
			if perr != nil {
				return perr
			}
			cur, rev = *d, entry.Revision()
		case errors.Is(err, nats.ErrKeyNotFound):
		default:
			return err
		}

		mutate(&cur)

		if cur.Policy == nil && cur.Override == nil {
			if rev == 0 {
				return nil
			}
			// A plain delete: there is no CAS delete in this client, and a
			// racing write recreates the key, which is the outcome it wants.
			if err := kv.Delete(workspace); err != nil && !errors.Is(err, nats.ErrKeyNotFound) {
				return err
			}
			return nil
		}

		value, err := json.Marshal(&cur)
		if err != nil {
			return err
		}
		if rev == 0 {
			_, err = kv.Create(workspace, value)
		} else {
			_, err = kv.Update(workspace, value, rev)
		}
		if err == nil {
			return nil
		}
		if !errors.Is(err, nats.ErrKeyExists) && !isWrongLastSequence(err) {
			return err
		}
	}
	return fmt.Errorf("threat detection: %s changed concurrently %d times, giving up", workspace, attempts)
}

// isWrongLastSequence reports whether err is a failed compare-and-set.
func isWrongLastSequence(err error) bool {
	var apiErr *nats.APIError
	return errors.As(err, &apiErr) && apiErr.ErrorCode == nats.JSErrCodeStreamWrongLastSequence
}
