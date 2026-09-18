// Copyright 2026 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package models

// PlatformVersions is the api-server's GET /api/v1/versions response: the
// versions of the deployed k8Shell release, as published by the deployment's
// k8shell-versions ConfigMap, plus the infrastructure versions the api-server
// observes at runtime.
type PlatformVersions struct {
	// PlatformVersion is the version of the k8Shell release the services were
	// deployed from (the Helm chart's app version).
	PlatformVersion string `json:"platformVersion"`
	// Services maps a service name (e.g. "apiServer", "k8shelld") to the
	// version of the image the release deployed it from. The set of services
	// comes from the release itself, so it grows with the platform rather than
	// with this struct.
	Services map[string]string `json:"services"`
	// Infra holds versions of the infrastructure the platform runs on. These
	// are not part of the release, so they are read from the live connection
	// rather than from the ConfigMap.
	Infra map[string]ServiceVersionInfo `json:"infra"`
}

// ServiceVersionInfo is the version of a single infrastructure dependency.
type ServiceVersionInfo struct {
	// Version is the reported version, or a caller-chosen fallback
	// (e.g. "0.0.0") when it could not be resolved.
	Version string `json:"version"`
	// Error is set when the version could not be read; Version then carries
	// the fallback.
	Error string `json:"error,omitempty"`
}
