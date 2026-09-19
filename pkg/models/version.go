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
	// Infra maps an infrastructure dependency name (e.g. "postgresql", "nats")
	// to its version, mirroring Services. These aren't part of the k8Shell
	// release, so they are published separately by the k8shell-infra-versions
	// ConfigMap rather than the release's k8shell-versions ConfigMap.
	Infra map[string]string `json:"infra"`
}
