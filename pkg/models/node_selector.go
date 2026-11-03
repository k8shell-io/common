// Copyright 2026 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package models

// NodeSelectorValue is one label value found on cluster nodes for a node
// selector key, with how many nodes carry it.
type NodeSelectorValue struct {
	Value            string `json:"value"`
	NodeCount        int32  `json:"nodeCount"`
	ReadyCount       int32  `json:"readyCount"`
	SchedulableCount int32  `json:"schedulableCount"`
}

// NodeSelectorKey is a node selector key the provisioner is configured with
// and the values currently present on cluster nodes, sorted by value.
type NodeSelectorKey struct {
	Key    string              `json:"key"`
	Values []NodeSelectorValue `json:"values"`
}

// NodeSelectorOptions is the response of GET /nodes/selectors.
type NodeSelectorOptions struct {
	Keys []NodeSelectorKey `json:"keys"`
}
