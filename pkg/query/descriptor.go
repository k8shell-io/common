// Copyright 2026 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package query provides a generic, resource-agnostic engine for declaring
// what fields of a resource are queryable/sortable, validating an incoming
// query.v1.Payload against that declaration, and translating a validated
// Payload into a parameterized Postgres WHERE/ORDER BY fragment.
//
// It holds no knowledge of any specific resource (users, sessions, ...) —
// each resource-owning service declares its own Descriptor with
// NewDescriptor, serves it from its own schema RPC, and reuses the same
// Descriptor to validate and translate incoming Payloads. That single
// declaration is what keeps a resource's advertised schema and its actual
// server-side enforcement from drifting apart.
package query

import (
	queryv1 "github.com/k8shell-io/common/pkg/api/gen/go/query/v1"
)

// DescriptorBuilder incrementally builds a resource's query Descriptor.
type DescriptorBuilder struct {
	d *queryv1.Descriptor
}

// NewDescriptor starts a Descriptor for the given resource identifier, e.g. "users".
func NewDescriptor(resource string) *DescriptorBuilder {
	return &DescriptorBuilder{d: &queryv1.Descriptor{Resource: resource}}
}

// Field declares a queryable/sortable field and the operators valid against it.
func (b *DescriptorBuilder) Field(name string, typ queryv1.FieldType, ops ...queryv1.Operator) *DescriptorBuilder {
	b.d.Fields = append(b.d.Fields, &queryv1.FieldDescriptor{
		Name:      name,
		Type:      typ,
		Operators: ops,
	})
	return b
}

// DefaultSort appends a sort key applied when a client's Payload specifies none.
func (b *DescriptorBuilder) DefaultSort(field string, dir queryv1.SortDir) *DescriptorBuilder {
	b.d.DefaultSort = append(b.d.DefaultSort, &queryv1.Sort{Field: field, Dir: dir})
	return b
}

// Build returns the assembled Descriptor.
func (b *DescriptorBuilder) Build() *queryv1.Descriptor {
	return b.d
}

func fieldsByName(desc *queryv1.Descriptor) map[string]*queryv1.FieldDescriptor {
	m := make(map[string]*queryv1.FieldDescriptor, len(desc.GetFields()))
	for _, f := range desc.GetFields() {
		m[f.GetName()] = f
	}
	return m
}
