// Copyright 2026 the k8Shell authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"encoding/json"
	"fmt"
)

// QueryFieldDescriptor is the JSON shape of a single queryable/sortable
// field of a resource, as advertised by that resource's _schema endpoint.
type QueryFieldDescriptor struct {
	Name      string   `json:"name"`
	Type      string   `json:"type"`
	Operators []string `json:"operators"`
}

// QuerySort is the JSON shape of a single sort key, used both in a
// QueryDescriptor's default sort and in a client-issued QueryPayload.
type QuerySort struct {
	Field string `json:"field"`
	Dir   string `json:"dir"`
}

// QueryDescriptor is the JSON shape returned by a resource's _schema
// endpoint, describing which fields are queryable/sortable.
type QueryDescriptor struct {
	Resource    string                 `json:"resource"`
	Fields      []QueryFieldDescriptor `json:"fields"`
	DefaultSort []QuerySort            `json:"defaultSort,omitempty"`
}

// QueryCondition is the JSON shape of a single filter condition in a
// client-issued query payload. Value accepts either a single string or an
// array of strings in JSON, since a condition's operator determines how
// many operands it takes (e.g. "in" takes several, "eq" takes one).
type QueryCondition struct {
	Field string
	Op    string
	Value []string
}

func (c *QueryCondition) UnmarshalJSON(data []byte) error {
	var raw struct {
		Field string          `json:"field"`
		Op    string          `json:"op"`
		Value json.RawMessage `json:"value"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	c.Field = raw.Field
	c.Op = raw.Op

	if len(raw.Value) == 0 {
		return nil
	}
	var single string
	if err := json.Unmarshal(raw.Value, &single); err == nil {
		c.Value = []string{single}
		return nil
	}
	var multi []string
	if err := json.Unmarshal(raw.Value, &multi); err != nil {
		return fmt.Errorf("condition value must be a string or array of strings")
	}
	c.Value = multi
	return nil
}

// QueryFilters is the JSON shape of a query payload's filter group.
type QueryFilters struct {
	Op         string           `json:"op"`
	Conditions []QueryCondition `json:"conditions"`
}

// QueryPage is the JSON shape of a query payload's paging window.
type QueryPage struct {
	Limit  int32 `json:"limit"`
	Offset int32 `json:"offset"`
}

// QueryPayload is the JSON shape of a client-issued query against a
// resource's queryable fields, as advertised by that resource's _schema
// endpoint.
type QueryPayload struct {
	Filters *QueryFilters `json:"filters,omitempty"`
	Sort    []QuerySort   `json:"sort,omitempty"`
	Page    *QueryPage    `json:"page,omitempty"`
}
