// Copyright 2026 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package query

import (
	"fmt"
	"strconv"
	"time"

	queryv1 "github.com/k8shell-io/common/pkg/api/gen/go/query/v1"
)

// dateOnlyLayout matches the plain YYYY-MM-DD dates a native HTML date
// picker produces, as an alternative to full RFC3339 timestamps.
const dateOnlyLayout = "2006-01-02"

// Validate checks a Payload against a resource's Descriptor: every filter
// condition's field must exist on the resource, its operator must be one
// the field's descriptor allows, and its value(s) must parse according to
// the field's declared type. Sort fields are checked for existence only.
// A nil Payload is always valid.
func Validate(desc *queryv1.Descriptor, p *queryv1.Payload) error {
	if p == nil {
		return nil
	}

	fields := fieldsByName(desc)

	if p.GetFilters() != nil {
		for _, c := range p.GetFilters().GetConditions() {
			f, ok := fields[c.GetField()]
			if !ok {
				return fmt.Errorf("query: unknown field %q", c.GetField())
			}
			if !operatorAllowed(f, c.GetOp()) {
				return fmt.Errorf("query: operator %s not allowed on field %q", c.GetOp(), c.GetField())
			}
			if err := validateValues(f, c.GetOp(), c.GetValues()); err != nil {
				return fmt.Errorf("query: field %q: %w", c.GetField(), err)
			}
		}
	}

	for _, s := range p.GetSort() {
		if _, ok := fields[s.GetField()]; !ok {
			return fmt.Errorf("query: unknown sort field %q", s.GetField())
		}
	}

	return nil
}

func operatorAllowed(f *queryv1.FieldDescriptor, op queryv1.Operator) bool {
	for _, o := range f.GetOperators() {
		if o == op {
			return true
		}
	}
	return false
}

func validateValues(f *queryv1.FieldDescriptor, op queryv1.Operator, values []string) error {
	switch op {
	case queryv1.Operator_OPERATOR_EXISTS:
		if len(values) > 1 {
			return fmt.Errorf("exists takes at most one value")
		}
		if len(values) == 1 {
			if _, err := strconv.ParseBool(values[0]); err != nil {
				return fmt.Errorf("exists value %q must be \"true\" or \"false\"", values[0])
			}
		}
		return nil
	case queryv1.Operator_OPERATOR_IN:
		if len(values) == 0 {
			return fmt.Errorf("in requires at least one value")
		}
	default:
		if len(values) != 1 {
			return fmt.Errorf("operator %s requires exactly one value", op)
		}
	}

	for _, v := range values {
		if _, err := ParseValue(f.GetType(), v); err != nil {
			return err
		}
	}
	return nil
}

// ParseValue parses a raw condition value according to a field's declared
// type, returning a Go-typed value (string, float64, bool, or time.Time)
// suitable for use directly as a SQL query argument.
func ParseValue(t queryv1.FieldType, raw string) (any, error) {
	switch t {
	case queryv1.FieldType_FIELD_TYPE_STRING:
		return raw, nil
	case queryv1.FieldType_FIELD_TYPE_NUMBER:
		v, err := strconv.ParseFloat(raw, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid number %q", raw)
		}
		return v, nil
	case queryv1.FieldType_FIELD_TYPE_BOOLEAN:
		v, err := strconv.ParseBool(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid boolean %q", raw)
		}
		return v, nil
	case queryv1.FieldType_FIELD_TYPE_DATETIME:
		if v, err := time.Parse(time.RFC3339, raw); err == nil {
			return v, nil
		}
		if v, err := time.Parse(dateOnlyLayout, raw); err == nil {
			return v, nil
		}
		return nil, fmt.Errorf("invalid datetime %q (expected RFC3339 or YYYY-MM-DD)", raw)
	default:
		return nil, fmt.Errorf("field has unspecified type")
	}
}
