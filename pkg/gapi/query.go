// Copyright 2026 the k8Shell authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package gapi

import (
	"fmt"

	queryv1 "github.com/k8shell-io/common/pkg/api/gen/go/query/v1"
	"github.com/k8shell-io/common/pkg/models"
)

var queryFieldTypeJSON = map[queryv1.FieldType]string{
	queryv1.FieldType_FIELD_TYPE_STRING:   "string",
	queryv1.FieldType_FIELD_TYPE_NUMBER:   "number",
	queryv1.FieldType_FIELD_TYPE_BOOLEAN:  "boolean",
	queryv1.FieldType_FIELD_TYPE_DATETIME: "datetime",
}

var queryOperatorJSON = map[queryv1.Operator]string{
	queryv1.Operator_OPERATOR_EQ:     "eq",
	queryv1.Operator_OPERATOR_NE:     "ne",
	queryv1.Operator_OPERATOR_IN:     "in",
	queryv1.Operator_OPERATOR_GT:     "gt",
	queryv1.Operator_OPERATOR_GTE:    "gte",
	queryv1.Operator_OPERATOR_LT:     "lt",
	queryv1.Operator_OPERATOR_LTE:    "lte",
	queryv1.Operator_OPERATOR_EXISTS: "exists",
}

var querySortDirJSON = map[queryv1.SortDir]string{
	queryv1.SortDir_SORT_DIR_ASC:  "asc",
	queryv1.SortDir_SORT_DIR_DESC: "desc",
}

// ProtoToQueryDescriptor converts a query.v1.Descriptor proto into the JSON
// shape served by a resource's _schema HTTP endpoint.
func ProtoToQueryDescriptor(desc *queryv1.Descriptor) *models.QueryDescriptor {
	if desc == nil {
		return nil
	}
	fields := make([]models.QueryFieldDescriptor, 0, len(desc.GetFields()))
	for _, f := range desc.GetFields() {
		ops := make([]string, 0, len(f.GetOperators()))
		for _, op := range f.GetOperators() {
			ops = append(ops, queryOperatorJSON[op])
		}
		fields = append(fields, models.QueryFieldDescriptor{
			Name:      f.GetName(),
			Type:      queryFieldTypeJSON[f.GetType()],
			Operators: ops,
		})
	}

	var sorts []models.QuerySort
	for _, s := range desc.GetDefaultSort() {
		sorts = append(sorts, models.QuerySort{
			Field: s.GetField(),
			Dir:   querySortDirJSON[s.GetDir()],
		})
	}

	return &models.QueryDescriptor{
		Resource:    desc.GetResource(),
		Fields:      fields,
		DefaultSort: sorts,
	}
}

// queryOperatorProto intentionally has no "contains" entry: query.v1.Operator
// dropped OPERATOR_CONTAINS in favor of glob wildcards ("*", "?") embedded in
// eq/ne values on string fields.
var queryOperatorProto = map[string]queryv1.Operator{
	"eq":     queryv1.Operator_OPERATOR_EQ,
	"ne":     queryv1.Operator_OPERATOR_NE,
	"in":     queryv1.Operator_OPERATOR_IN,
	"gt":     queryv1.Operator_OPERATOR_GT,
	"gte":    queryv1.Operator_OPERATOR_GTE,
	"lt":     queryv1.Operator_OPERATOR_LT,
	"lte":    queryv1.Operator_OPERATOR_LTE,
	"exists": queryv1.Operator_OPERATOR_EXISTS,
}

var querySortDirProto = map[string]queryv1.SortDir{
	"asc":  queryv1.SortDir_SORT_DIR_ASC,
	"desc": queryv1.SortDir_SORT_DIR_DESC,
}

var queryFilterOpProto = map[string]queryv1.FilterOp{
	"and": queryv1.FilterOp_FILTER_OP_AND,
	"or":  queryv1.FilterOp_FILTER_OP_OR,
}

// QueryPayloadToProto converts a client-issued JSON query payload into a
// query.v1.Payload proto, rejecting any op/dir/filter-op values outside the
// known enum strings. It does not validate field names, per-field operator
// permissions, or value types against a resource's schema — that's
// query.Validate's job (pkg/query) once the caller has a Descriptor to
// validate against.
func QueryPayloadToProto(p *models.QueryPayload) (*queryv1.Payload, error) {
	payload := &queryv1.Payload{}
	if p == nil {
		return payload, nil
	}

	if p.Filters != nil {
		filterOp, ok := queryFilterOpProto[p.Filters.Op]
		if !ok {
			return nil, fmt.Errorf("invalid filters.op %q", p.Filters.Op)
		}
		conditions := make([]*queryv1.Condition, 0, len(p.Filters.Conditions))
		for _, cond := range p.Filters.Conditions {
			op, ok := queryOperatorProto[cond.Op]
			if !ok {
				return nil, fmt.Errorf("invalid condition op %q", cond.Op)
			}
			conditions = append(conditions, &queryv1.Condition{
				Field:  cond.Field,
				Op:     op,
				Values: cond.Value,
			})
		}
		payload.Filters = &queryv1.Filters{Op: filterOp, Conditions: conditions}
	}

	for _, s := range p.Sort {
		dir, ok := querySortDirProto[s.Dir]
		if !ok {
			return nil, fmt.Errorf("invalid sort dir %q", s.Dir)
		}
		payload.Sort = append(payload.Sort, &queryv1.Sort{Field: s.Field, Dir: dir})
	}

	if p.Page != nil {
		payload.Page = &queryv1.Page{Limit: p.Page.Limit, Offset: p.Page.Offset}
	}

	return payload, nil
}
