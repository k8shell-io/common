// Copyright 2026 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package query

import (
	"testing"

	queryv1 "github.com/k8shell-io/common/pkg/api/gen/go/query/v1"
)

func usersDescriptor() *queryv1.Descriptor {
	return NewDescriptor("users").
		Field("username", queryv1.FieldType_FIELD_TYPE_STRING,
			queryv1.Operator_OPERATOR_EQ, queryv1.Operator_OPERATOR_NE).
		Field("startTime", queryv1.FieldType_FIELD_TYPE_DATETIME,
			queryv1.Operator_OPERATOR_EQ, queryv1.Operator_OPERATOR_GT, queryv1.Operator_OPERATOR_GTE,
			queryv1.Operator_OPERATOR_LT, queryv1.Operator_OPERATOR_LTE).
		Field("bytesIn", queryv1.FieldType_FIELD_TYPE_NUMBER,
			queryv1.Operator_OPERATOR_EQ, queryv1.Operator_OPERATOR_GT).
		Field("endTime", queryv1.FieldType_FIELD_TYPE_DATETIME,
			queryv1.Operator_OPERATOR_EXISTS).
		DefaultSort("startTime", queryv1.SortDir_SORT_DIR_DESC).
		Build()
}

func TestValidate_OK(t *testing.T) {
	desc := usersDescriptor()
	p := &queryv1.Payload{
		Filters: &queryv1.Filters{
			Op: queryv1.FilterOp_FILTER_OP_AND,
			Conditions: []*queryv1.Condition{
				{Field: "username", Op: queryv1.Operator_OPERATOR_EQ, Values: []string{"bruckins"}},
				{Field: "startTime", Op: queryv1.Operator_OPERATOR_GTE, Values: []string{"2026-07-01"}},
			},
		},
		Sort: []*queryv1.Sort{{Field: "startTime", Dir: queryv1.SortDir_SORT_DIR_DESC}},
	}
	if err := Validate(desc, p); err != nil {
		t.Fatalf("expected valid payload, got error: %v", err)
	}
}

func TestValidate_NilPayload(t *testing.T) {
	if err := Validate(usersDescriptor(), nil); err != nil {
		t.Fatalf("nil payload should always be valid, got: %v", err)
	}
}

func TestValidate_UnknownField(t *testing.T) {
	p := &queryv1.Payload{Filters: &queryv1.Filters{
		Conditions: []*queryv1.Condition{{Field: "nope", Op: queryv1.Operator_OPERATOR_EQ, Values: []string{"x"}}},
	}}
	if err := Validate(usersDescriptor(), p); err == nil {
		t.Fatal("expected error for unknown field")
	}
}

func TestValidate_OperatorNotAllowedOnField(t *testing.T) {
	// "lt" is valid for the resource (declared on startTime) but not declared for bytesIn.
	p := &queryv1.Payload{Filters: &queryv1.Filters{
		Conditions: []*queryv1.Condition{{Field: "bytesIn", Op: queryv1.Operator_OPERATOR_LT, Values: []string{"1"}}},
	}}
	if err := Validate(usersDescriptor(), p); err == nil {
		t.Fatal("expected error for operator not allowed on field")
	}
}

func TestValidate_BadValueForType(t *testing.T) {
	p := &queryv1.Payload{Filters: &queryv1.Filters{
		Conditions: []*queryv1.Condition{{Field: "bytesIn", Op: queryv1.Operator_OPERATOR_EQ, Values: []string{"not-a-number"}}},
	}}
	if err := Validate(usersDescriptor(), p); err == nil {
		t.Fatal("expected error for unparseable number value")
	}
}

func TestValidate_ExistsWithoutValue(t *testing.T) {
	p := &queryv1.Payload{Filters: &queryv1.Filters{
		Conditions: []*queryv1.Condition{{Field: "endTime", Op: queryv1.Operator_OPERATOR_EXISTS}},
	}}
	if err := Validate(usersDescriptor(), p); err != nil {
		t.Fatalf("exists with no value should be valid, got: %v", err)
	}
}

func TestValidate_UnknownSortField(t *testing.T) {
	p := &queryv1.Payload{Sort: []*queryv1.Sort{{Field: "nope"}}}
	if err := Validate(usersDescriptor(), p); err == nil {
		t.Fatal("expected error for unknown sort field")
	}
}

func TestBuildWhere_Empty(t *testing.T) {
	clause, args, err := BuildWhere(usersDescriptor(), nil, nil, 0)
	if err != nil || clause != "" || args != nil {
		t.Fatalf("expected empty result for nil filters, got clause=%q args=%v err=%v", clause, args, err)
	}
}

func TestBuildWhere_AndCombinator(t *testing.T) {
	desc := usersDescriptor()
	fm := FieldMap{} // no overrides needed; field names match column names here
	filters := &queryv1.Filters{
		Op: queryv1.FilterOp_FILTER_OP_AND,
		Conditions: []*queryv1.Condition{
			{Field: "username", Op: queryv1.Operator_OPERATOR_EQ, Values: []string{"bruckins"}},
			{Field: "startTime", Op: queryv1.Operator_OPERATOR_GTE, Values: []string{"2026-07-01"}},
		},
	}
	clause, args, err := BuildWhere(desc, fm, filters, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	const want = "username ILIKE $1 AND startTime >= $2"
	if clause != want {
		t.Fatalf("clause = %q, want %q", clause, want)
	}
	if len(args) != 2 {
		t.Fatalf("expected 2 args, got %d: %v", len(args), args)
	}
	if args[0] != "bruckins" {
		t.Fatalf("args[0] = %v, want %q", args[0], "bruckins")
	}
}

func TestBuildWhere_ColumnOverride(t *testing.T) {
	desc := NewDescriptor("users").
		Field("org", queryv1.FieldType_FIELD_TYPE_STRING, queryv1.Operator_OPERATOR_EQ).
		Build()
	fm := FieldMap{"org": {Name: "organization"}}
	filters := &queryv1.Filters{Conditions: []*queryv1.Condition{
		{Field: "org", Op: queryv1.Operator_OPERATOR_EQ, Values: []string{"acme"}},
	}}
	clause, args, err := BuildWhere(desc, fm, filters, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if clause != "organization ILIKE $1" {
		t.Fatalf("clause = %q, want column override applied", clause)
	}
	if args[0] != "acme" {
		t.Fatalf("args[0] = %v", args[0])
	}
}

func TestBuildWhere_ArgOffset(t *testing.T) {
	desc := usersDescriptor()
	filters := &queryv1.Filters{Conditions: []*queryv1.Condition{
		{Field: "username", Op: queryv1.Operator_OPERATOR_EQ, Values: []string{"bruckins"}},
	}}
	clause, _, err := BuildWhere(desc, nil, filters, 2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if clause != "username ILIKE $3" {
		t.Fatalf("clause = %q, want placeholder offset by 2", clause)
	}
}

func TestBuildWhere_OrCombinator(t *testing.T) {
	desc := usersDescriptor()
	filters := &queryv1.Filters{
		Op: queryv1.FilterOp_FILTER_OP_OR,
		Conditions: []*queryv1.Condition{
			{Field: "username", Op: queryv1.Operator_OPERATOR_EQ, Values: []string{"a"}},
			{Field: "username", Op: queryv1.Operator_OPERATOR_EQ, Values: []string{"b"}},
		},
	}
	clause, _, err := BuildWhere(desc, nil, filters, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	const want = "username ILIKE $1 OR username ILIKE $2"
	if clause != want {
		t.Fatalf("clause = %q, want %q", clause, want)
	}
}

func TestBuildWhere_In(t *testing.T) {
	desc := NewDescriptor("users").
		Field("username", queryv1.FieldType_FIELD_TYPE_STRING, queryv1.Operator_OPERATOR_IN).
		Build()
	filters := &queryv1.Filters{Conditions: []*queryv1.Condition{
		{Field: "username", Op: queryv1.Operator_OPERATOR_IN, Values: []string{"a", "b", "c"}},
	}}
	clause, args, err := BuildWhere(desc, nil, filters, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if clause != "username IN ($1, $2, $3)" {
		t.Fatalf("clause = %q", clause)
	}
	if len(args) != 3 {
		t.Fatalf("expected 3 args, got %d", len(args))
	}
}

func TestBuildWhere_ArrayEqIsMembershipWithWildcard(t *testing.T) {
	desc := NewDescriptor("users").
		Field("roles", queryv1.FieldType_FIELD_TYPE_STRING,
			queryv1.Operator_OPERATOR_EQ, queryv1.Operator_OPERATOR_NE).
		Build()
	fm := FieldMap{"roles": {Array: true}}

	clause, args, err := BuildWhere(desc, fm, &queryv1.Filters{Conditions: []*queryv1.Condition{
		{Field: "roles", Op: queryv1.Operator_OPERATOR_EQ, Values: []string{"admin*"}},
	}}, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	const want = "EXISTS (SELECT 1 FROM unnest(roles) AS elem WHERE elem ILIKE $1)"
	if clause != want {
		t.Fatalf("clause = %q, want %q", clause, want)
	}
	if args[0] != "admin%" {
		t.Fatalf("args[0] = %v, want glob wildcard translated", args[0])
	}
}

func TestBuildWhere_ArrayNeIsNegatedMembership(t *testing.T) {
	desc := NewDescriptor("users").
		Field("roles", queryv1.FieldType_FIELD_TYPE_STRING, queryv1.Operator_OPERATOR_NE).
		Build()
	fm := FieldMap{"roles": {Array: true}}

	clause, args, err := BuildWhere(desc, fm, &queryv1.Filters{Conditions: []*queryv1.Condition{
		{Field: "roles", Op: queryv1.Operator_OPERATOR_NE, Values: []string{"admin"}},
	}}, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	const want = "NOT EXISTS (SELECT 1 FROM unnest(roles) AS elem WHERE elem ILIKE $1)"
	if clause != want {
		t.Fatalf("clause = %q, want %q", clause, want)
	}
	if args[0] != "admin" {
		t.Fatalf("args[0] = %v", args[0])
	}
}

func TestBuildWhere_ArrayInIsOverlap(t *testing.T) {
	desc := NewDescriptor("users").
		Field("roles", queryv1.FieldType_FIELD_TYPE_STRING, queryv1.Operator_OPERATOR_IN).
		Build()
	fm := FieldMap{"roles": {Array: true}}

	clause, args, err := BuildWhere(desc, fm, &queryv1.Filters{Conditions: []*queryv1.Condition{
		{Field: "roles", Op: queryv1.Operator_OPERATOR_IN, Values: []string{"admin", "ops"}},
	}}, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if clause != "roles && $1" {
		t.Fatalf("clause = %q, want overlap operator with a single array param", clause)
	}
	if len(args) != 1 {
		t.Fatalf("expected 1 arg (the value set), got %d: %v", len(args), args)
	}
	values, ok := args[0].([]string)
	if !ok || len(values) != 2 || values[0] != "admin" || values[1] != "ops" {
		t.Fatalf("args[0] = %v, want []string{\"admin\", \"ops\"}", args[0])
	}
}

func TestBuildWhere_ExistsTrueAndFalse(t *testing.T) {
	desc := usersDescriptor()

	clause, args, err := BuildWhere(desc, nil, &queryv1.Filters{Conditions: []*queryv1.Condition{
		{Field: "endTime", Op: queryv1.Operator_OPERATOR_EXISTS},
	}}, 0)
	if err != nil || clause != "endTime IS NOT NULL" || len(args) != 0 {
		t.Fatalf("exists (default true): clause=%q args=%v err=%v", clause, args, err)
	}

	clause, args, err = BuildWhere(desc, nil, &queryv1.Filters{Conditions: []*queryv1.Condition{
		{Field: "endTime", Op: queryv1.Operator_OPERATOR_EXISTS, Values: []string{"false"}},
	}}, 0)
	if err != nil || clause != "endTime IS NULL" || len(args) != 0 {
		t.Fatalf("exists (false): clause=%q args=%v err=%v", clause, args, err)
	}
}

func TestBuildWhere_StringEqGlobWildcard(t *testing.T) {
	desc := usersDescriptor()
	clause, args, err := BuildWhere(desc, nil, &queryv1.Filters{Conditions: []*queryv1.Condition{
		{Field: "username", Op: queryv1.Operator_OPERATOR_EQ, Values: []string{"*bruck*"}},
	}}, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if clause != "username ILIKE $1" {
		t.Fatalf("clause = %q", clause)
	}
	if args[0] != "%bruck%" {
		t.Fatalf("args[0] = %v, want glob wildcards translated to SQL wildcards", args[0])
	}
}

func TestBuildWhere_StringEqNoWildcardIsExactMatch(t *testing.T) {
	desc := usersDescriptor()
	clause, args, err := BuildWhere(desc, nil, &queryv1.Filters{Conditions: []*queryv1.Condition{
		{Field: "username", Op: queryv1.Operator_OPERATOR_EQ, Values: []string{"bruckins"}},
	}}, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if clause != "username ILIKE $1" || args[0] != "bruckins" {
		t.Fatalf("clause=%q args=%v, want plain ILIKE with no wildcards", clause, args)
	}
}

func TestBuildWhere_StringNeGlobWildcard(t *testing.T) {
	desc := usersDescriptor()
	clause, args, err := BuildWhere(desc, nil, &queryv1.Filters{Conditions: []*queryv1.Condition{
		{Field: "username", Op: queryv1.Operator_OPERATOR_NE, Values: []string{"bruck?ns"}},
	}}, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if clause != "username NOT ILIKE $1" || args[0] != "bruck_ns" {
		t.Fatalf("clause=%q args=%v", clause, args)
	}
}

func TestBuildWhere_NumberEqUsesStrictEquality(t *testing.T) {
	desc := usersDescriptor()
	clause, args, err := BuildWhere(desc, nil, &queryv1.Filters{Conditions: []*queryv1.Condition{
		{Field: "bytesIn", Op: queryv1.Operator_OPERATOR_EQ, Values: []string{"42"}},
	}}, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if clause != "bytesIn = $1" {
		t.Fatalf("clause = %q, want strict equality for non-string field", clause)
	}
	if args[0] != float64(42) {
		t.Fatalf("args[0] = %v, want parsed float64", args[0])
	}
}

func TestGlobToLikePattern_EscapesLiteralMetacharacters(t *testing.T) {
	got := globToLikePattern("50%_off\\*literal*and?")
	want := `50\%\_off\\%literal%and_`
	if got != want {
		t.Fatalf("globToLikePattern = %q, want %q", got, want)
	}
}

func TestBuildOrderBy_DefaultsWhenSortEmpty(t *testing.T) {
	desc := usersDescriptor()
	orderBy := BuildOrderBy(desc, nil, nil)
	if orderBy != "startTime DESC" {
		t.Fatalf("orderBy = %q, want default_sort applied", orderBy)
	}
}

func TestBuildOrderBy_ExplicitSort(t *testing.T) {
	desc := usersDescriptor()
	orderBy := BuildOrderBy(desc, nil, []*queryv1.Sort{{Field: "username", Dir: queryv1.SortDir_SORT_DIR_ASC}})
	if orderBy != "username ASC" {
		t.Fatalf("orderBy = %q", orderBy)
	}
}

func TestParseValue_Datetime(t *testing.T) {
	if _, err := ParseValue(queryv1.FieldType_FIELD_TYPE_DATETIME, "2026-07-01"); err != nil {
		t.Fatalf("expected YYYY-MM-DD to parse: %v", err)
	}
	if _, err := ParseValue(queryv1.FieldType_FIELD_TYPE_DATETIME, "2026-07-01T10:00:00Z"); err != nil {
		t.Fatalf("expected RFC3339 to parse: %v", err)
	}
	if _, err := ParseValue(queryv1.FieldType_FIELD_TYPE_DATETIME, "not-a-date"); err == nil {
		t.Fatal("expected invalid datetime to error")
	}
}
