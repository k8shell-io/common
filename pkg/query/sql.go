// Copyright 2026 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package query

import (
	"fmt"
	"strings"

	queryv1 "github.com/k8shell-io/common/pkg/api/gen/go/query/v1"
)

// FieldMap overrides how a resource's descriptor field names resolve to SQL
// columns. A field absent from the map resolves to a non-array column of
// its own name. It is declared by the resource-owning service alongside its
// Descriptor and is never derived from client input, so every column
// identifier that reaches the generated SQL originates from a trusted,
// server-declared string.
type FieldMap map[string]Column

// Column describes how a single descriptor field name resolves to SQL.
type Column struct {
	// Name is the SQL column name. Empty means the same as the field name.
	Name string

	// Array marks Name as a Postgres array column (e.g. "roles" text[]).
	// eq/ne become array-membership checks (true when any element matches,
	// with the same glob-wildcard support as scalar string eq/ne) and in
	// becomes an array-overlap check against a literal value set, instead
	// of the usual scalar comparisons.
	Array bool
}

func (fm FieldMap) resolve(field string) Column {
	col, ok := fm[field]
	if !ok {
		return Column{Name: field}
	}
	if col.Name == "" {
		col.Name = field
	}
	return col
}

// ColumnFor resolves the SQL column name for a descriptor field name.
func (fm FieldMap) ColumnFor(field string) string {
	return fm.resolve(field).Name
}

var comparisonSQL = map[queryv1.Operator]string{
	queryv1.Operator_OPERATOR_EQ:  "=",
	queryv1.Operator_OPERATOR_NE:  "<>",
	queryv1.Operator_OPERATOR_GT:  ">",
	queryv1.Operator_OPERATOR_GTE: ">=",
	queryv1.Operator_OPERATOR_LT:  "<",
	queryv1.Operator_OPERATOR_LTE: "<=",
}

// BuildWhere translates a Filters group into a parameterized SQL WHERE
// clause fragment (without the leading "WHERE") using Postgres-style $N
// placeholders, plus the arguments to bind to it in order. argOffset is the
// number of positional arguments already bound ahead of this fragment (0 if
// none). Returns "", nil, nil when filters has no conditions.
//
// Callers must run Validate on the enclosing Payload against the same desc
// first — BuildWhere trusts that every condition's field and operator have
// already been checked against the resource's Descriptor.
func BuildWhere(desc *queryv1.Descriptor, fm FieldMap, filters *queryv1.Filters, argOffset int) (string, []any, error) {
	if filters == nil || len(filters.GetConditions()) == 0 {
		return "", nil, nil
	}

	fields := fieldsByName(desc)
	combinator := " AND "
	if filters.GetOp() == queryv1.FilterOp_FILTER_OP_OR {
		combinator = " OR "
	}

	var (
		parts []string
		args  []any
	)
	for _, c := range filters.GetConditions() {
		f, ok := fields[c.GetField()]
		if !ok {
			return "", nil, fmt.Errorf("query: unknown field %q", c.GetField())
		}

		part, partArgs, err := conditionSQL(fm.resolve(c.GetField()), f.GetType(), c, argOffset+len(args))
		if err != nil {
			return "", nil, err
		}
		parts = append(parts, part)
		args = append(args, partArgs...)
	}

	return strings.Join(parts, combinator), args, nil
}

func conditionSQL(col Column, typ queryv1.FieldType, c *queryv1.Condition, argOffset int) (string, []any, error) {
	switch c.GetOp() {
	case queryv1.Operator_OPERATOR_EXISTS:
		want := true
		if len(c.GetValues()) == 1 {
			v, err := ParseValue(queryv1.FieldType_FIELD_TYPE_BOOLEAN, c.GetValues()[0])
			if err != nil {
				return "", nil, err
			}
			want = v.(bool)
		}
		if want {
			return col.Name + " IS NOT NULL", nil, nil
		}
		return col.Name + " IS NULL", nil, nil

	case queryv1.Operator_OPERATOR_EQ, queryv1.Operator_OPERATOR_NE:
		if col.Array {
			return arrayMembershipCondition(col.Name, c, argOffset)
		}
		if typ == queryv1.FieldType_FIELD_TYPE_STRING {
			verb := "ILIKE"
			if c.GetOp() == queryv1.Operator_OPERATOR_NE {
				verb = "NOT ILIKE"
			}
			return fmt.Sprintf("%s %s $%d", col.Name, verb, argOffset+1), []any{globToLikePattern(c.GetValues()[0])}, nil
		}
		return comparisonCondition(col.Name, typ, c, argOffset)

	case queryv1.Operator_OPERATOR_IN:
		if col.Array {
			return arrayOverlapCondition(col.Name, c, argOffset)
		}
		placeholders := make([]string, len(c.GetValues()))
		args := make([]any, len(c.GetValues()))
		for i, raw := range c.GetValues() {
			v, err := ParseValue(typ, raw)
			if err != nil {
				return "", nil, err
			}
			placeholders[i] = fmt.Sprintf("$%d", argOffset+i+1)
			args[i] = v
		}
		return fmt.Sprintf("%s IN (%s)", col.Name, strings.Join(placeholders, ", ")), args, nil

	default:
		return comparisonCondition(col.Name, typ, c, argOffset)
	}
}

// comparisonCondition builds a plain "column <op> $N" fragment for the
// strict-comparison operators (eq/ne on non-array, non-string fields,
// gt/gte/lt/lte).
func comparisonCondition(column string, typ queryv1.FieldType, c *queryv1.Condition, argOffset int) (string, []any, error) {
	op, ok := comparisonSQL[c.GetOp()]
	if !ok {
		return "", nil, fmt.Errorf("query: unsupported operator %s", c.GetOp())
	}
	v, err := ParseValue(typ, c.GetValues()[0])
	if err != nil {
		return "", nil, err
	}
	return fmt.Sprintf("%s %s $%d", column, op, argOffset+1), []any{v}, nil
}

// arrayMembershipCondition builds an eq/ne condition against a Postgres
// array column: true when at least one element of the array
// case-insensitively glob-matches the value (see globToLikePattern).
func arrayMembershipCondition(column string, c *queryv1.Condition, argOffset int) (string, []any, error) {
	if len(c.GetValues()) != 1 {
		return "", nil, fmt.Errorf("query: operator %s requires exactly one value", c.GetOp())
	}
	expr := fmt.Sprintf("EXISTS (SELECT 1 FROM unnest(%s) AS elem WHERE elem ILIKE $%d)", column, argOffset+1)
	if c.GetOp() == queryv1.Operator_OPERATOR_NE {
		expr = "NOT " + expr
	}
	return expr, []any{globToLikePattern(c.GetValues()[0])}, nil
}

// arrayOverlapCondition builds an in condition against a Postgres array
// column: true when the column shares at least one element (exact match,
// no wildcards) with the given set of values, bound as a single array
// parameter.
func arrayOverlapCondition(column string, c *queryv1.Condition, argOffset int) (string, []any, error) {
	if len(c.GetValues()) == 0 {
		return "", nil, fmt.Errorf("query: in requires at least one value")
	}
	return fmt.Sprintf("%s && $%d", column, argOffset+1), []any{c.GetValues()}, nil
}

// globToLikePattern translates a client glob pattern ("*" for any run of
// characters, "?" for any single character) into a Postgres ILIKE pattern,
// escaping any literal "%", "_", or "\" in the input first so they can
// never be misread as pattern metacharacters. Postgres's default LIKE/ILIKE
// escape character is "\", so no explicit ESCAPE clause is needed.
func globToLikePattern(raw string) string {
	var b strings.Builder
	for _, r := range raw {
		switch r {
		case '%', '_', '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case '*':
			b.WriteByte('%')
		case '?':
			b.WriteByte('_')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// Mandatory is a single AND condition enforced independent of a client's
// Filters — typically derived from authz obligations rather than client
// input (e.g. scoping a listing to the caller's org). Column must be a
// trusted, server-declared identifier, never taken from client input.
type Mandatory struct {
	// Column is the SQL column name to constrain.
	Column string

	// Array marks Column as a Postgres array column, using the same
	// overlap ("&&") semantics as an "in" Condition on an array field (see
	// arrayOverlapCondition). When false, an equality condition is built
	// against Values[0].
	Array bool

	// Values holds the operand(s). An empty Values means "no constraint";
	// BuildQuery skips such entries, so callers may unconditionally append
	// a Mandatory built from an obligation that turned out to be absent.
	Values []string
}

func (m Mandatory) sql(argOffset int) (string, []any) {
	if len(m.Values) == 0 {
		return "", nil
	}
	if m.Array {
		return fmt.Sprintf("%s && $%d", m.Column, argOffset+1), []any{m.Values}
	}
	return fmt.Sprintf("%s = $%d", m.Column, argOffset+1), []any{m.Values[0]}
}

// BuildQuery assembles a full paginated SQL query from a base "SELECT ...
// FROM ..." header, a client's Filters/Sort (validate the enclosing Payload
// against desc with Validate before calling this), and a set of Mandatory
// conditions that apply regardless of the client's own Filters.op.
//
// The Filters-derived WHERE fragment is parenthesized before ANDing
// mandatory conditions onto it — without that, a client-chosen
// Filters.op = OR would exploit SQL's AND-binds-tighter-than-OR precedence
// to dilute a mandatory (e.g. obligation-derived) constraint instead of
// being scoped by it.
//
// Returns the complete query string and its positional arguments, ready to
// pass to a pgx Query call. Callers still own their own SELECT column list
// and row-scanning, since those are resource-specific.
func BuildQuery(selectSQL string, desc *queryv1.Descriptor, fm FieldMap, payload *queryv1.Payload,
	mandatory []Mandatory, limit, offset int) (string, []any, error) {
	where, args, err := BuildWhere(desc, fm, payload.GetFilters(), 0)
	if err != nil {
		return "", nil, err
	}

	var conditions []string
	if where != "" {
		conditions = append(conditions, "("+where+")")
	}
	for _, m := range mandatory {
		frag, fragArgs := m.sql(len(args))
		if frag == "" {
			continue
		}
		conditions = append(conditions, frag)
		args = append(args, fragArgs...)
	}

	sqlQuery := selectSQL
	if len(conditions) > 0 {
		sqlQuery += "WHERE " + strings.Join(conditions, " AND ") + "\n"
	}
	if orderBy := BuildOrderBy(desc, fm, payload.GetSort()); orderBy != "" {
		sqlQuery += "ORDER BY " + orderBy + "\n"
	}

	args = append(args, limit, offset)
	sqlQuery += fmt.Sprintf("LIMIT $%d OFFSET $%d", len(args)-1, len(args))

	return sqlQuery, args, nil
}

// BuildOrderBy translates Sort keys into a SQL ORDER BY fragment (without
// the leading "ORDER BY"), falling back to the descriptor's default_sort
// when sorts is empty. Returns "" when there is nothing to sort by.
func BuildOrderBy(desc *queryv1.Descriptor, fm FieldMap, sorts []*queryv1.Sort) string {
	if len(sorts) == 0 {
		sorts = desc.GetDefaultSort()
	}
	if len(sorts) == 0 {
		return ""
	}

	parts := make([]string, 0, len(sorts))
	for _, s := range sorts {
		dir := "ASC"
		if s.GetDir() == queryv1.SortDir_SORT_DIR_DESC {
			dir = "DESC"
		}
		parts = append(parts, fmt.Sprintf("%s %s", fm.ColumnFor(s.GetField()), dir))
	}
	return strings.Join(parts, ", ")
}
