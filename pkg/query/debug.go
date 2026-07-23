// Copyright 2026 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package query

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// placeholderRe matches Postgres positional parameters ($1, $2, ...) so
// InterpolateSQL can substitute them with literal values for debug logging.
var placeholderRe = regexp.MustCompile(`\$(\d+)`)

// whitespaceRe collapses the indentation/newlines of a query's Go source
// formatting so InterpolateSQL's output is a single-line statement.
var whitespaceRe = regexp.MustCompile(`\s+`)

// InterpolateSQL inlines args into a $-parameterized query, producing a
// single-line standalone statement that can be pasted into a query console
// to reproduce a logged call. It is for debug logging only — never use the
// result to execute a query, since the substitution is not injection-safe.
func InterpolateSQL(q string, args []any) string {
	inlined := placeholderRe.ReplaceAllStringFunc(q, func(m string) string {
		idx, err := strconv.Atoi(m[1:])
		if err != nil || idx < 1 || idx > len(args) {
			return m
		}
		return sqlLiteral(args[idx-1])
	})
	return strings.TrimSpace(whitespaceRe.ReplaceAllString(inlined, " "))
}

// sqlLiteral renders a bound query argument as a Postgres literal.
func sqlLiteral(v any) string {
	switch val := v.(type) {
	case nil:
		return "NULL"
	case string:
		return quoteLiteral(val)
	case []string:
		if val == nil {
			return "NULL"
		}
		quoted := make([]string, len(val))
		for i, s := range val {
			quoted[i] = quoteLiteral(s)
		}
		return "ARRAY[" + strings.Join(quoted, ", ") + "]"
	case bool:
		if val {
			return "TRUE"
		}
		return "FALSE"
	case time.Time:
		return quoteLiteral(val.Format(time.RFC3339Nano))
	case *time.Time:
		if val == nil {
			return "NULL"
		}
		return quoteLiteral(val.Format(time.RFC3339Nano))
	default:
		return fmt.Sprintf("%v", val)
	}
}

func quoteLiteral(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}
