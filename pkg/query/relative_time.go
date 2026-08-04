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

// timeNow is the "now" used to resolve relative datetime expressions.
// Overridable in tests to pin a deterministic instant.
var timeNow = time.Now

// relativeAnchors maps a relative-date anchor keyword (case-insensitive) to
// the UTC instant it resolves to, before any +/- offset terms are applied.
// Adding a new anchor is a one-line addition here — ParseValue, Validate,
// and every resource's Descriptor pick it up with no further changes.
var relativeAnchors = map[string]func(now time.Time) time.Time{
	"now":       func(now time.Time) time.Time { return now },
	"today":     func(now time.Time) time.Time { return startOfDay(now) },
	"yesterday": func(now time.Time) time.Time { return startOfDay(now).AddDate(0, 0, -1) },
	"lastweek":  func(now time.Time) time.Time { return startOfWeek(now).AddDate(0, 0, -7) },
}

func startOfDay(t time.Time) time.Time {
	y, m, d := t.Date()
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}

// startOfWeek returns 00:00 UTC on the Monday of t's ISO week.
func startOfWeek(t time.Time) time.Time {
	d := startOfDay(t)
	daysSinceMonday := (int(d.Weekday()) + 6) % 7 // time.Weekday has Sunday=0
	return d.AddDate(0, 0, -daysSinceMonday)
}

// relativeExprPattern splits a relative-date expression into its anchor
// keyword and its (possibly empty) sequence of +/- offset terms, e.g.
// "now-90m+15s" -> anchor "now", offsets "-90m+15s".
var relativeExprPattern = regexp.MustCompile(`^([A-Za-z]+)((?:[+-]\d+[A-Za-z]+)*)$`)

// offsetTermPattern matches a single signed offset term within the offsets
// suffix, e.g. "-90m" -> sign "-", amount "90", unit "m".
var offsetTermPattern = regexp.MustCompile(`([+-])(\d+)([A-Za-z]+)`)

// parseRelativeDatetime attempts to parse raw as a relative-date expression:
// one of the relativeAnchors keywords, optionally followed by one or more
// +/- offset terms with unit s/m/h/d/w/M/y (M is month, m is minute,
// matching Grafana's relative-time convention). matched is false when raw
// isn't shaped like a relative expression at all, telling the caller to fall
// back to absolute-format parsing; err is non-nil only when raw did match
// the shape but named an unknown anchor or unit.
func parseRelativeDatetime(raw string) (t time.Time, matched bool, err error) {
	m := relativeExprPattern.FindStringSubmatch(raw)
	if m == nil {
		return time.Time{}, false, nil
	}
	anchor, ok := relativeAnchors[strings.ToLower(m[1])]
	if !ok {
		return time.Time{}, false, nil
	}

	t = anchor(timeNow().UTC())
	for _, term := range offsetTermPattern.FindAllStringSubmatch(m[2], -1) {
		n, convErr := strconv.Atoi(term[2])
		if convErr != nil {
			return time.Time{}, true, fmt.Errorf("invalid relative date %q: offset %q out of range", raw, term[0])
		}
		if term[1] == "-" {
			n = -n
		}
		t, err = applyOffset(t, n, term[3])
		if err != nil {
			return time.Time{}, true, fmt.Errorf("invalid relative date %q: %w", raw, err)
		}
	}
	return t, true, nil
}

func applyOffset(t time.Time, n int, unit string) (time.Time, error) {
	switch unit {
	case "s":
		return t.Add(time.Duration(n) * time.Second), nil
	case "m":
		return t.Add(time.Duration(n) * time.Minute), nil
	case "h":
		return t.Add(time.Duration(n) * time.Hour), nil
	case "d":
		return t.AddDate(0, 0, n), nil
	case "w":
		return t.AddDate(0, 0, 7*n), nil
	case "M":
		return t.AddDate(0, n, 0), nil
	case "y":
		return t.AddDate(n, 0, 0), nil
	default:
		return time.Time{}, fmt.Errorf("unknown offset unit %q (want one of s, m, h, d, w, M, y)", unit)
	}
}
