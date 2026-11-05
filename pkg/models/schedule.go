package models

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Schedule limits how long a workspace may run. It is declared on a
// blueprint and inherits through the blueprint's template field one key at a
// time, so a child can override a single value.
//
// The timeline of a workspace with a schedule:
//
//	To                      the run ends, the stop grace period begins and
//	                        the user is warned
//	To + StopGrace          the workspace pod is stopped
//	stopped + TerminateGrace  the stopped workspace is terminated (deleted)
//
// All fields are strings so that they merge as scalars; ParseSchedule turns
// them into typed values. Every field is optional. An empty field is unset.
//
// A time is either absolute, an RFC 3339 timestamp with an offset or Z
// (2026-11-10T08:00:00Z, 2026-11-10T09:00:00+01:00), or a local time without
// an offset (2026-11-10T09:00, 2026-11-10 09:00:00), which is read in
// Timezone, or in the deployment's default zone when that is unset.
type Schedule struct {
	// Timezone is the IANA name (e.g. Europe/Prague) of the zone times
	// without an offset are read in. Unset means the deployment's default.
	Timezone string `yaml:"timezone,omitempty" json:"timezone,omitempty"`
	// From is the earliest time the workspace may be provisioned.
	From string `yaml:"from,omitempty" json:"from,omitempty"`
	// To is the time the workspace expires. Unset means the workspace never
	// expires.
	To string `yaml:"to,omitempty" json:"to,omitempty"`
	// StopGrace is the period between To and the stop of the workspace. It is
	// a duration such as 15m, 2h or 1d. Unset means no grace period.
	StopGrace string `yaml:"stopGrace,omitempty" json:"stopGrace,omitempty"`
	// TerminateGrace is the period a stopped workspace is kept before it is
	// terminated. It is a duration such as 12h or 7d. Unset means a stopped
	// workspace is never terminated.
	TerminateGrace string `yaml:"terminateGrace,omitempty" json:"terminateGrace,omitempty"`
}

// ParsedSchedule is a Schedule with its values parsed. A nil time is unset.
// StopGrace is zero when unset. TerminateGrace needs HasTerminateGrace to
// tell an unset value from an explicit zero.
type ParsedSchedule struct {
	// Location is the zone times without an offset were read in.
	Location       *time.Location
	From           *time.Time
	To             *time.Time
	StopGrace      time.Duration
	TerminateGrace time.Duration
	// HasTerminateGrace reports whether TerminateGrace was set. When false a
	// stopped workspace is never terminated.
	HasTerminateGrace bool
}

// ScheduleError is a schedule validation failure. Field is the YAML key the
// failure applies to (e.g. "to", "stopGrace"), not including the "schedule."
// prefix.
type ScheduleError struct {
	Field string
	Msg   string
}

// Error implements error.
func (e *ScheduleError) Error() string { return e.Msg }

func scheduleErrorf(field, format string, args ...any) *ScheduleError {
	return &ScheduleError{Field: field, Msg: fmt.Sprintf("schedule."+field+" "+format, args...)}
}

// ParseScheduleDuration parses a duration like time.ParseDuration does and in
// addition accepts a whole number of days with the suffix "d" (e.g. "7d"),
// which time.ParseDuration lacks. The duration must not be negative.
func ParseScheduleDuration(s string) (time.Duration, error) {
	var d time.Duration
	if days, ok := strings.CutSuffix(s, "d"); ok {
		n, err := strconv.ParseUint(days, 10, 32)
		if err != nil {
			return 0, fmt.Errorf("%q is not a valid duration", s)
		}
		d = time.Duration(n) * 24 * time.Hour
	} else {
		var err error
		d, err = time.ParseDuration(s)
		if err != nil {
			return 0, fmt.Errorf("%q is not a valid duration", s)
		}
	}
	if d < 0 {
		return 0, fmt.Errorf("%q must not be negative", s)
	}
	return d, nil
}

// scheduleLayouts are the accepted forms of a time without an offset.
var scheduleLayouts = []string{
	"2006-01-02T15:04:05",
	"2006-01-02T15:04",
	"2006-01-02 15:04:05",
	"2006-01-02 15:04",
}

const wallLayout = "2006-01-02T15:04:05"

// ParseScheduleTime parses a schedule time: an RFC 3339 timestamp, or a time
// without an offset which is read in loc (the local zone when loc is nil).
//
// A time that does not exist in loc, because the clocks jump over it when
// daylight saving time starts, is moved forward by the length of the jump. A
// time that happens twice, when daylight saving time ends, is the first of the
// two.
func ParseScheduleTime(raw string, loc *time.Location) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, raw); err == nil {
		return t, nil
	}
	if loc == nil {
		loc = time.Local
	}
	for _, layout := range scheduleLayouts {
		if wall, err := time.Parse(layout, raw); err == nil {
			return resolveLocal(wall, loc), nil
		}
	}
	return time.Time{}, fmt.Errorf("%q is not a valid time: use an RFC 3339 timestamp with an offset "+
		"(2026-11-10T08:00:00Z) or a local time (2026-11-10 09:00)", raw)
}

// resolveLocal returns the instant at which the clocks of loc show wall (a
// wall-clock reading carried in a UTC time.Time), see ParseScheduleTime.
func resolveLocal(wall time.Time, loc *time.Location) time.Time {
	// A zone changes its offset rarely and never twice within a day, so the
	// offsets a day before and a day after bracket the one at wall.
	_, before := wall.Add(-24 * time.Hour).In(loc).Zone()
	_, after := wall.Add(24 * time.Hour).In(loc).Zone()

	var found []time.Time
	for i, off := range []int{before, after} {
		if i == 1 && after == before {
			break
		}
		c := wall.Add(-time.Duration(off) * time.Second)
		if c.In(loc).Format(wallLayout) == wall.Format(wallLayout) {
			found = append(found, c)
		}
	}
	switch len(found) {
	case 0: // inside the gap: use the offset from before it
		return wall.Add(-time.Duration(before) * time.Second)
	case 1:
		return found[0]
	default:
		if found[1].Before(found[0]) {
			return found[1]
		}
		return found[0]
	}
}

// Location returns the zone times without an offset are read in: the
// schedule's Timezone, or def when it is unset (the local zone when def is
// nil too). The error is a *ScheduleError.
func (s *Schedule) Location(def *time.Location) (*time.Location, error) {
	if s == nil || s.Timezone == "" {
		if def == nil {
			return time.Local, nil
		}
		return def, nil
	}
	loc, err := time.LoadLocation(s.Timezone)
	if err != nil {
		return nil, scheduleErrorf("timezone", "%q is not a known time zone (use an IANA name such as Europe/Prague)", s.Timezone)
	}
	return loc, nil
}

// Normalize returns a copy of s in which every time without an offset has
// been resolved to an RFC 3339 timestamp, in the zone it was read in. Times
// that already carry an offset are kept as written, and the Timezone is kept.
// Resolving once, when a workspace is provisioned, keeps its schedule from
// moving when the default zone changes later. A nil s gives nil.
func (s *Schedule) Normalize(def *time.Location) (*Schedule, error) {
	if s == nil {
		return nil, nil
	}
	loc, err := s.Location(def)
	if err != nil {
		return nil, err
	}
	out := *s
	for _, f := range []struct {
		field string
		dst   *string
	}{{"from", &out.From}, {"to", &out.To}} {
		if *f.dst == "" {
			continue
		}
		if _, err := time.Parse(time.RFC3339, *f.dst); err == nil {
			continue
		}
		t, err := ParseScheduleTime(*f.dst, loc)
		if err != nil {
			return nil, scheduleErrorf(f.field, "%v", err)
		}
		*f.dst = t.In(loc).Format(time.RFC3339)
	}
	return &out, nil
}

// ParseSchedule parses and validates s, reading times without an offset in
// its Timezone or, when that is unset, in def (the local zone when nil). A nil
// s yields a nil result and no error. The error, if any, is a *ScheduleError.
func ParseSchedule(s *Schedule, def *time.Location) (*ParsedSchedule, error) {
	if s == nil {
		return nil, nil
	}
	loc, err := s.Location(def)
	if err != nil {
		return nil, err
	}
	p := &ParsedSchedule{Location: loc}

	for _, f := range []struct {
		field string
		raw   string
		dst   **time.Time
	}{
		{"from", s.From, &p.From},
		{"to", s.To, &p.To},
	} {
		if f.raw == "" {
			continue
		}
		t, err := ParseScheduleTime(f.raw, loc)
		if err != nil {
			return nil, scheduleErrorf(f.field, "%v", err)
		}
		*f.dst = &t
	}
	if p.From != nil && p.To != nil && !p.From.Before(*p.To) {
		return nil, scheduleErrorf("to", "%q must be after schedule.from %q", s.To, s.From)
	}

	if s.StopGrace != "" {
		d, err := ParseScheduleDuration(s.StopGrace)
		if err != nil {
			return nil, scheduleErrorf("stopGrace", "%v", err)
		}
		p.StopGrace = d
	}
	if s.TerminateGrace != "" {
		d, err := ParseScheduleDuration(s.TerminateGrace)
		if err != nil {
			return nil, scheduleErrorf("terminateGrace", "%v", err)
		}
		p.TerminateGrace = d
		p.HasTerminateGrace = true
	}
	return p, nil
}
