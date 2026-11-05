package models

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestParseScheduleDuration(t *testing.T) {
	tests := []struct {
		in   string
		want time.Duration
		err  bool
	}{
		{"15m", 15 * time.Minute, false},
		{"2h", 2 * time.Hour, false},
		{"1h30m", 90 * time.Minute, false},
		{"7d", 7 * 24 * time.Hour, false},
		{"0", 0, false},
		{"0d", 0, false},
		{"-5m", 0, true},
		{"1.5d", 0, true},
		{"d", 0, true},
		{"soon", 0, true},
		{"", 0, true},
	}
	for _, tt := range tests {
		got, err := ParseScheduleDuration(tt.in)
		if (err != nil) != tt.err {
			t.Errorf("ParseScheduleDuration(%q) error = %v, want error %v", tt.in, err, tt.err)
			continue
		}
		if err == nil && got != tt.want {
			t.Errorf("ParseScheduleDuration(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestParseSchedule(t *testing.T) {
	t.Run("nil", func(t *testing.T) {
		p, err := ParseSchedule(nil, nil)
		if p != nil || err != nil {
			t.Fatalf("got %v, %v; want nil, nil", p, err)
		}
	})

	t.Run("empty is valid and unset", func(t *testing.T) {
		p, err := ParseSchedule(&Schedule{}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if p.From != nil || p.To != nil || p.StopGrace != 0 || p.HasTerminateGrace {
			t.Fatalf("expected everything unset, got %+v", p)
		}
	})

	t.Run("full", func(t *testing.T) {
		p, err := ParseSchedule(&Schedule{
			From: "2026-11-10T08:00:00Z", To: "2026-11-10T18:00:00Z",
			StopGrace: "15m", TerminateGrace: "7d",
		}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if !p.From.Equal(time.Date(2026, 11, 10, 8, 0, 0, 0, time.UTC)) ||
			!p.To.Equal(time.Date(2026, 11, 10, 18, 0, 0, 0, time.UTC)) {
			t.Fatalf("bad times: %v %v", p.From, p.To)
		}
		if p.StopGrace != 15*time.Minute || p.TerminateGrace != 7*24*time.Hour || !p.HasTerminateGrace {
			t.Fatalf("bad durations: %+v", p)
		}
	})

	t.Run("explicit zero terminate grace is set", func(t *testing.T) {
		p, err := ParseSchedule(&Schedule{TerminateGrace: "0"}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if !p.HasTerminateGrace || p.TerminateGrace != 0 {
			t.Fatalf("got %+v", p)
		}
	})

	t.Run("offset timestamps are accepted", func(t *testing.T) {
		p, err := ParseSchedule(&Schedule{To: "2026-11-10T18:00:00+01:00"}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if !p.To.Equal(time.Date(2026, 11, 10, 17, 0, 0, 0, time.UTC)) {
			t.Fatalf("got %v", p.To)
		}
	})

	errCases := []struct {
		name  string
		s     Schedule
		field string
		msg   string
	}{
		{"bad from", Schedule{From: "tomorrow"}, "from", "RFC 3339"},
		{"offset without leading zero", Schedule{To: "2026-11-05T11:12:00+1:00"}, "to", "RFC 3339"},
		{"unknown timezone", Schedule{Timezone: "Mars/Olympus", To: "2026-11-10 09:00"}, "timezone", "not a known time zone"},
		{"date only to", Schedule{To: "2026-11-10"}, "to", "RFC 3339"},
		{"local from after local to", Schedule{From: "2026-11-11 08:00", To: "2026-11-10 08:00"}, "to", "must be after"},
		{"from equals to", Schedule{From: "2026-11-10T08:00:00Z", To: "2026-11-10T08:00:00Z"}, "to", "must be after"},
		{"from after to", Schedule{From: "2026-11-11T08:00:00Z", To: "2026-11-10T08:00:00Z"}, "to", "must be after"},
		{"bad stop grace", Schedule{StopGrace: "later"}, "stopGrace", "not a valid duration"},
		{"negative stop grace", Schedule{StopGrace: "-1h"}, "stopGrace", "negative"},
		{"bad terminate grace", Schedule{TerminateGrace: "1w"}, "terminateGrace", "not a valid duration"},
	}
	for _, tt := range errCases {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseSchedule(&tt.s, nil)
			var se *ScheduleError
			if !errors.As(err, &se) {
				t.Fatalf("want *ScheduleError, got %v", err)
			}
			if se.Field != tt.field {
				t.Errorf("field = %q, want %q", se.Field, tt.field)
			}
			if !strings.Contains(se.Error(), tt.msg) || !strings.HasPrefix(se.Error(), "schedule."+tt.field) {
				t.Errorf("message %q should start with schedule.%s and contain %q", se.Error(), tt.field, tt.msg)
			}
		})
	}
}

func mustLoad(t *testing.T, name string) *time.Location {
	t.Helper()
	loc, err := time.LoadLocation(name)
	if err != nil {
		t.Skipf("time zone data for %s is not available: %v", name, err)
	}
	return loc
}

func TestParseScheduleTimeInZone(t *testing.T) {
	prague := mustLoad(t, "Europe/Prague")
	utc := func(y int, m time.Month, d, h, mi int) time.Time { return time.Date(y, m, d, h, mi, 0, 0, time.UTC) }

	tests := []struct {
		name string
		raw  string
		want time.Time
	}{
		// winter (CET, +01:00) and summer (CEST, +02:00) in the same zone
		{"winter with T", "2026-11-10T09:00:00", utc(2026, 11, 10, 8, 0)},
		{"winter with T without seconds", "2026-11-10T09:00", utc(2026, 11, 10, 8, 0)},
		{"winter with space", "2026-11-10 09:00", utc(2026, 11, 10, 8, 0)},
		{"winter with space and seconds", "2026-11-10 09:00:00", utc(2026, 11, 10, 8, 0)},
		{"summer", "2026-07-10 09:00", utc(2026, 7, 10, 7, 0)},
		// an offset or Z always wins over the zone
		{"explicit offset", "2026-11-10T09:00:00+05:00", utc(2026, 11, 10, 4, 0)},
		{"zulu", "2026-11-10T09:00:00Z", utc(2026, 11, 10, 9, 0)},
		{"fractional seconds", "2026-11-05T10:03:00.000Z", utc(2026, 11, 5, 10, 3)},
		// spring forward 2026-03-29: 02:00-03:00 does not exist; moved forward
		{"before the gap", "2026-03-29 01:59", utc(2026, 3, 29, 0, 59)},
		{"inside the gap", "2026-03-29 02:30", utc(2026, 3, 29, 1, 30)}, // = 03:30 CEST
		{"after the gap", "2026-03-29 03:00", utc(2026, 3, 29, 1, 0)},
		// fall back 2026-10-25: 02:00-03:00 happens twice; the first one
		{"before the overlap", "2026-10-25 01:59", utc(2026, 10, 24, 23, 59)},
		{"inside the overlap", "2026-10-25 02:30", utc(2026, 10, 25, 0, 30)}, // CEST, the first
		{"after the overlap", "2026-10-25 03:00", utc(2026, 10, 25, 2, 0)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseScheduleTime(tt.raw, prague)
			if err != nil {
				t.Fatal(err)
			}
			if !got.Equal(tt.want) {
				t.Fatalf("ParseScheduleTime(%q) = %v, want %v", tt.raw, got.UTC(), tt.want)
			}
		})
	}

	t.Run("gap lands on a valid wall time", func(t *testing.T) {
		got, _ := ParseScheduleTime("2026-03-29 02:30", prague)
		if h := got.In(prague).Hour(); h != 3 {
			t.Fatalf("local hour = %d, want 3 (moved forward)", h)
		}
	})

	t.Run("zone without daylight saving", func(t *testing.T) {
		got, err := ParseScheduleTime("2026-07-10 09:00", time.UTC)
		if err != nil || !got.Equal(utc(2026, 7, 10, 9, 0)) {
			t.Fatalf("got %v, %v", got, err)
		}
	})

	t.Run("a zone east of Greenwich and one west", func(t *testing.T) {
		tokyo, ny := mustLoad(t, "Asia/Tokyo"), mustLoad(t, "America/New_York")
		if got, _ := ParseScheduleTime("2026-11-10 09:00", tokyo); !got.Equal(utc(2026, 11, 10, 0, 0)) {
			t.Errorf("tokyo: %v", got.UTC())
		}
		if got, _ := ParseScheduleTime("2026-11-10 09:00", ny); !got.Equal(utc(2026, 11, 10, 14, 0)) {
			t.Errorf("new york: %v", got.UTC())
		}
	})
}

func TestParseScheduleZoneSelection(t *testing.T) {
	prague, tokyo := mustLoad(t, "Europe/Prague"), mustLoad(t, "Asia/Tokyo")

	t.Run("default zone applies without a timezone", func(t *testing.T) {
		p, err := ParseSchedule(&Schedule{To: "2026-11-10 09:00"}, prague)
		if err != nil {
			t.Fatal(err)
		}
		if !p.To.Equal(time.Date(2026, 11, 10, 8, 0, 0, 0, time.UTC)) || p.Location != prague {
			t.Fatalf("to = %v, location = %v", p.To.UTC(), p.Location)
		}
	})

	t.Run("the schedule's timezone wins over the default", func(t *testing.T) {
		p, err := ParseSchedule(&Schedule{Timezone: "Asia/Tokyo", To: "2026-11-10 09:00"}, prague)
		if err != nil {
			t.Fatal(err)
		}
		if !p.To.Equal(time.Date(2026, 11, 10, 0, 0, 0, 0, time.UTC)) || p.Location.String() != tokyo.String() {
			t.Fatalf("to = %v, location = %v", p.To.UTC(), p.Location)
		}
	})

	t.Run("an offset ignores both", func(t *testing.T) {
		p, err := ParseSchedule(&Schedule{Timezone: "Asia/Tokyo", To: "2026-11-10T09:00:00Z"}, prague)
		if err != nil || !p.To.Equal(time.Date(2026, 11, 10, 9, 0, 0, 0, time.UTC)) {
			t.Fatalf("got %v, %v", p, err)
		}
	})

	t.Run("from and to are read in the same zone", func(t *testing.T) {
		p, err := ParseSchedule(&Schedule{From: "2026-11-10 09:00", To: "2026-11-10 18:00"}, prague)
		if err != nil {
			t.Fatal(err)
		}
		if d := p.To.Sub(*p.From); d != 9*time.Hour {
			t.Fatalf("to - from = %v", d)
		}
	})

	t.Run("nil default is the local zone", func(t *testing.T) {
		p, err := ParseSchedule(&Schedule{To: "2026-11-10 09:00"}, nil)
		if err != nil || p.Location != time.Local {
			t.Fatalf("got %v, %v", p, err)
		}
	})
}

func TestScheduleNormalize(t *testing.T) {
	prague := mustLoad(t, "Europe/Prague")

	got, err := (&Schedule{
		Timezone: "Europe/Prague", From: "2026-11-10 09:00", To: "2026-07-10T19:00",
		StopGrace: "15m", TerminateGrace: "7d",
	}).Normalize(nil)
	if err != nil {
		t.Fatal(err)
	}
	want := Schedule{Timezone: "Europe/Prague", From: "2026-11-10T09:00:00+01:00", To: "2026-07-10T19:00:00+02:00",
		StopGrace: "15m", TerminateGrace: "7d"}
	if *got != want {
		t.Fatalf("got %+v\nwant %+v", *got, want)
	}

	t.Run("absolute times are kept as written", func(t *testing.T) {
		in := Schedule{From: "2026-11-10T08:00:00Z", To: "2026-11-14T19:00:00+01:00"}
		got, err := in.Normalize(prague)
		if err != nil || *got != in {
			t.Fatalf("got %+v, %v", got, err)
		}
	})

	t.Run("the default zone is used and the original is untouched", func(t *testing.T) {
		in := &Schedule{To: "2026-11-10 09:00"}
		got, err := in.Normalize(prague)
		if err != nil || got.To != "2026-11-10T09:00:00+01:00" || in.To != "2026-11-10 09:00" {
			t.Fatalf("got %+v, %v; in %+v", got, err, in)
		}
	})

	t.Run("nil and errors", func(t *testing.T) {
		if got, err := (*Schedule)(nil).Normalize(nil); got != nil || err != nil {
			t.Fatalf("nil: %v, %v", got, err)
		}
		var se *ScheduleError
		if _, err := (&Schedule{To: "later"}).Normalize(nil); !errors.As(err, &se) || se.Field != "to" {
			t.Fatalf("bad time: %v", err)
		}
		if _, err := (&Schedule{Timezone: "Nowhere/Land", To: "2026-11-10 09:00"}).Normalize(nil); !errors.As(err, &se) || se.Field != "timezone" {
			t.Fatalf("bad zone: %v", err)
		}
	})
}
