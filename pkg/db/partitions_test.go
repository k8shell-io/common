package db

import (
	"testing"
	"time"
)

func TestParsePartitionDay(t *testing.T) {
	day, ok := ParsePartitionDay("threats_", "threats_20261013")
	if !ok || !day.Equal(time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("got %v, %v", day, ok)
	}
	for _, name := range []string{"audit_20261013", "threats_2026101", "threats_default", "threats_20261313"} {
		if _, ok := ParsePartitionDay("threats_", name); ok {
			t.Errorf("%q must not parse as a threats_ day partition", name)
		}
	}
}

func TestDayFloorIsUTC(t *testing.T) {
	prague := time.FixedZone("CEST", 2*60*60)
	// 00:30 local on the 14th is still the 13th in UTC.
	got := DayFloor(time.Date(2026, 10, 14, 0, 30, 0, 0, prague))
	if want := time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC); !got.Equal(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}
