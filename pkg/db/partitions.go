package db

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// partitionDateLayout is the day suffix of a daily partition's name
// (<prefix>YYYYMMDD).
const partitionDateLayout = "20060102"

// DailyPartitions describes a table partitioned by range on a timestamptz
// column into one partition per UTC calendar day, each named
// <Schema>.<Prefix>YYYYMMDD. Partitioning by day lets a retention janitor
// DROP whole expired partitions instead of running a row-by-row DELETE,
// which leaves no dead tuples or index bloat behind for autovacuum.
//
// The parent table itself is created by the service's own migration
// (... PARTITION BY RANGE (<column>)); EnsureDailyPartitions creates the
// partitions, so the migration needs no partition-management function or
// extension such as pg_partman.
type DailyPartitions struct {
	// Schema and Table name the partitioned parent table.
	Schema string
	Table  string

	// Prefix of each partition's name, e.g. "threats_" for threats_20261013.
	Prefix string

	// LockKey is the Postgres advisory lock key serializing partition
	// maintenance across replicas of the owning service. It must be unique
	// among the services sharing the database.
	LockKey int64
}

// EnsureDailyPartitions makes sure a partition exists for the UTC calendar
// day of from and for each of the following aheadDays days, so a write never
// fails for lack of a partition to land in. Existing partitions are left
// untouched. It holds the advisory lock while creating them, so replicas
// running it concurrently never race on the same CREATE TABLE.
func (db *DB) EnsureDailyPartitions(ctx context.Context, p DailyPartitions, from time.Time, aheadDays int) error {
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin partition maintenance: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, p.LockKey); err != nil {
		return fmt.Errorf("acquire partition lock: %w", err)
	}

	start := DayFloor(from)
	for i := 0; i <= aheadDays; i++ {
		day := start.AddDate(0, 0, i)
		// Bounds are explicit UTC timestamps, so the partition covers the same
		// UTC day whatever the session's TimeZone is.
		stmt := fmt.Sprintf("CREATE TABLE IF NOT EXISTS %s PARTITION OF %s FOR VALUES FROM ('%s') TO ('%s')",
			pgx.Identifier{p.Schema, p.Prefix + day.Format(partitionDateLayout)}.Sanitize(),
			pgx.Identifier{p.Schema, p.Table}.Sanitize(),
			day.Format(time.RFC3339), day.AddDate(0, 0, 1).Format(time.RFC3339))
		if _, err := tx.Exec(ctx, stmt); err != nil {
			return fmt.Errorf("ensure partition of %s.%s for %s: %w", p.Schema, p.Table, day.Format(time.DateOnly), err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit partition maintenance: %w", err)
	}
	return nil
}

// DropExpiredDailyPartitions drops each partition whose entire day falls
// before cutoff and returns their names. Dropping a partition is a fast
// catalog operation regardless of how many rows it holds. If another replica
// holds the advisory lock, this call is a no-op and returns (nil, nil)
// instead of racing it. Child tables not following the <Prefix>YYYYMMDD
// naming are left alone.
func (db *DB) DropExpiredDailyPartitions(ctx context.Context, p DailyPartitions, cutoff time.Time) ([]string, error) {
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin partition cleanup: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var locked bool
	if err := tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock($1)`, p.LockKey).Scan(&locked); err != nil {
		return nil, fmt.Errorf("acquire partition lock: %w", err)
	}
	if !locked {
		return nil, nil
	}

	rows, err := tx.Query(ctx, `
		SELECT child.relname
		FROM pg_inherits
		JOIN pg_class parent  ON pg_inherits.inhparent = parent.oid
		JOIN pg_class child   ON pg_inherits.inhrelid  = child.oid
		JOIN pg_namespace nsp ON parent.relnamespace   = nsp.oid
		WHERE nsp.nspname = $1 AND parent.relname = $2`, p.Schema, p.Table)
	if err != nil {
		return nil, fmt.Errorf("list partitions of %s.%s: %w", p.Schema, p.Table, err)
	}
	names, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, fmt.Errorf("list partitions of %s.%s: %w", p.Schema, p.Table, err)
	}

	var dropped []string
	for _, name := range names {
		day, ok := ParsePartitionDay(p.Prefix, name)
		if !ok {
			continue
		}
		if !day.AddDate(0, 0, 1).Before(cutoff) {
			continue // the partition's upper bound has not fully aged out yet
		}
		if _, err := tx.Exec(ctx, "DROP TABLE "+pgx.Identifier{p.Schema, name}.Sanitize()); err != nil {
			return nil, fmt.Errorf("drop expired partition %q: %w", name, err)
		}
		dropped = append(dropped, name)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit partition cleanup: %w", err)
	}
	return dropped, nil
}

// DayFloor truncates t to midnight UTC of its calendar day.
func DayFloor(t time.Time) time.Time {
	y, m, d := t.UTC().Date()
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}

// ParsePartitionDay extracts the day a <prefix>YYYYMMDD partition covers.
func ParsePartitionDay(prefix, relname string) (time.Time, bool) {
	suffix, ok := strings.CutPrefix(relname, prefix)
	if !ok {
		return time.Time{}, false
	}
	day, err := time.Parse(partitionDateLayout, suffix)
	if err != nil {
		return time.Time{}, false
	}
	return day, true
}
