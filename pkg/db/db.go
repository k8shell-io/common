package db

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	log "github.com/k8shell-io/common/pkg/logger"
	"github.com/rs/zerolog"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
)

type DBConfig struct {
	Enabled           bool          `yaml:"enabled"`
	Username          string        `yaml:"username"`
	Password          string        `yaml:"password"`
	Database          string        `yaml:"database"`
	Hostname          string        `yaml:"hostname"`
	Port              int           `yaml:"port"`
	MaxConns          int32         `yaml:"maxConns"`
	MinConns          int32         `yaml:"minConns"`
	MaxConnIdleTime   time.Duration `yaml:"maxConnIdleTime"`
	MaxConnLifetime   time.Duration `yaml:"maxConnLifetime"`
	HealthCheckPeriod time.Duration `yaml:"healthCheckPeriod"`

	// MigrationRetryTimeout and MigrationRetryInterval bound how long
	// runDBMigrations keeps retrying a dirty migration before giving up.
	// Services in a bundle can start in no particular order, and a
	// migration's DDL may depend on a schema/table that another
	// service's own migration creates (see e.g. the provisioner's
	// db/migrations, which FKs into the identity schema). Since the
	// postgres driver sends a whole migration file as a single implicit
	// transaction, a failed migration never leaves partial DDL behind —
	// only the dirty marker survives the rollback — so it's safe to
	// clear that marker and retry until the dependency appears.
	MigrationRetryTimeout  time.Duration `yaml:"migrationRetryTimeout"`
	MigrationRetryInterval time.Duration `yaml:"migrationRetryInterval"`
}

type DB struct {
	config DBConfig
	Pool   *pgxpool.Pool
	log    *zerolog.Logger
}

const (
	MigrationsRoot   = "db/migrations"
	DefaultListLimit = 50
	MaxListLimit     = 100
)

func runDBMigrations(connString, serviceName string, retryTimeout, retryInterval time.Duration, log *zerolog.Logger) error {
	src := fmt.Sprintf("file://%s", MigrationsRoot)

	u, err := url.Parse(connString)
	if err != nil {
		return fmt.Errorf("parse conn string for migrate: %w", err)
	}
	q := u.Query()
	q.Set("x-migrations-table", "schema_migrations_"+serviceName)
	u.RawQuery = q.Encode()
	dbURL := u.String()

	m, err := migrate.New(src, dbURL)
	if err != nil {
		return fmt.Errorf("init migrate: %w (src=%s)", err, src)
	}

	deadline := time.Now().Add(retryTimeout)
	for {
		err := m.Up()
		if err == nil || err == migrate.ErrNoChange {
			return nil
		}

		var dirtyErr migrate.ErrDirty
		if !errors.As(err, &dirtyErr) {
			return fmt.Errorf("apply migrate: %w", err)
		}

		if time.Now().After(deadline) {
			return fmt.Errorf("apply migrate: migration version %d is still dirty after retrying for %s — "+
				"the SQL in db/migrations/ likely has a syntax error, or a cross-service dependency "+
				"(e.g. a FK into another service's schema) never showed up: %w", dirtyErr.Version, retryTimeout, err)
		}

		// The postgres driver sends a whole migration file as a single
		// implicit transaction, so this failed attempt rolled back any
		// DDL it ran — only the dirty marker itself persists. Clear it
		// and retry; this is expected when services in a bundle start
		// in no particular order and this migration depends on state
		// another service's own migration hasn't created yet.
		log.Warn().Msgf("migration version %d is dirty, likely waiting on a cross-service dependency; "+
			"clearing and retrying in %s: %v", dirtyErr.Version, retryInterval, err)
		if ferr := m.Force(int(dirtyErr.Version) - 1); ferr != nil {
			return fmt.Errorf("apply migrate: clear dirty version %d: %w", dirtyErr.Version, ferr)
		}
		time.Sleep(retryInterval)
	}
}

func (c *DBConfig) SetDefaults() {
	if c.Port == 0 {
		c.Port = 5432
	}
	if c.MaxConns == 0 {
		c.MaxConns = 10
	}
	if c.MinConns == 0 {
		c.MinConns = 1
	}
	if c.MaxConnIdleTime == 0 {
		c.MaxConnIdleTime = 5 * time.Minute
	}
	if c.MaxConnLifetime == 0 {
		c.MaxConnLifetime = time.Hour
	}
	if c.HealthCheckPeriod == 0 {
		c.HealthCheckPeriod = 30 * time.Second
	}
	if c.MigrationRetryTimeout == 0 {
		c.MigrationRetryTimeout = 2 * time.Minute
	}
	if c.MigrationRetryInterval == 0 {
		c.MigrationRetryInterval = 3 * time.Second
	}
}

func (c *DBConfig) ConnString() string {
	q := url.Values{}
	q.Add("sslmode", "disable")
	return fmt.Sprintf(
		"postgres://%s:%s@%s:%d/%s?%s",
		url.QueryEscape(c.Username),
		url.QueryEscape(c.Password),
		url.QueryEscape(c.Hostname),
		c.Port,
		url.QueryEscape(c.Database),
		q.Encode(),
	)
}

func NewDB(config DBConfig, serviceName string) (*DB, error) {
	log := log.NewLogger("db")
	if !config.Enabled {
		return nil, fmt.Errorf("database is disabled")
	}
	if config.Username == "" || config.Password == "" || config.Database == "" || config.Hostname == "" {
		return nil, fmt.Errorf("database configuration is incomplete: username, password, database, and hostname are required")
	}
	if serviceName == "" {
		return nil, fmt.Errorf("ServiceName is required to namespace migrations")
	}

	config.SetDefaults()
	connString := config.ConnString()

	poolConfig, err := pgxpool.ParseConfig(connString)
	if err != nil {
		return nil, fmt.Errorf("parse connection string: %w", err)
	}
	poolConfig.MaxConns = config.MaxConns
	poolConfig.MinConns = config.MinConns
	poolConfig.MaxConnIdleTime = config.MaxConnIdleTime
	poolConfig.MaxConnLifetime = config.MaxConnLifetime
	poolConfig.HealthCheckPeriod = config.HealthCheckPeriod

	ctx := context.Background()
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, fmt.Errorf("create connection pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping db pool: %w", err)
	}
	log.Info().Msgf("DB connection OK %s:%d/%s", config.Hostname, config.Port, config.Database)

	if err := runDBMigrations(connString, serviceName, config.MigrationRetryTimeout, config.MigrationRetryInterval, log); err != nil {
		pool.Close()
		return nil, fmt.Errorf("run database migrations: %w", err)
	}

	log.Info().Msg("Database migrations applied")
	return &DB{config: config, Pool: pool, log: log}, nil
}

func (db *DB) Close() {
	db.Pool.Close()
}

func AdjustListLimit(limit, offset int) (int, int) {
	if limit <= 0 {
		limit = DefaultListLimit
	} else if limit > MaxListLimit {
		limit = MaxListLimit
	}
	if offset < 0 {
		offset = 0
	}
	return limit, offset
}
