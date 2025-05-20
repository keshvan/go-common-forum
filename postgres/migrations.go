package postgres

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/golang-migrate/migrate/v4"
	pgxMigrateDriver "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	_ "github.com/golang-migrate/migrate/v4/source/file" // Для "file://"
	_ "github.com/jackc/pgx/v5/stdlib"
)

func (p *Postgres) RunMigrations(ctx context.Context, migrationPath string) error {
	if p.Pool == nil {
		return fmt.Errorf("migrations: pgxpool.Pool is nil in Postgres struct")
	}

	connStr := p.Pool.Config().ConnString()

	db, err := sql.Open("pgx", connStr)
	if err != nil {
		return fmt.Errorf("failed to open db connection: %w", err)
	}
	defer db.Close()

	driver, err := pgxMigrateDriver.WithInstance(db, &pgxMigrateDriver.Config{})
	if err != nil {
		return fmt.Errorf("failed to create postgres driver: %w", err)
	}

	m, err := migrate.NewWithDatabaseInstance("file://"+migrationPath, "postgres", driver)
	if err != nil {
		return fmt.Errorf("failed to create migrate instance: %w", err)
	}

	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		return fmt.Errorf("failed to apply migrations: %w", err)
	}

	m.Close()

	return nil
}
