// Package config handles application configuration and database connectivity.
//
// SQL migration — run once manually OR let InitDB() auto-apply it on startup:
//
//	CREATE EXTENSION IF NOT EXISTS "pgcrypto";
//
//	CREATE TABLE IF NOT EXISTS users (
//	    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
//	    name         VARCHAR(255)        NOT NULL,
//	    email        VARCHAR(255) UNIQUE NOT NULL,
//	    password_hash VARCHAR(255)       NOT NULL,
//	    role         VARCHAR(50)         NOT NULL DEFAULT 'user',
//	    created_at   TIMESTAMP           NOT NULL DEFAULT NOW()
//	);
package config

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"
)

// DB is the application-wide connection pool.
// It is initialised once by InitDB() and then shared across all handlers.
// pgxpool is safe for concurrent use — no external locking needed.
var DB *pgxpool.Pool

// InitDB opens a PostgreSQL connection pool using values from the environment,
// pings the server to confirm connectivity, and runs the schema migration so
// the users table exists before the first request arrives.
//
// It calls log.Fatal on any unrecoverable error so the process exits immediately
// with a clear message rather than crashing later with a nil-pointer panic.
func InitDB() {
	dsn := buildDSN()

	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		log.Fatalf("config: unable to create connection pool: %v", err)
	}

	// Verify the database is reachable before the server starts accepting requests.
	if err := pool.Ping(context.Background()); err != nil {
		log.Fatalf("config: unable to reach database: %v", err)
	}

	DB = pool
	log.Println("config: database connection pool established")

	runMigrations()
}

// buildDSN constructs a PostgreSQL DSN string from individual environment
// variables. Using discrete vars (instead of a single DATABASE_URL) makes
// the .env template easier to understand and lets each value be changed
// independently (e.g. only the password needs to change in staging).
func buildDSN() string {
	host := os.Getenv("DB_HOST")
	port := os.Getenv("DB_PORT")
	user := os.Getenv("DB_USER")
	password := os.Getenv("DB_PASSWORD")
	dbname := os.Getenv("DB_NAME")

	// pgx DSN format: postgres://user:password@host:port/dbname
	return fmt.Sprintf(
		"postgres://%s:%s@%s:%s/%s?sslmode=disable",
		user, password, host, port, dbname,
	)
}

// runMigrations executes idempotent DDL statements against the database.
// Using IF NOT EXISTS / CREATE EXTENSION IF NOT EXISTS means this is safe
// to call every time the application starts — it is a no-op when the schema
// already exists.
//
// For a production service with many migrations, replace this with a proper
// migration tool (golang-migrate, goose, etc.). For this project a single
// boot-time migration is sufficient.
func runMigrations() {
	migration := `
		CREATE EXTENSION IF NOT EXISTS "pgcrypto";

		CREATE TABLE IF NOT EXISTS users (
			id            UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
			name          VARCHAR(255) NOT NULL,
			email         VARCHAR(255) UNIQUE NOT NULL,
			password_hash VARCHAR(255) NOT NULL,
			role          VARCHAR(50)  NOT NULL DEFAULT 'user',
			created_at    TIMESTAMP    NOT NULL DEFAULT NOW()
		);
	`

	_, err := DB.Exec(context.Background(), migration)
	if err != nil {
		log.Fatalf("config: migration failed: %v", err)
	}

	log.Println("config: database migration applied successfully")
}
