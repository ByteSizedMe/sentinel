// Command migrate applies or reverts the SQL files in the migrations folder.
// Usage: go run ./cmd/migrate up|down
package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/pgx/v5" // registers the pgx5:// driver
	_ "github.com/golang-migrate/migrate/v4/source/file"     // registers file:// sources
)

func main() {
	if err := run(os.Args[1:], os.Getenv); err != nil {
		log.Fatalf("migrate: %v", err)
	}
}

func run(args []string, getenv func(string) string) error {
	if len(args) != 1 || (args[0] != "up" && args[0] != "down") {
		return errors.New("usage: migrate up|down")
	}
	dbURL := getenv("DATABASE_URL")
	if dbURL == "" {
		return errors.New("DATABASE_URL is required")
	}
	// golang-migrate picks its driver from the URL scheme; "pgx5" selects the pgx v5 driver.
	dbURL = strings.Replace(dbURL, "postgres://", "pgx5://", 1)

	dir := getenv("MIGRATIONS_DIR")
	if dir == "" {
		dir = "migrations"
	}

	m, err := migrate.New("file://"+dir, dbURL)
	if err != nil {
		return err
	}
	defer m.Close()

	if args[0] == "up" {
		err = m.Up()
	} else {
		err = m.Down() // reverts every migration
	}
	// ErrNoChange just means there was nothing to do.
	if err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return err
	}
	fmt.Println("migrate", args[0], "done")
	return nil
}
