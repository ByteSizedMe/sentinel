.PHONY: up down run test test-integration bench migrate-up migrate-down db-app-role token

# On Windows, always use cmd.exe so behaviour does not depend on whether Git
# Bash happens to be on PATH. Every recipe below is one plain command, so it
# works the same under cmd.exe or sh. Avoid cp, rm, `if [ ... ]` and friends.
ifeq ($(OS),Windows_NT)
SHELL := cmd.exe
endif

# Load .env (if present) and export it so child processes (go run, go test)
# see DATABASE_URL etc. Lines must be plain KEY=VALUE; a literal $ in a value
# would need to be written as $$.
#
# Two database URLs: DATABASE_URL is what the server (make run) and the tests
# use, the low-privilege sentinel_app role. MIGRATE_DATABASE_URL is the owner,
# used only by cmd/migrate (make migrate-up / migrate-down); if it is unset,
# cmd/migrate falls back to DATABASE_URL.
-include .env
export

up:
	docker compose up -d

down:
	docker compose down

run:
	go run ./cmd/sentinel

test:
	go test ./...

# Integration tests and benchmarks need the docker-compose Postgres and Redis
# (make up, make migrate-up). They are behind the "integration" build tag, so
# plain `make test` never runs them. REDIS_URL falls back to the local default
# if .env does not set it; they skip themselves if DATABASE_URL is unset.
test-integration: REDIS_URL ?= redis://localhost:6379/0
test-integration: APP_DATABASE_URL ?= $(DATABASE_URL)
test-integration:
	go test -tags integration -count=1 -v ./internal/integration/...

# Compare /authorize with a warm cache against Postgres every time. Each run
# adds audit_log rows (append-only, so they stay); see the note in the code.
bench: REDIS_URL ?= redis://localhost:6379/0
bench:
	go test -tags integration -run NONE -bench . -benchtime 500x ./internal/integration/...

# Apply / revert the SQL files in migrations/ (needs `make up` first).
migrate-up:
	go run ./cmd/migrate up

migrate-down:
	go run ./cmd/migrate down

# Give the sentinel_app role (created by migration 000004) a login password,
# taken from APP_DB_PASSWORD in .env. Run it once after `make migrate-up`.
#
# The password never appears in a command line: docker is told only the NAME of
# the variable (-e APP_DB_PASSWORD), and psql reads the SQL from standard input
# (see scripts/set_app_role_password.sql). It runs psql inside the postgres
# container as the container's superuser, so it needs no owner URL. The leading @
# keeps make from echoing the command.
db-app-role:
	@$(if $(APP_DB_PASSWORD),,$(error APP_DB_PASSWORD is not set; add it to .env))
	@docker compose exec -T -e APP_DB_PASSWORD postgres psql -q -U $(POSTGRES_USER) -d $(POSTGRES_DB) < scripts/set_app_role_password.sql

# Print a short-lived dev JWT (signed with JWT_SECRET from .env) to stdout.
# The leading @ stops make from echoing the command, so only the token prints.
# Local testing only. Options: go run ./cmd/tokengen -sub my-service -ttl 30m
token:
	@go run ./cmd/tokengen
