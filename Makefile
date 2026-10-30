.PHONY: up down run test test-integration bench migrate-up migrate-down token

# On Windows, always use cmd.exe so behaviour does not depend on whether Git
# Bash happens to be on PATH. Every recipe below is one plain command, so it
# works the same under cmd.exe or sh. Avoid cp, rm, `if [ ... ]` and friends.
ifeq ($(OS),Windows_NT)
SHELL := cmd.exe
endif

# Load .env (if present) and export it so child processes (go run, go test)
# see DATABASE_URL etc. Lines must be plain KEY=VALUE; a literal $ in a value
# would need to be written as $$.
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

# Print a short-lived dev JWT (signed with JWT_SECRET from .env) to stdout.
# The leading @ stops make from echoing the command, so only the token prints.
# Local testing only. Options: go run ./cmd/tokengen -sub my-service -ttl 30m
token:
	@go run ./cmd/tokengen
