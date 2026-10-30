.PHONY: up down run test migrate-up migrate-down token

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
