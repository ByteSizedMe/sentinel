.PHONY: up down run test

# Load .env (if present) and export it so `go run` sees DATABASE_URL etc.
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
