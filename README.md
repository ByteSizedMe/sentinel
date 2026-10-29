# Sentinel

Sentinel is an application-level RBAC authorization microservice written in Go.
It answers one question: *can user X perform action Y on resource Z?* with an
allow/deny decision and a reason. Anything not explicitly allowed is denied.

**Status:** early development. Only the project skeleton and `GET /health` exist so far.

## Requirements

- Go (see `go.mod`)
- Docker with Docker Compose
- Optional: `make`

## Quick start

1. Create your local config and set a real password:

   ```powershell
   Copy-Item .env.example .env
   ```

2. Start Postgres 16 and Redis 7 (both bound to 127.0.0.1; Postgres is on host port 5433):

   ```powershell
   docker compose up -d
   docker compose ps
   ```

3. Run the server (it needs `DATABASE_URL`; the Makefile loads `.env` for you,
   the PowerShell version below does the same by hand):

   ```powershell
   Get-Content .env | Where-Object { $_ -match '^\s*[^#\s][^=]*=' } | ForEach-Object {
     $name, $value = $_ -split '=', 2
     Set-Item -Path "env:$($name.Trim())" -Value $value.Trim()
   }
   go run ./cmd/sentinel
   ```

4. Check it:

   ```powershell
   curl.exe -i http://localhost:8080/health
   ```

   Expected: `200 OK` with `{"status":"ok"}`. Press Ctrl+C to stop; it shuts down gracefully.

## Make targets and PowerShell equivalents

| Target      | Does                          | PowerShell equivalent                 |
|-------------|-------------------------------|---------------------------------------|
| `make up`   | start Postgres and Redis      | `docker compose up -d`                |
| `make down` | stop and remove containers    | `docker compose down`                 |
| `make run`  | run the server                | load `.env` (step 3), `go run ./cmd/sentinel` |
| `make test` | run all tests                 | `go test ./...`                       |

`docker compose down -v` also deletes the database volume.

## Configuration

All settings come from environment variables.

| Variable        | Default           | Notes                          |
|-----------------|-------------------|--------------------------------|
| `SENTINEL_ADDR` | `:8080`           | HTTP listen address            |
| `DATABASE_URL`  | none (required)   | PostgreSQL connection string   |
| `REDIS_ADDR`    | `localhost:6379`  | Redis host:port                |

The server refuses to start if `DATABASE_URL` is missing. Only `.env.example`
is committed; `.env` is git-ignored.

## Layout

```
cmd/sentinel      entry point
internal/config   environment-based config
internal/httpapi  Chi router and handlers
internal/rbac     authorization logic (planned)
internal/store    PostgreSQL access (planned)
internal/auth     JWT validation (planned)
internal/audit    audit log (planned)
internal/cache    Redis cache (planned)
```
