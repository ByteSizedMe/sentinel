# Sentinel

Sentinel is an application-level RBAC authorization microservice written in Go.
It answers one question: *can user X perform action Y on resource Z?* with an
allow/deny decision and a reason. Anything not explicitly allowed is denied.

**Status:** early development. Implemented so far: the Postgres schema, CRUD for
roles, permissions and resources, and role assignment under `/v1`.
`POST /authorize`, JWT auth, the audit log and caching are not built yet.

> **Security warning:** the `/v1` endpoints currently have **no authentication**.
> Anyone who can reach the server can change policy. Run it on localhost only.

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

## Running locally on Windows

Postgres is published on host port **5433** (5432 is often taken), so
`DATABASE_URL` in `.env` uses `localhost:5433`. From a PowerShell window in the repo:

```powershell
Copy-Item .env.example .env
make up
make migrate-up
make run
```

`make` loads `.env` by itself, so no manual env setup is needed. Migrations are
never run automatically at startup; run `make migrate-up` after pulling changes.
`make test` runs everything; the Postgres store tests run only when `DATABASE_URL`
is set and the database is up and migrated, otherwise they are skipped.

Try it from a second window:

```powershell
Invoke-RestMethod -Method Post -Uri http://localhost:8080/v1/roles -ContentType "application/json" -Body '{"name":"editor"}'
Invoke-RestMethod http://localhost:8080/v1/roles
```

## Make targets and PowerShell equivalents

| Target              | Does                              | PowerShell equivalent                          |
|---------------------|-----------------------------------|------------------------------------------------|
| `make up`           | start Postgres and Redis          | `docker compose up -d`                         |
| `make down`         | stop and remove containers        | `docker compose down`                          |
| `make migrate-up`   | apply migrations                  | load `.env` (step 3), `go run ./cmd/migrate up`   |
| `make migrate-down` | revert all migrations (deletes data) | load `.env` (step 3), `go run ./cmd/migrate down` |
| `make run`          | run the server                    | load `.env` (step 3), `go run ./cmd/sentinel`  |
| `make test`         | run all tests                     | `go test ./...`                                |

`docker compose down -v` also deletes the database volume.
Values in `.env` must be plain `KEY=VALUE` lines (make reads them); a literal `$` in a value must be written `$$`.

## API (v1, unauthenticated)

IDs are numbers returned by the create calls. Names, actions and user IDs allow
only letters, digits and `_ . : -` (user IDs also allow `@`); names and actions are
1-64 characters, user IDs 1-128, descriptions up to 256.

| Method and path | Body | Success |
|-----------------|------|---------|
| `POST /v1/roles` | `{"name":"editor","description":""}` | 201 role |
| `GET /v1/roles`, `GET /v1/roles/{id}` | | 200 |
| `DELETE /v1/roles/{id}` | | 204 (also removes its grants and assignments) |
| `POST /v1/resources` | `{"name":"invoices","description":""}` | 201 resource |
| `GET /v1/resources`, `GET /v1/resources/{id}` | | 200 |
| `DELETE /v1/resources/{id}` | | 204 (also removes its permissions) |
| `POST /v1/permissions` | `{"action":"read","resource_id":1}` | 201 permission |
| `GET /v1/permissions`, `GET /v1/permissions/{id}` | | 200 |
| `DELETE /v1/permissions/{id}` | | 204 |
| `GET /v1/roles/{id}/permissions` | | 200 |
| `POST /v1/roles/{id}/permissions` | `{"permission_id":1}` | 201 |
| `DELETE /v1/roles/{id}/permissions/{permissionID}` | | 204 |
| `GET /v1/users/{userID}/roles` | | 200 |
| `POST /v1/users/{userID}/roles` | `{"role_id":1}` | 201 |
| `DELETE /v1/users/{userID}/roles/{roleID}` | | 204 |

Errors are JSON like `{"error":"not found"}`: 400 invalid input, 404 not found
(including a missing referenced role, resource or permission), 409 already exists,
500 generic.

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
cmd/sentinel      server entry point
cmd/migrate       runs the SQL migrations
migrations/       plain SQL up/down files (golang-migrate)
internal/config   environment-based config
internal/httpapi  Chi router and handlers
internal/rbac     domain types, validation, PolicyStore interface
internal/store    PostgreSQL implementation of PolicyStore (pgx)
internal/auth     JWT validation (planned)
internal/audit    audit log (planned)
internal/cache    Redis cache (planned)
```
