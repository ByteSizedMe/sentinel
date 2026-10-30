# Sentinel

Sentinel is an application-level RBAC authorization microservice written in Go.
It answers one question: *can user X perform action Y on resource Z?* with an
allow/deny decision and a reason. Anything not explicitly allowed is denied.

**Status:** early development. Implemented so far: the Postgres schema, CRUD for
roles, permissions and resources, role assignment, `POST /v1/authorize`, JWT
authentication on every `/v1` route, and an append-only audit log of every decision.
Caching is not built yet.

All `/v1` routes require a signed JWT (see [Authentication](#authentication)).
Only `GET /health` is public.

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

Before `make run` works you must set the JWT variables in `.env`
(see [Configuration](#configuration)); the server refuses to start without them.

`make` loads `.env` by itself, so no manual env setup is needed. Migrations are
never run automatically at startup; run `make migrate-up` after pulling changes.
`make test` runs everything; the Postgres store tests run only when `DATABASE_URL`
is set and the database is up and migrated, otherwise they are skipped.

Try it from a second window (mint a token first, see [Authentication](#authentication)):

```powershell
$token = make token
$h = @{ Authorization = "Bearer $token" }
Invoke-RestMethod -Method Post -Uri http://localhost:8080/v1/roles -Headers $h -ContentType "application/json" -Body '{"name":"editor"}'
Invoke-RestMethod -Uri http://localhost:8080/v1/roles -Headers $h
```

## Make targets and PowerShell equivalents

| Target              | Does                              | PowerShell equivalent                          |
|---------------------|-----------------------------------|------------------------------------------------|
| `make up`           | start Postgres and Redis          | `docker compose up -d`                         |
| `make down`         | stop and remove containers        | `docker compose down`                          |
| `make migrate-up`   | apply migrations                  | load `.env` (step 3), `go run ./cmd/migrate up`   |
| `make migrate-down` | revert all migrations (deletes data) | load `.env` (step 3), `go run ./cmd/migrate down` |
| `make run`          | run the server                    | load `.env` (step 3), `go run ./cmd/sentinel`  |
| `make token`        | print a dev JWT (local testing only) | load `.env` (step 3), `go run ./cmd/tokengen` |
| `make test`         | run all tests                     | `go test ./...`                                |

`docker compose down -v` also deletes the database volume.
Values in `.env` must be plain `KEY=VALUE` lines (make reads them); a literal `$` in a value must be written `$$`.

## Authentication

Every `/v1` route needs `Authorization: Bearer <jwt>`. Tokens are HS256, signed
with `JWT_SECRET`, and must carry `exp`, `iss` (= `JWT_ISSUER`), `aud`
(= `JWT_AUDIENCE`) and `sub`. Anything else gets a generic `401`. Other algorithms
(including `none`) are rejected. The token identifies the **calling service**
(the `sub` claim); it never decides which user an authorization check is about.

Generate a strong secret once and put it in `.env` as `JWT_SECRET` (and add
`JWT_ISSUER` and `JWT_AUDIENCE`, see `.env.example`):

```powershell
$b = New-Object byte[] 32; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b); [Convert]::ToBase64String($b)
```

Mint a short-lived dev token (local testing only; it reads the same variables
as the server):

```powershell
$token = make token
```

Options: `go run ./cmd/tokengen -sub my-service -ttl 30m`. Never log or commit tokens.

## Authorization check

`POST /v1/authorize` answers "can this user do this action on this resource?".
The caller (identified by the token) asks about the user named in the body:

```powershell
$h = @{ Authorization = "Bearer $token" }
Invoke-RestMethod -Method Post -Uri http://localhost:8080/v1/authorize -Headers $h -ContentType "application/json" -Body '{"user_id":"u1","action":"read","resource":"invoices"}'
```

Response: `{"allowed":true,"reason":"permission granted","matched_role":"editor"}` or
`{"allowed":false,"reason":"no matching grant"}`. Access is granted only if a role
held by the user grants that action on that resource; everything else is denied,
including unknown users, resources and actions. The reason never lists the user's
roles. If the database or the audit log fails, the response is a generic `500`, never
an allow.

Every decision, allow and deny, is written to the `audit_log` table (who asked, which
user, action, resource, result, reason, time). The table is append-only: the database
rejects `UPDATE`, `DELETE` and `TRUNCATE` on it. Because of that, test rows can only be
cleared with `make migrate-down` followed by `make migrate-up` (which also wipes all
other data). To look at the log:

```powershell
docker compose exec postgres psql -U sentinel -d sentinel -c "SELECT * FROM audit_log ORDER BY id DESC LIMIT 10"
```

## API (v1, requires a token)

IDs are numbers returned by the create calls. Names, actions and user IDs allow
only letters, digits and `_ . : -` (user IDs also allow `@`); names and actions are
1-64 characters, user IDs 1-128, descriptions up to 256.

| Method and path | Body | Success |
|-----------------|------|---------|
| `POST /v1/authorize` | `{"user_id":"u1","action":"read","resource":"invoices"}` | 200 decision |
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

Errors are JSON like `{"error":"not found"}`: 400 invalid input, 401 missing or
invalid token, 404 not found (including a missing referenced role, resource or
permission), 409 already exists, 413 body too large, 500 generic.

## Configuration

All settings come from environment variables.

| Variable        | Default           | Notes                          |
|-----------------|-------------------|--------------------------------|
| `SENTINEL_ADDR` | `:8080`           | HTTP listen address            |
| `DATABASE_URL`  | none (required)   | PostgreSQL connection string   |
| `REDIS_ADDR`    | `localhost:6379`  | Redis host:port                |
| `JWT_SECRET`    | none (required)   | HS256 signing key, at least 32 characters |
| `JWT_ISSUER`    | none (required)   | expected `iss` claim           |
| `JWT_AUDIENCE`  | none (required)   | expected `aud` claim           |

The server refuses to start if `DATABASE_URL` or any `JWT_*` variable is missing,
or if `JWT_SECRET` is too short (the placeholder in `.env.example` is, on purpose). Only `.env.example`
is committed; `.env` is git-ignored.

## Layout

```
cmd/sentinel      server entry point
cmd/migrate       runs the SQL migrations
cmd/tokengen      mints a dev JWT for local testing
migrations/       plain SQL up/down files (golang-migrate)
internal/config   environment-based config
internal/httpapi  Chi router and handlers (including /v1/authorize)
internal/rbac     domain types, validation, PolicyStore interface
internal/store    PostgreSQL implementation of PolicyStore (pgx)
internal/auth     JWT validation and middleware
internal/audit    append-only audit log
internal/cache    Redis cache (planned)
```
