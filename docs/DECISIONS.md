# Design decisions

Short records of the main choices in Sentinel and the reasons for them.

## 1. Deny by default

**Decision.** `allowed` is true only when the decision query finds a grant that
joins the user's roles to a permission for the requested action and resource.
Every other outcome is a denial: unknown users, unknown resources, unknown
actions, empty input after validation, and any error.

**Why.** An authorization service that fails open turns every outage or bug into
a security hole. With deny by default, forgetting to add a rule makes things
fail visibly instead of silently allowing access.

**Consequence.** Unknown users, resources and actions all return the same reason
(`no matching grant`), so callers cannot probe which of them exist. Errors that
mean "could not decide" return `500` rather than a decision.

## 2. PostgreSQL plus Redis

**Decision.** PostgreSQL is the source of truth. Redis holds a short-lived copy
of decisions.

**Why.** Policy data is relational (roles, permissions and resources joined
through link tables) and needs constraints, foreign keys with cascading deletes
and transactions, which suits Postgres. Authorization checks are read-heavy and
repeat the same questions, which suits an in-memory cache. Redis never holds
anything that Postgres does not, so losing Redis loses speed, not data.

## 3. Cache-aside

**Decision.** The authorize path reads Redis first, asks Postgres on a miss and
stores the result with a TTL. Writes go to Postgres only.

**Why.** It is the simplest pattern in which the cache can fail without taking
the service down: any cache error falls through to Postgres. Write-through or
write-behind would make Redis part of the write path and a possible source of
truth, which is the wrong trade for an authorization system.

**Consequence.** Only Postgres answers are stored. A cache error can never turn
into an allow. The TTL (default 60 seconds) is also an upper bound on how long
any stale entry could survive.

## 4. Invalidation: a generation counter

**Decision.** One number in Redis (the "generation") is stamped on every cached
entry when the lookup starts. Any change that can alter a decision moves the
generation forward after the database change commits, which makes every older
entry unreachable at once. The logic lives in one type, `cache.CachedStore`,
which lists every store method explicitly.

**Why not delete the affected users' keys?** That needs a lookup of "which users
hold this role?" for every kind of change, and there is a race: a slow request
can read the old policy, lose the race with the writer's delete, and then store
the old answer. With a generation, such a request holds the old generation, so
what it stores is already unreachable.

**Trade-off.** Any policy change empties the whole cache. That is acceptable
because policy changes are rare compared with checks. If invalidation fails (for
example Redis is down during a write), the store skips the cache for one TTL, by
which time every old entry has expired.

## 5. Audit failure fails closed

**Decision.** Every decision is written to the audit log before the response is
sent. If the write fails, the response is a `500` and the decision is withheld.

**Why.** An audit log is only useful if it is complete. Returning decisions that
were not recorded would let access happen with no trace, exactly when something
is wrong. A caller that gets an error should treat it as a denial.

**Cost.** If the audit table is unavailable, authorization stops. The decision
query and the audit table live in the same database, so in practice both fail
together.

The log is append-only at the database level (triggers reject `UPDATE`, `DELETE`
and `TRUNCATE`), not just by convention.

## 6. What was deliberately left out

- **Role hierarchies, deny rules and wildcard permissions.** They make decisions
  harder to reason about and to cache correctly. Exact matching keeps the model small.
- **RS256 and JWKS.** HS256 with a shared secret is enough for a service called
  by a few trusted services, and keeps the key handling simple.
- **Login, token refresh and user management.** Sentinel authorizes; it does not
  authenticate end users. Callers present a token issued elsewhere.
- **Finer-grained caller permissions.** Callers get three coarse scopes (see
  section 7), not per-resource or per-role scopes, and there is no callers table
  or token revocation.
- **Distributed rate limiting and trusted-proxy handling.** Limits are per
  process (section 8), and the client IP ignores proxy headers.
- **Metrics and tracing.** Out of scope for this stage.
- **Cloud deployment and production container images.** Everything runs locally;
  configuration is read from environment variables so deployment stays possible later.

## 7. Scopes in the JWT, one per kind of call

**Decision.** Each `/v1` route requires a scope in the token's `scope` claim:
`sentinel:authorize` for `POST /v1/authorize`, `sentinel:read` for every `GET`,
`sentinel:admin` for every other `POST` and `DELETE`. A token that is valid but
lacks the scope gets `403 {"error":"forbidden"}`.

**Why scopes in the JWT.** The service already trusts the token's signature and
`sub`. Putting the permission in the same signed token needs no new table, no
extra query per request and nothing to keep in sync. The `scope` claim is the
standard OAuth2 shape (one space-separated string), parsed strictly: exact,
case-sensitive matches on single spaces, and a missing or non-string claim means
no scopes.

**Why three independent scopes.** The two jobs differ in risk: asking "may X do
Y?" is something many services need, while changing policy is something almost
none should. Admin does not imply read or authorize, so a token can be given
exactly the access its caller needs and a stolen admin token does not also read
or authorize unless it was issued with those scopes. There is no hierarchy to
reason about.

**Why a fixed 403 body.** The same `{"error":"forbidden"}` for every case, with no
hint about the needed scope or the token's scopes, gives a prober nothing to learn
from. The server logs the route pattern and the token's `sub` (quoted, never the
token or scope list), and does not write to the audit log, which only records
authorization decisions. A request with no valid token is still a `401`.

**Why deny by default for routes.** All `/v1` routes are declared in one table
that names each route's scope. A route declared with an empty scope is refused
for everyone, and a test walks the real router and fails if a route exists
without a scope, so a forgotten scope cannot become an open endpoint.

**Cost.** Scopes are only as safe as the signing secret: with a shared HS256 key,
anyone who holds `JWT_SECRET` can mint any scope. Changing a caller's scopes
means issuing a new token, and an issued token cannot be revoked before it
expires. RS256 with separate issuer and verifier keys would remove the first
problem; it is left out for now.

## 8. Rate limiting: in-process buckets, IP first, then caller

**Decision.** Two token-bucket limiters protect `/v1`: one per client IP
before authentication, one per token subject after it. `/health` is exempt. A
refusal is `429 {"error":"too many requests"}` with `Retry-After`. The order is
IP limit, JWT check, caller limit, scope check, handler.

**Why in-process buckets and not Redis.** Redis is already optional here: when it
is down, the service falls back to Postgres. A Redis-backed limiter would add a
new failure mode to every request and force a question with no good answer: if
Redis is unreachable, do requests go through (fail open, no protection exactly
when something is wrong) or get refused (fail closed, an outage of a cache takes
the API down)? In-process buckets cost no network round trip and cannot fail that
way. Memory is bounded with a key cap, least-recently-seen eviction and a lazy
sweep of idle keys, so there is no background goroutine to leak or shut down.

**Cost.** Counters are per process: with N instances the effective limit is up to
N times higher, and a restart resets them. That is acceptable for stopping floods
and token guessing, not for exact quotas. Distributed limiting is left for later.

**Why this order.** The IP limiter goes first so that floods of invalid or missing
tokens are slowed down before any token is parsed. The caller limiter needs the
subject, so it must come after authentication; that also means an invalid token
never spends a real caller's budget, so an attacker cannot drain someone else's
allowance by sending garbage. It goes before the scope check so that a caller
that keeps getting `403` still spends its own budget and cannot probe for free.

**Why `RemoteAddr` only.** `X-Forwarded-For`, `X-Real-IP` and `Forwarded` are set
by the client unless a trusted proxy overwrites them. Believing them would let any
client pick a new key per request and walk around the limit, or charge someone
else's address. The TCP peer address cannot be chosen that way. The cost is that
behind a proxy or load balancer all clients share one address; section 10 adds
an explicit list of trusted proxies for that case.

**Why one fixed 429.** Same body for both limiters and no limit values in the
response, so a client learns nothing about which limiter fired or how it is set.

## 9. A second database role for the running service

**Decision.** Migrations run as the database owner (`MIGRATE_DATABASE_URL`). The
server runs as `sentinel_app` (`DATABASE_URL`), created by migration 000004 as
`NOLOGIN` with no password in any file. It gets read and write on the five policy
tables and only `SELECT` and `INSERT` on `audit_log`; nothing on `schema_migrations`;
no `CREATE` in the schema. `make db-app-role` sets its login password.

**Why the triggers alone were not enough.** The append-only triggers block
`UPDATE`, `DELETE` and `TRUNCATE`, but a table owner can `DROP TRIGGER` (or
`ALTER TABLE ... DISABLE TRIGGER`) and then change anything. A service that runs as
the owner therefore protects its audit log only as well as its own code. Privileges
close that gap: `sentinel_app` is not the owner, so it cannot touch the triggers,
and it does not hold the privileges the triggers guard. Two layers now: a missing
privilege for the app role, a trigger for everyone who does hold the privilege.
The privilege tests check this by name, and they were confirmed to fail when
`UPDATE` is granted to the role by hand.

**Why a password script that reads the environment.** `ALTER ROLE ... PASSWORD`
cannot take a bind parameter, so the statement is built by `psql`
(`:'pw'` quotes the value as a string literal). The value reaches `psql` through an
environment variable that the shell passes by name only (`docker compose exec -e
APP_DB_PASSWORD`), and the SQL arrives on standard input. Piping the password in
from `cmd.exe` was rejected: each side of a `cmd.exe` pipe runs in a child process
whose command line contains the already expanded text, which would put the password
in the process list. One caveat: if the server is configured with
`log_statement = 'ddl'` or `'all'`, the `ALTER ROLE` statement text, password
included, would be logged. The default (`none`) does not.

**What it does not cover.** A superuser or the table owner can still rewrite the
log; that is outside what the application can control. There is no startup check
that the connection is *not* a superuser or the owner. It is future work, along
with keeping the owner credential out of the runtime environment (a deployment
concern). Tables added by later migrations get no automatic grants: a new table is
unreachable for `sentinel_app` until a migration grants it, which is the
deny-by-default behaviour we want.

## 10. Trusted proxies: `X-Forwarded-For` only, read from the right

**Decision.** `TRUSTED_PROXIES` lists proxy IPs and CIDRs. Empty means the old
behaviour: the key is the TCP peer and every forwarding header is ignored. If the
peer is listed, the client is the rightmost `X-Forwarded-For` entry that is not
itself a listed proxy. Only the per-IP limiter uses this.

**Why `X-Forwarded-For` only.** It is the header an AWS load balancer appends to,
and supporting `X-Real-IP` and `Forwarded` as well would be three parsers, three
sets of spoofing rules and no benefit. A header Sentinel does not read cannot be
abused.

**Why right to left.** Each proxy appends the address it saw to the right. Entries
to the left were written by the client or by hops we have no reason to trust, so
the leftmost entry is exactly what an attacker controls. Walking from the right and
skipping our own proxies stops at the first address nobody we trust vouched for, which
is the real client as seen by our own infrastructure. Spoofed entries added on the
left are never reached.

**Why fail back to the peer address.** A missing, empty, malformed, over-long
(more than 20 entries) or all-trusted header gives no safe answer, and the peer
address is always safe: it can only cost precision (all clients share the proxy's
bucket), never let a client choose its bucket. Every entry is parsed with
`net/netip`; one bad entry rejects the whole header, and the raw string is never used
as a key. The result is normalized (zone removed, IPv4-mapped IPv6 unmapped) so one
client cannot get two buckets by spelling its address two ways.

**Why reject `/0` at startup.** Trusting every address means every peer's header is
believed, so the limiter is fully spoofable again, silently. That configuration is
almost certainly a mistake, so the server refuses to start, with a message that names
the entry's position and never repeats its value. Bad CIDRs, empty entries and lists
over 64 entries are refused the same way.

**Remaining limits.** Counters are still per process. IPv6 clients are keyed by full
address, so one host with a /64 can use many addresses; limiting per /64 is future
work. A list that is too wide (say a whole cloud region) trusts more than intended,
and the header is only meaningful if the proxy really appends to it and Sentinel is
not reachable except through that proxy.

## 11. Container image

**Decision.** A multi-stage `Dockerfile`: build `cmd/sentinel` and `cmd/migrate` with
`CGO_ENABLED=0 -trimpath -ldflags "-s -w"` on the official `golang` image whose tag
matches `go.mod`, then copy them and `migrations/` onto `distroless/static` (nonroot
variant), both pinned by tag and digest. The user is numeric (`65532`), there is no
shell, no `HEALTHCHECK` (the load balancer uses `GET /health`), and `cmd/tokengen`
is never copied into the build, so it cannot ship. The migrate binary finds its SQL
through the existing `MIGRATIONS_DIR` variable, set to `/app/migrations`; embedding
the migrations in the binary was considered and left out because the existing
setting already solves it with no code change. Secrets are only passed at run time.
