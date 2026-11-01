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
behind a proxy or load balancer all clients share one address; fixing that needs
a list of trusted proxies, which is future work.

**Why one fixed 429.** Same body for both limiters and no limit values in the
response, so a client learns nothing about which limiter fired or how it is set.