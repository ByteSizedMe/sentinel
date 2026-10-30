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
- **Per-caller permissions on the management API.** Any valid token can change
  policy for now.
- **Rate limiting, metrics and tracing.** Out of scope for this stage.
- **Cloud deployment and production container images.** Everything runs locally;
  configuration is read from environment variables so deployment stays possible later.
