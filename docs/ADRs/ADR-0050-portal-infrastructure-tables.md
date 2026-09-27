# ADR-0050: Portal Infrastructure Tables

- Status: Accepted
- Date: 2026-09-28
- Authors: PRAHO maintainers

## Context

Portal workers need shared, atomic request counters and durable replay and
idempotency claims. LocMemCache is private to each worker. DatabaseCache can
evict live entries and does not provide the fixed-window increment contract.

Portal already stores server-side sessions in SQLite. Migrating every installed
app also runs historical billing migrations that create and remove business
tables. Deployment must target the infrastructure apps explicitly.

## Decision

The Portal database may contain sessions and explicitly named infrastructure
tables. Its application model inventory is exactly sessions.Session and
common.Counter. Django also maintains django_migrations and SQLite metadata.

common_counters stores expiring counters and token-owned claims. It contains no
business records or cached customer lists. Platform remains the authority for
customers, orders, billing and services; Portal accesses them through signed HTTP.
Counter keys can contain account or network identifiers and require the same
access controls and retention discipline as session data.

Request budgets reserve a count before admission. Authentication failure budgets
are checked before authentication and recorded after a rejected attempt.
Database errors deny admission. The caller owns the rate-limiting kill switch.

Checkout reserves a claim, publishes the Platform order identifier on success,
and releases only its own pending claim on failure. Completed results survive
worker restarts and replay even after the cart is cleared. Platform also receives
the idempotency key. Webhook and price-seal claims remain reserved throughout
their acceptance windows. An expired owner cannot change another owner's claim.

Default caches remain LocMemCache for preferences, customer lists and local
single-flight coordination. They are not security counter or claim storage.

Deployment runs migrate sessions --noinput, migrate common --noinput, and
check --deploy --fail-level ERROR before serving traffic. portal.E002 verifies
the counter table on the write database. Ordinary checks permit migrations on an
empty database. The native health gate probes /billing/ so admission depends on
the counter store.

Only a confirmed SQLite integrity_check failure permits database recreation.
Other startup failures preserve the database and stop startup. Recreation logs
that sessions, replay protection and idempotency guards were reset.

Expired rows require bounded cleanup with the cull_counters command in container
startup and native scheduled maintenance. This maintenance command must be
available before those deployment hooks are enabled.

## Consequences

Portal needs a persistent writable SQLite volume shared by its workers.
Horizontal deployments must share the same authoritative counter database;
independent container volumes do not coordinate admission or replay protection.

The store uses atomic upserts and preserves first-hit expiry. It participates
in ambient transactions, so a rollback also rolls back the counter operation.
Admission middleware executes outside view transactions.

Model inventory, service parity, deployment order and limited health-route
coverage are enforced by tests. This decision amends the earlier sessions-only
Portal contract while preserving the separation of business data.
