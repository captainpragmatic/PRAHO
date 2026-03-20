# ADR-0037: psycopg v3 Migration

## Status
**Active** - March 2026

## Context

PRAHO used `psycopg2-binary` as its PostgreSQL adapter. As of 2024, `psycopg2` has entered maintenance mode: security patches are applied but no new features are planned. The project lead has confirmed the package is effectively frozen.

psycopg v3 (`psycopg`) is the successor library with active development. Key improvements relevant to PRAHO:

- **Native async support**: `AsyncConnection` and `AsyncCursor` are first-class citizens, enabling future async Django views and background tasks without adapter constraints.
- **Connection pooling**: `psycopg_pool` offers both sync and async pools with health checks, replacing the ad-hoc `CONN_MAX_AGE` workaround.
- **Type system**: Server-side binding (`%s` placeholders prepared once) reduces query plan cache misses under PostgreSQL 14+.
- **Active maintenance**: Bug fixes, PG 17 support, and Django 5.x compatibility are tracked upstream.

The migration is low-risk because Django abstracts all psycopg calls through its database backend. Application code never calls psycopg directly — all SQL goes through the ORM or `connection.cursor()`.

## Decision

Replace `psycopg2-binary` with `psycopg[binary]` (psycopg v3) in the platform service dependencies.

### Package change

```
# Before
psycopg2-binary>=2.9

# After
psycopg[binary]>=3.1
```

The `[binary]` extra bundles the compiled C extension (`libpq` wrapper). This matches the previous `psycopg2-binary` install strategy: no system `libpq-dev` required on developer machines or CI runners.

### Django backend

Django 4.2+ includes native psycopg v3 support via the `django.db.backends.postgresql` backend. No backend switch required — the backend auto-detects the installed adapter.

### Synchronous mode only (for now)

Async support is available but not activated. All database access remains synchronous (`psycopg.Connection`). The async path (`psycopg.AsyncConnection`) is available for future use when PRAHO adopts Django async views.

### Connection pooling

`CONN_MAX_AGE` settings remain unchanged. psycopg v3's `ConnectionPool` is not introduced in this migration — it is reserved for a future ADR covering connection pool architecture.

## Consequences

### Positive
- Modern, actively maintained adapter — security patches and PG version support are guaranteed
- Async database access is unblocked for future feature work
- Server-side parameter binding improves query performance under high prepared-statement cache reuse
- `psycopg[binary]` is a drop-in replacement for `psycopg2-binary` in all ORM-mediated code

### Negative
- Raw SQL using `copy` or `notify` requires API changes: psycopg v3 uses `cursor.copy()` and `connection.notifies()` instead of v2's `copy_expert()` and `connection.poll()`
- Any code using `psycopg2.extras` (e.g., `execute_values`, `RealDictCursor`) must migrate to psycopg v3 equivalents (`executemany` with `returning`, `psycopg.rows.dict_row`)
- `django-db-geventpool` and similar psycopg2-specific connection pool packages are incompatible — must be removed before migration

### Neutral
- `%s` parameterized query syntax is identical between v2 and v3 — all existing `RawSQL` and `cursor.execute()` calls are unaffected
- `CONN_MAX_AGE` and persistent connections work identically in psycopg v3
- CI PostgreSQL version requirement is unchanged (PostgreSQL 15+)

## Migration Notes

The only PRAHO-specific change needed at migration time is updating `pyproject.toml`. No application code references psycopg directly. The pre-commit `security-credentials-check` hook was verified to not flag `psycopg` as a sensitive import.

If raw `COPY` or `LISTEN/NOTIFY` usage is added in future, follow the psycopg v3 migration guide at https://www.psycopg.org/psycopg3/docs/basic/from_pg2.html.

## Reference Commit

| Commit | Change |
|--------|--------|
| c78206d4 | Replace psycopg2-binary with psycopg[binary] v3 in pyproject.toml |

## Related

- ADR-0020: Async Task Processing Architecture (Django-Q2 worker pool — async DB access would affect task workers)
- ADR-0015: Configuration Resolution Order (database settings inheritance across base/dev/prod/test)
