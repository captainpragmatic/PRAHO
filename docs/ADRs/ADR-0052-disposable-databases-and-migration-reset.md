# ADR-0052: All Databases Are Disposable Until the First One That Must Be Preserved

- Status: Accepted
- Date: 2026-10-02
- Authors: PRAHO maintainers
- Related: ADR-0014 (no test suppression), ADR-0050 (Portal infrastructure tables)

## Context

PRAHO is pre-1.0 alpha. On 2026-10-01 we confirmed that no production or staging
database exists. The only databases are local development and E2E SQLite files, and
all of them can be rebuilt from migrations and fixtures.

The Platform had accumulated 149 migration files across 15 apps, and the Portal 3.
48 of the Platform's operations were `RunPython` data migrations. Most of them repaired
rows on databases that do not exist: backfills, canonicalizations and guards against
historical data. 27 test files, plus a helper, rewound the schema with
`MigrationExecutor` or called a migration's function to test those repairs.

`squashmigrations` exists to keep deployed databases compatible with a shortened
history. With no deployed database, it would preserve 48 data migrations for nobody.

## Decision

### The reset

Every migration file in both services is replaced by freshly generated initial
migrations. Django splits apps with circular foreign keys into several initial files.

Objects that only migrations can create are carried forward by hand. Each depends on
the last generated migration of its app:

| Migration | Creates | Backend |
|---|---|---|
| audit 0003, billing 0003, integrations 0002 | nine covering, opclass, GIN and BRIN indexes, SQL copied verbatim | PostgreSQL only |
| customers 0003 | the encryption-context immutability trigger: a plpgsql function and trigger on PostgreSQL, a `RAISE(ABORT)` trigger on SQLite, and a `RuntimeError` on any other backend | both |
| billing 0004 | the RON, EUR and USD currency rows | both |
| settings 0002 | the `billing.default_currency` = RON selling-policy row | both |

The other 42 data migrations only touched existing rows and were dropped, together
with the tests whose only subject they were. That removes a test target. It does not
suppress a failing test (ADR-0014).

`scripts/compare_db_schema.py` compared a database built from the new chain with one
built from the old chain, on PostgreSQL 15 and on SQLite. It covered:
- columns, constraints, indexes, functions and triggers;
- CHECK constraints;
- Django's migration state;
- row counts and seeded contents.

It found three differences, all accepted:
- **The RON currency name.** RON is now named "Romanian Leu". The old chain created it
  with an empty name before its seed ran.
- **One constraint name.** The `encryption_context_id` unique constraint now has
  Django's inline name (`_key`) instead of the old `AlterField` name (`_uniq`). The
  definition is the same.
- **Two model bases.** Two models now record django_fsm's `ConcurrentTransitionMixin` in
  their migration state. `makemigrations` never tracks base-class changes. It creates
  no DDL.

Five deliberate breakages each turned the comparison red: a missing trigger, a changed
index, a changed field default, a missing seed, and a dropped CHECK constraint.

### While every database is disposable

- No backfill, repair or data-fix migrations. A schema change ships as the generated
  migration alone, and existing dev databases are rebuilt.
- Another reset is allowed, under the same rule: carry forward every object that only a
  migration creates, and prove equivalence with the comparator.

### Once a database must be preserved

The first production or staging database, or any database whose rows cannot be
recreated, ends this ADR's disposable phase. From then on:
- the migration history is append-only;
- only `squashmigrations` may shorten it, keeping the replaced migrations until every
  preserved database has applied the squash;
- data repairs become migrations again, with tests.

That change must be recorded by updating this ADR's status.

### The SQLite trigger hazard

SQLite cannot alter most table definitions in place, so Django rebuilds the table, and
a rebuild drops the table's triggers. Any future migration that alters
`customer_payment_methods` on SQLite silently removes the encryption-context trigger,
unless that migration re-creates it.

`tests/customers/test_payment_method_encryption_trigger.py` turns red when that happens.
`tests/common/test_migration_db_objects.py` checks that each object exists on PostgreSQL
and on SQLite, by name. Both run on SQLite in the normal suite and on PostgreSQL in the
integration workflow.

## Consequences

### Migration speed

The reset did not make `migrate` meaningfully faster:

| Backend | Old chain | New chain |
|---|---|---|
| PostgreSQL | 108 s, 184 migrations | 94 to 100 s, 72 migrations |
| SQLite | 102 s, 180 migrations | 100 s |

A `migrate` with nothing to apply takes 1 s, so the cost is in applying the chain, not in
startup. The large generated files dominate: `promotions.0002` alone takes 30 s,
`provisioning.0002` 16 s and `billing.0002` 15 s. The near-equal cost on both backends
points to Django's in-memory migration-state work for hundreds of `AddField` operations,
rather than to DDL. That is an inference, not a measurement.

Every test run still pays this cost to build its database. The suite got faster
anyway, because the removed tests rewound the schema with `MigrationExecutor`. The
payment-method encryption migration test alone took about 15 minutes, for 4 tests.
Full `make test-platform` runs compare as follows:
- **Test execution** (the runner's own figure, without the database build): 1,372 to
  1,452 s for about 10,250 tests in overnight runs on equivalent trees, against 35 s
  for 10,255 tests after the reset.
- **Wall-clock after the reset:** 134 s for the whole run, about 100 s of it building
  the test database. The load average was 4.2 to 6.6 on 8 cores, on 2026-10-02. The
  overnight runs did not record wall-clock time.

Making the remaining database build faster needs a separate decision, such as a
file-backed test database with `--keepdb`, or re-enabling `DisableMigrations`. The
second would skip the trigger and the seeds, so it needs its own analysis.

### Other consequences

- Every existing dev and E2E database must be deleted and recreated. An old database's
  `django_migrations` rows name `0001_initial` and the like, so Django would treat it as
  up to date while its tables differ, without any error.
- Historical documents (the changelog, dated plans and reviews) still name old
  migrations. They describe the history before this reset.
