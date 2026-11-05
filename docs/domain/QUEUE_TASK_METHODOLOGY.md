# Queue and Task Methodology

Platform owns background business work. It uses Django-Q2 with the ORM broker on the
same `default` database as its business data: SQLite for local development, PostgreSQL
for deployed services. Portal submits business operations through signed Platform API calls.

[ADR-0020](../ADRs/ADR-0020-async-task-processing-architecture.md) records the queue choice.
[ADR-0045](../ADRs/ADR-0045-committed-side-effect-boundaries.md) defines the transaction
boundaries. The [Makefile](../../Makefile) and current settings take precedence over examples here.

## Development and Schedule Setup

`virtualmin-usage-sync` is registered under Virtualmin maintenance at `10 * * * *`
on `praho-cluster`. It dispatches at most one claimed node poll per hour; each job
has a 300-second deadline and a 330-second durable lease. It reads cached usage
over enrolled root SSH, never raw credential-bearing domain listings. Publication
checks ownership, canonical node intervals, mutation watermarks and SSH identity.
Retention removes old readings in bounded batches after 90 days, preserving last-good
pointers. Disable `provisioning.usage_sync_enabled` to stop new polls. The former
`Collect Virtualmin Usage` billing schedule is removed only by its exact owned
name/function; messages already queued are no-ops. Generic service metering excludes
Virtualmin-backed services. No observation creates a billable usage event.

From the repository root:

```bash
make install
make dev
```

`make dev` builds both services' CSS and starts Platform on port 8700 and Portal on 8701.
Its `dev-platform` target runs migrations, `setup_initial_data`, and sample-data generation,
then starts `qcluster` in the background. Stopping that target stops its worker process.
Worker output goes to `services/platform/django_q.log`.

Schedules are database rows. Recreate them after rebuilding a disposable database;
an application restart alone does not erase them. `setup_initial_data` calls the consolidated
`setup_scheduled_tasks` command. Each category's setup function owns creation and any
reconciliation of its schedules; rerunning setup is not a blanket reset of existing rows.

For manual management commands, activate the repository's per-OS virtualenv
(`.venv-darwin` on macOS, `.venv-linux` on Linux), then work from `services/platform/`:

```bash
python manage.py setup_scheduled_tasks --settings=config.settings.dev
python manage.py setup_scheduled_tasks --virtualmin-only --settings=config.settings.dev
python manage.py qcluster --settings=config.settings.dev
```

The last command runs a worker in the foreground. Use it when a worker is not already running;
the normal `make dev` flow already starts one.

Choose at most one category flag:

| Flag | Setup scope |
|---|---|
| `--virtualmin-only` | Virtualmin provisioning and maintenance |
| `--security-only` | User security |
| `--billing-only` | Billing/usage, e-Factura, issuer recovery, FX and gift funding |
| `--efactura-only` | e-Factura only |
| `--orders-only` | Order processing |
| `--status-only` | Integration/system status |
| `--audit-only` | Audit integrity, retention and export maintenance |
| `--tickets-only` | Ticket lifecycle |
| `--domains-only` | Domain lifecycle |

See the [command](../../services/platform/apps/common/management/commands/setup_scheduled_tasks.py)
for registration and the domain task modules for actual intervals and feature gates.
For example, audit-chain anchoring is registered only when its ledger flag is enabled.
Billing setup can refuse an unsafe legacy-renewal cutover; resolve its reported prerequisite
using the [recurring billing runbook](RECURRING_BILLING.md).

### Paid hosting plan-change ownership

Billing setup registers four five-minute schedules independently of the new
acceptance flag:

| Schedule | Durable entrypoint |
|---|---|
| `billing-plan-change-payments` | `apps.billing.plan_change_payment_service.recover_plan_change_payments` |
| `billing-scheduled-plan-changes` | `apps.billing.plan_change_lifecycle.activate_scheduled_plan_changes` |
| `billing-plan-change-financial-review` | `apps.billing.plan_change_review_service.sweep_financial_reviews` |
| `billing-plan-change-fulfilment` | `apps.billing.plan_change_operations.sweep_plan_change_fulfilment` |

A queue message is a wake-up signal, never charge/application authority. Payment
attempts own immutable payloads, the original idempotency key and durable leases.
Unknown outcomes keep that identity; neither task timeout nor redelivery permits
another PaymentIntent. Native completion is reconciled from current receipt
evidence after financial locks have been released. The fulfilment sweep also
recovers pending phase notices, with per-record backoff so one failed service or
render does not starve unrelated work.

That same operation context emits one HIGH/review-required staff audit event when
a confirmed, committed downgrade is already due and remains `limits_attention`.
`staff_escalated_at` is an append-only technical marker committed with the event;
it is not a customer-delivery receipt. Marker-only saves publish no customer phase
notice. The existing staff review queue owns acknowledgement, and a failed audit
insert leaves the marker unset so a later sweep retries.

Payment-first dispute/refund processing appends a durable `PlanChangeReviewEvent`
and queues its consumer only after commit. The consumer enters each existing
document context separately, rather than taking document locks while retaining
the original Payment lock. Coverage checks reject disputed source facts before
the event worker catches up.

`PlanChangeNotice` owns one phase obligation and links at most one stored
`EmailLog`; duplicate queue delivery and email-log retention do not reopen it.
Operational service preferences and final owner/recipient/privacy/phase checks
still apply. Provider submission has no exactly-once delivery guarantee.

Disabling `billing.hosting_plan_changes_enabled` stops new acceptance/first claims,
not these schedules or already-issued payment/webhook/native recovery. Do not
discard pending broker messages or downgrade workers as a substitute for cancelling
an actual processor intent. See [ADR-0074](../ADRs/ADR-0074-paid-hosting-plan-changes.md)
and [recovery](../deployment/PLATFORM_RESTORE.md#hosting-plan-change-recovery).

## Deployed Workers

Use the supported [deployment procedures](../deployment/DEPLOYMENT.md), with
`config.settings.prod` or `config.settings.staging` and the operator's deployment environment.
Do not substitute development settings on a deployed database.

| Runtime | Setup and worker |
|---|---|
| Native Ansible | Deployment runs `setup_initial_data`; systemd runs `praho-qcluster` from the Platform directory and loads the operator environment file. |
| Production Compose stacks containing Platform | Platform entrypoint runs migrations and `setup_initial_data`; a separate `qcluster` service runs the Platform image after Platform becomes healthy. |
| Portal-only stack | No Platform worker; the remote Platform deployment must operate its own worker. |

The local `make docker-dev` stack defines no `qcluster` service. Run a separate worker in
that development environment when exercising asynchronous work.

Inspect native worker state and logs on the deployed host:

```bash
systemctl status praho-qcluster
journalctl -u praho-qcluster -f
```

For Compose, from the checkout holding its configured deployment environment:

```bash
./deploy/scripts/deploy.sh single-server --env prod --logs
```

This follows stack logs, including the worker. Use the matching deployment type/environment
for a different stack. Registration of a schedule is not evidence that a worker executed it.

## Queue Configuration and Retries

[Platform base settings](../../services/platform/config/settings/base.py) define
`Q_CLUSTER_BASE` and `Q_CLUSTER`. Current defaults are:

| Setting | Value | Meaning |
|---|---|---|
| `orm` | `default` | Queue messages use the business database. |
| `workers` | 2 | Worker processes in the cluster. |
| `sync` | False | Enqueued work runs asynchronously. |
| `timeout` | 300 seconds | Default task execution budget; some domains supply a longer one. |
| `retry` | 14,400 seconds | ORM broker visibility interval before an unacknowledged message can be delivered again. |
| `catch_up` | False | Do not replay every missed scheduled occurrence after downtime. |
| `save_limit` | 1,000 | Configured saved-result limit; not a retention policy for business records. |

The visibility interval is chosen to exceed long-running task budgets (node deployment can
take three hours). A task's execution budget must remain below that interval, or it can be
redelivered while its first execution still runs. Broker `retry` is not an application retry
count or exponential-backoff policy.

Use each domain's retry/reconciliation service. Virtualmin uses durable job rows and
`process_failed_virtualmin_jobs`; billing and provider issuance have their own state and
retry budgets. Do not pass an invented `retry=` option to `async_task`.
A returned `{"success": False}` is an ordinary Python return, not an exception that
automatically requests a queue retry. Some tasks deliberately acknowledge failures or
expire old requests, such as password-reset mail. Inspect both queue outcome and domain state.

## Enqueueing and Commit Boundaries

[Queue helpers](../../services/platform/apps/common/queue.py) expose `queue(callable, ...)`
and `queue_by_name(dotted_path, ...)`; both delegate to Django-Q2 `async_task`.
A returned task ID establishes enqueueing, not completion of the business operation.

Follow the domain's established boundary:

- **Intent and message in one transaction:** with the ORM broker on `default`, write the
  durable intent and enqueue inside `transaction.atomic()`. Backup/restore admission in
  [virtualmin_service.py](../../services/platform/apps/provisioning/virtualmin_service.py)
  forces `sync=False` so provider work cannot execute within that admission transaction.
- **Work following an aggregate commit:** enqueue through `transaction.on_commit()` and
  retain a compensating sweep for a crash or enqueue failure after the commit. Provisioning
  reconciliation uses this convention in
  [virtualmin_tasks.py](../../services/platform/apps/provisioning/virtualmin_tasks.py).
- **Provider mutations:** commit the domain claim before network I/O and persist the outcome
  afterward. An ambiguous timeout must remain reconcilable; it does not prove nothing happened.

Moving the broker away from the business database changes the first convention's guarantee.
Do not replace either convention with a generic enqueue recipe.

## Concurrency and Idempotency

[Node maintenance](../deployment/NODE_MAINTENANCE.md) publishes the exact window revision,
resource identity and execution token atomically with its ORM task. The leaf records issued intent
before native I/O and checks the business result, rather than Django-Q's task-success flag.
Only proved-unissued claims can expire; provider acknowledgment or an uncertain command retains its hold.
Maintenance notices link one durable intent to the existing encrypted EmailLog. Configuration retries
reuse that pending intent; provider retries reuse the same log, claim and attempt budget, with preference,
recipient, revision and current ownership checked at every final dispatch boundary.

Use durable domain state, conditional updates or row locks, unique operation identities,
and provider idempotency keys where the integration supports them. A worker can be redelivered
or die after the external action succeeds. Retrying must recover the same operation.

For a short expiring claim, the implemented
[counter helper](../../services/platform/apps/common/counters.py) provides atomic
`claim(key, ttl_seconds, token)` and token-owned `release(key, token)`. This illustrative
shape is for repeatable local work, not a new registered task:

```python
from secrets import token_urlsafe

from apps.common import counters

token = token_urlsafe(32)
key = "example:repeatable-local-work:resource-id"
if counters.claim(key, ttl_seconds=300, token=token):
    try:
        ...  # Local work that tolerates repetition after lease expiry.
    finally:
        counters.release(key, token)
```

A check followed by `cache.set()` is not an atomic claim. Token-owned release prevents an
expired worker from deleting a newer owner's claim, but expiry does not stop the old worker.
Use the domain's durable claim/reconciliation protocol for chargeable or destructive work;
a lease alone cannot guarantee exactly-once effects. Store errors as errors, retain ambiguous
provider outcomes for review, and keep credentials and personal payloads out of queue logs.

## Hosting warnings and raise expiry

The hourly usage publisher creates owner-scoped warning intents inside its account
transaction. It does not lock customers or delivery logs there. The separate
five-minute `hosting-warning-deliveries` sweep groups eligible intents and links
each delivery version to one encrypted EmailLog before queueing on commit. Final
dispatch rechecks current owner, source period, preferences, hard suppression,
operational and pending limits, native mail ownership and the exact stored body.
Refuse and rebuild only proven undispatched versions; uncertain provider acceptance
retains its original obligation.

The existing hosting-limit dispatcher materializes due raise expiry before
selecting pending applications, including when new raises are disabled. Native
work uses current canonical ownership, immutable issuance, capacity reservations
and fencing. Expiry removes only preauthorized temporary capacity and never
reenables an account or changes billing. Follow the
[warning and relief runbook](../deployment/HOSTING_USAGE_WARNINGS.md) for enablement,
delivery diagnosis and recovery.

## Monitoring and Troubleshooting

Open Platform **Settings → Automation & Schedules** at `/settings/automation/`.
It shows schedules, next-run times, queue depth, and recent task outcomes. It matches each
schedule's function against the latest 200 stored task rows, so an absent result is not proof
that the schedule never ran. Django admin is disabled; `/admin/django_q/` is not a monitoring UI.

For work that does not complete:

1. Check the worker process and its logs in the runtime above.
2. Check the schedule's function, next run, domain feature gate and registration output.
3. Inspect the task result and the durable domain record, including its claim/retry state.
4. Reconcile an uncertain provider outcome through the domain runbook before resubmitting.

Keep failure evidence while investigating. Do not clear failed-task rows or operation
identities as a recovery procedure. PostgreSQL concurrency tests, not SQLite row-lock
assumptions, establish the deployed locking guarantees.
