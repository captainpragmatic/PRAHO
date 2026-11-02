# Row locking and fresh related reads

Tracking: [#805](https://github.com/captainpragmatic/PRAHO/issues/805).
Baseline: `176646ef`; implementation base: `04e1844b`.

## Contract

At PostgreSQL READ COMMITTED, a waiting locking statement can recheck its
updated root with related rows from the statement's earlier snapshot. A second
statement gets a new snapshot. See the [isolation documentation](https://www.postgresql.org/docs/16/transaction-iso.html#XACT-READ-COMMITTED)
and [executor notes](https://github.com/postgres/postgres/blob/REL_16_STABLE/src/backend/executor/README).

Use an ordinary root-only `select_for_update(of=("self",))` when no eager
relationships are needed. Otherwise, inside the existing atomic transaction:

```python
from apps.common.row_locks import lock_many_and_load, lock_one_and_load

order = lock_one_and_load(Order.objects.filter(pk=order_id, customer=customer).select_related("invoice"))
cycles = lock_many_and_load(
    BillingCycle.objects.filter(subscription__customer=customer).select_related("subscription").order_by("period_start")
)
```

The shared implementation resolves the write router once, derives candidate PKs
in an unordered subquery, and locks an outer base-model query in PK order. Joined
filters remain inside the subquery; simply clearing `select_related()` would
leave those joins in the locking query. The second statement clones the original
queryset on the same alias and reapplies its predicates within the locked PK set.
Rows that cease to qualify are excluded; newly eligible unlocked rows cannot enter.
Output ordering, deferred fields, eager loading and prefetches are preserved.

Nonempty batches use two base statements, plus requested prefetches; an empty
lock set needs one statement. Previously evaluated queryset caches are ignored.
`lock_one_and_load()` raises the model's `DoesNotExist` or `MultipleObjectsReturned`.
For an optional unique-PK claim use the bulk API and map an empty list to `None`.

Both APIs support `no_key`, `nowait`, and `skip_locked`; the last two are mutually
exclusive. They require an atomic transaction on the resolved write alias and
reject already-locking, sliced, projected, distinct, annotated/grouped, combined,
correlated, and extra/RawSQL query shapes. Apply any bounded ambiguity check to
the returned list, rather than passing a sliced queryset.

Freshness at reload is not stability through COMMIT. Explicitly protect related
rows whose configuration or ownership must remain stable. Keep domain lock
boundaries and multi-model order in the service. Do not move native or network
I/O into these transactions. `NO KEY UPDATE` protects configuration from edits
while allowing compatible FK references; see [row-lock compatibility](https://www.postgresql.org/docs/16/explicit-locking.html#LOCKING-ROWS).

## Census and enforcement

`make row-lock-census` scans all Platform `apps/`, excluding migrations.
`make lint-row-locks` enforces the completed scope (billing in PR 1, all apps in
PR 2). The shared AST scanner follows either method order, intervening calls,
queryset aliases, reassignment, branches, slices and queryset factories. Clearing
joins and projections remove eager loading; prefetches are separate statements.
Fixtures pin exact discoveries and include the final conditional provider-cleanup
pattern. There are no permanent exemptions for previously safe joined locks.

The historical issue reported 60 sites. The census is regenerated against both
the historical tree and the implementation tree; the historical count is not a
target for the current inventory. New provider-cleanup and certificate/DNS sites
belong in the audit too.

## Billing site ledger (PR 1)

Paths below are relative to `services/platform/apps/`. Locations use stable
function names because line numbers change during the audit. `self` means only
the root model. Unless specified, the change replaces a single joined locking
statement with self-only locking followed by fresh eager loading. Existing
surrounding locks, frozen financial evidence and transaction/I/O boundaries stay
in place. Mechanical normalization does not assert a newly reachable business race.

| Original/current location | Consumer and competing writer | Old -> new targets/order | Requirement and disposition | Proof |
|---|---|---|---|---|
| billing/recurring_billing.py:prepare_due_proformas | Grouping, proforma buyer, mandate validation; auto-pay enrollment, billing edit, service opt-out | Subscription -> Subscription PK order | Already fixed lock/load split extracted; recheck all joined eligibility | renewal subscription concurrency; shared FK/eligibility tests |
| billing/payment_convergence.py:_converge_invoice | Subscription save()/clean() validates mandate ownership; auto-pay enrollment | Subscription -> Subscription PK order | Fresh deferred batch load keeps indirect validation reads batched; public Customer/Subscription boundary already protects mandate changes | recurring lock batches; payment settlement and recurring collection concurrency |
| billing/payment_convergence.py:converge_gateway_success | Gateway facts and document linkage; recurring reservation/convergence | Payment -> Payment | Fresh currency/document data; retain gateway-fact validation | subscription invoice payments; payment settlement |
| billing/payment_convergence.py:recover_unlinked_recurring_attempt (gift) | Gift funding validation; gift convergence | Payment + Currency -> Payment | Remove shared Currency protection; gift path has its own public convergence boundary | gift funding tests; shared-reference lock test |
| billing/payment_convergence.py:recover_unlinked_recurring_attempt (recurring) | Attempt ownership and facts; competing early gateway events | Payment -> Payment PK order | Fresh linkage; retain ambiguity refusal, loading full eligible batch before bounded check | subscription invoice payments |
| billing/payment_convergence.py:converge_local_paid_document | Paid state; document settlement | Payment -> Payment | Existing Customer/document boundary retained | payment settlement |
| billing/payment_service.py:_bind_retry_result_before_gateway | Retry document matching; retry/convergence workers | Retry -> Retry | Optional unique claim, fresh Payment; gateway I/O remains outside | subscription invoice payments |
| billing/recurring_submission_service.py:record_recurring_submission_replay_started | Replay Stripe payload; reconciliation claim writer | Submission -> Submission | Fresh Payment/documents; lease/token/state predicate rechecked | recurring submission/reconciliation tests |
| billing/recurring_billing.py:collect_due_proformas | Saved Stripe method; mandate revocation | Proforma -> Cycle PK order in both phases | Fresh method hint; PaymentService revalidates consent before durable claim | recurring lock batches; recurring collection concurrency |
| billing/recurring_authorization_service.py:set_subscription_auto_payment | Consent and method ownership; authorization completion/withdrawal | Customer -> joined Authorization/Method -> Subscription becomes Customer -> Method -> Authorization -> Subscription | Stability through COMMIT; preliminary FK hint rechecked | authorization tests; renewal/collection concurrency |
| billing/usage_invoice_service.py:generate_invoice_from_cycle | Buyer, tax and credit; signed billing edit | Cycle -> Customer retained | Use returned locked Customer before identity/tax; rating stays before Customer | public billing edit/usage invoice wait regression |
| billing/currency_transitions.py:prepare_currency_offer | Notice recipient, catalog offer; customer edit | Subscription -> Subscription | Fresh notice inputs, frozen terms retained | currency transition tests |
| billing/services.py:convert_to_invoice | Invoice, rendered/stored notification; public GDPR erasure | Proforma -> Proforma | Fresh relationships; buyer snapshot is email authority, not live Customer | invoice email erasure PostgreSQL tests |
| billing/refund_service.py:refund_order | Customer and invoice binding; refund/payment convergence | Order -> Order | Fresh buyer, retain context lock and linkage refusal | refund service/concurrency tests |
| billing/refund_service.py:_get_order | Refund eligibility helper; order updates | Order -> Order | Fresh customer | refund service tests |
| billing/refund_service.py:refund_invoice | Customer and settlement; refund/payment convergence | Invoice -> Invoice | Fresh buyer, retain payment/context order | refund service/concurrency tests |
| billing/refund_service.py:_get_invoice | Refund eligibility helper; invoice updates | Invoice -> Invoice | Fresh customer | refund service tests |
| billing/refund_service.py:converge_gateway_refund | Amount/currency and binding; competing refund events | Payment -> Payment | Fresh Currency, single application and instruction matching retained | refund convergence tests |
| billing/fiscal_correction_service.py:record_provider_storno | Storno currency validation; fiscal correction writer | Already Invoice-only -> Invoice-only | Preserve merged shared-currency fix | provider storno currency concurrency |
| billing/fiscal_correction_worker.py:_claim_communication | Credit note and claim lease; correction worker | Correction -> Correction | Optional unique claim, nullable note, unchanged lease refusal | fiscal correction tests |
| billing/metering_service.py:_update_aggregation_sync | Event meter/subscription/service; event and cycle workers | Event -> Cycle retained | Fresh relationships; exactly-once aggregation | metering concurrency/enforcement tests |
| billing/metering_service.py:close_billing_cycle | Subscription and audit; event/close workers | Cycle -> Cycle | Fresh subscription; Event -> Cycle direction retained | metering services/enforcement |
| billing/metering_service.py:rate_aggregation | Frozen/legacy tariff and cycle currency; rating workers | Aggregation -> Aggregation | Fresh relationships; Cycle -> Aggregation batch order retained | metering gateway regressions |
| billing/subscription_service.py:reactivate_subscription | Explicit Service lock later; cancellation/reactivation | Subscription -> Service retained | Remove unused Service join | subscription lifecycle tests |
| billing/tasks.py:_bind_replayed_recurring_intent | Gateway ID/meta only; replay/convergence | Payment -> Payment | Remove unused currency/document joins | recurring reconciliation tests |
| billing/efactura/service.py:_lock_owned_claim | Finalize accepted ANAF response; submission claim | Fixed on master: Invoice -> Document | Preserve merged lock-order correction | efactura lock-order concurrency |

## Remaining sites (PR 2)

Pending: order confirmation (two phases); domains currency notices, data-zone
locks (two branches), zone import and revision claim, DNS guard, renewal claim,
order fulfilment and post-grace TLD; hosting fulfilment; order service creation
and payment-status handlers (two); cancellation/refund signals (two); promotion
coupon and tender-refund legs (three); account-name certificates; hosted-domain
DNS; bridge cleanup; provisioning reconciliation; ticket closure; conditional
provider cleanup. Preserve intentional joined-row protection explicitly.

Already fixed on master and retained: hostname announcement, usage current-state
and publication, account-sync reads, artifact-cleanup server lock order,
hosting-fulfilment plan retarget handling, provisioning/cancellation ordering and
nameserver domain-only scope. The remaining hosting fulfilment query still needs
normalization. TLD and ServicePlan configuration protection must use explicit
NO KEY UPDATE with through-COMMIT compatibility tests.

## Verification record

In progress. Scanner fixtures failed on the stub and passed after implementation;
the billing scope guard initially found the remaining combined sites. Shared
helper contracts failed on the stub (including the no-SQL unsupported-shape gate).
PostgreSQL workers assert READ COMMITTED and observe `pg_blocking_pids()` for the
exact writer and intended table/statement before allowing COMMIT. Completion
requires focused, gated and full-suite checks, lint/types, and revert proofs for
new behavioral fixes. No migrations or isolation-level changes are included.

Review follow-up: Subscription.save()/clean() consumes the saved method and
authorization indirectly. Its public entitlement regression detects four
standalone relationship reads for two subscriptions before the correction and
one deferred joined batch afterward. Both collection phases, overlapping
settlement/failure Cycle sets and overdue marking acquire Cycle locks in PK
order and preserve their original processing order on reload. A public collection
SQL test verifies both phases; the generic helper tests prove opposite output
orders still acquire locks consistently. Scanner canaries also cover method
argument materialization, negation, compound predicates and assertions.
