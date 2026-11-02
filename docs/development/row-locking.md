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
`make lint-row-locks` enforces all Platform apps (billing was enforced first in
PR 1). It also runs as a dependency of `make lint`. The shared AST scanner follows either method order, intervening calls,
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

## Remaining-application site ledger (PR 2)

All paths are relative to `services/platform/apps/`; test modules are relative to
`services/platform/tests/`. Every mechanical row is also guarded by
`common/test_row_lock_scanner.py:test_platform_has_no_combined_queries`.
Those structural changes retain the existing business controls: they do not
claim that bypassing those controls reproduces a public financial race.

| Historical/current location | Consumer and competing writer | Old -> new targets/order | Requirement and disposition | Proof/control modules |
|---|---|---|---|---|
| api/orders/views.py:confirm_order phase 1 | Tenant, PaymentIntent and payable proforma; order confirmation/cancellation and conversion | Order -> Order | Fresh document; same PI/tenant checks and confirmed replay | orders/test_confirm_order_lock_waits.py; test_confirm_order_pi_validation.py |
| api/orders/views.py:confirm_order phase 3 | Invoice/proforma binding after gateway gap; payment convergence | Order -> Order | Fresh documents; document-change refusal and network gap retained | orders/test_confirm_order_lock_waits.py; test_confirm_order_concurrency.py |
| domains/currency_terms.py:reconcile_domain_currency_notices | TLD price and recipient; catalog/customer updates | Domain -> Domain | Fresh notice inputs; retain frozen domain terms | domains/test_currency_terms_lifecycle.py |
| domains/dns_zone_record_services.py:lock_data_zone account | Account fence only; account operations | Account NO KEY UPDATE -> same | Remove unused Service join; hostname boundary retained | domains/test_dns_zone_records.py; test_dns_zone_concurrency.py |
| domains/dns_zone_record_services.py:lock_data_zone zone | Customer authority from zone; zone/data writers | Zone -> Zone | Remove unused Service join, preserve zone authority | domains/test_dns_zone_records.py |
| domains/dns_zone_services.py:preview_zone_import | Service/customer binding; account retarget/retirement | Account NO KEY UPDATE -> same | Fresh service; unchanged enrollment validation | domains/test_dns_zone_import_service.py |
| domains/dns_zone_services.py:_locked_zone | Optional account/service ownership; account/name writers | Account NO KEY UPDATE -> same | Fresh service, refresh and ownership checks retained | domains/test_dns_zone_import_service.py; test_dns_zone_concurrency.py |
| domains/dns_zone_tasks.py:_guard | Revision and operation lease; revision activation/operation worker | Operation + Revision -> Operation -> Revision | Explicit stability protection through COMMIT; lease and revision checks retained | domains/test_dns_zone_tasks.py |
| domains/operation_services.py:_claim_renewal | Registrar/TLD renewal rules; domain/registrar writers | Domain -> Domain | Fresh inputs; durable intent, preflight and refusal retained | domains/test_durable_operations.py |
| domains/order_fulfilment.py:_lock_line | Line's order state; order status/line workers | Order -> Line retained | Fresh order after optional line claim; order binding preserved | domains/test_domain_staff_fulfilment.py |
| domains/services.py:_expire_post_grace_domains | Grace period; TLD configuration editor | Domain + TLD -> Domain -> TLD NO KEY UPDATE | Stable configuration with compatible new Domain FK references | common/test_configuration_row_locks.py |
| orders/hosting_fulfilment.py:_lock (line) | Order/status/customer; confirmation, cancellation | Order -> Customer -> Line -> Service retained | Fresh order; Service plan is read after its own existing root lock | orders/test_hosting_fulfilment.py; test_hosting_plan_lock_concurrency.py |
| orders/services.py:create_pending_services | Product mapping; product/line writers | Line -> Line PK order | Batch fresh products; no per-line relationship reload | orders/test_orders_services.py; test_staff_line_fulfilment.py |
| orders/services.py:update_service_status_on_payment (lines) | Product and new service bindings; service creation | Line -> Line PK order | Reload after creation; preserve business order and frozen item prices | orders/test_orders_services.py; test_order_payment_recovery_isolation.py |
| orders/services.py:update_service_status_on_payment (services) | Currency and subscription enrollment; currency/service writers | Service PK order -> same | Fresh currencies; retain explicit shared Service batch locks | orders/test_orders_services.py; billing/test_subscription_invoice_payments.py |
| orders/signals.py:_handle_order_cancellation | Separate Service locks; cancellation/refunds | Line -> Service retained | Drop dead join; retain non-null filter and Customer boundary | orders/test_orders_cancellation.py |
| orders/signals.py:_handle_invoice_refunded | Separate Service locks; refunds/cancellation | Line -> Service retained | Drop dead join; retain non-null filter and subscription refusal | orders/test_orders_refund.py |
| promotions/services.py:apply_coupon | Campaign, currency and eligibility; campaign retarget/catalog edits | Campaign -> Coupon retained | Fresh relations; reject retargeted campaign before spending budgets | promotions/test_services.py |
| promotions/tender_refunds.py:_settle_leg | Command/leg projection; duplicate refund callbacks | Payment -> joined Leg/Command becomes Payment -> Command -> Leg | Preserve explicit Command protection and recheck invoice/payment binding | promotions/test_tender_refunds.py |
| promotions/tender_refunds.py:_submit_leg | Durable command and retry intent; refund submissions | Payment -> Leg becomes Payment -> Command -> Leg | Stable instruction; network remains after durable claim | promotions/test_tender_refunds.py |
| promotions/tender_refunds.py:converge_tender_refund | Payment currency and instruction facts; refund callbacks | Refund -> Refund | Fresh payment/currency; exact amount and currency matching retained | promotions/test_tender_refunds.py |
| provisioning/account_name_certificates.py:_claim_attempt | Hostname retirement, attempt and budget; hostname retirement/certificate worker | Certificate + Hostname -> Certificate -> Hostname | Explicit hostname stability; budget and lease checks retained | provisioning/test_account_name_certificates.py; test_account_name_certificate_provenance.py |
| provisioning/hosted_domain_dns_service.py:request_recheck | Service/customer authority and DNS snapshot; account/service writers | Account + Service -> Account -> Service | Explicit Service protection through COMMIT; scope checks precede mutation | provisioning/test_hosted_domain_dns_status.py |
| provisioning/migration_bridge_cleanup.py:_claim | Cleanup lease, account and target binding; completed migration rerun | joined Bridge/Migration/Target -> Account -> both Servers PK order -> Migration -> Bridge | Completed hint gates admission; locked scope rechecked; mismatch rolls back hinted locks; unfinished hint takes Bridge only | provisioning/test_bridge_cleanup_lock_concurrency.py; test_migration_bridge_cleanup.py; test_component_bridge_cleanup.py |
| provisioning/signals.py:_trigger_automatic_virtualmin_provisioning | Task admission and customer ownership; immediate subscription cancellation | Service + Customer -> Customer NO KEY UPDATE -> Service | Recheck ownership and hosting eligibility under lock; preserve deduplication and post-transaction dispatch | provisioning/test_reconciliation_cancellation_lock.py; test_provisioning_signals.py |
| tickets/tasks.py:auto_close_inactive_tickets | Recipient/customer name; customer edits and service requests | Ticket -> Ticket | Fresh customer; unchanged request guard, notification after COMMIT | tickets/test_ticket_tasks.py |
| infrastructure/cloud_destroy_execution.py:_guard | Provider ownership/type and token fingerprint; deployment/provider edits | Deployment -> Deployment | Conditional helper preserves unlocked read path; fresh provider before scope mutation | infrastructure/test_cloud_destroy_execution.py; test_cloud_destroy_service.py |

The provider-cleanup site was introduced after the historical audit. The census
of `176646ef` finds exactly 60 sites and the implementation base `04e1844b`
contains 51 (24 billing and 27 other applications); all historical sites have a disposition in
this document. Counts are evidence for these snapshots, not an allowance for
future exceptions.

## Previously fixed historical sites retained

| Historical location | Current protection and rationale | Competing writer / proof |
|---|---|---|
| billing/efactura/service.py:_lock_owned_claim | Invoice -> Document; claim ownership checked after explicit locks | Submission claim; billing/efactura/test_lock_order_concurrency.py |
| billing/recurring_billing.py:prepare_due_proformas | Prior lock/load split extracted into shared root-only helper, eligibility retained | Enrollment/opt-out; billing/test_renewal_subscription_lock_concurrency.py |
| provisioning/account_hostname_hosting.py:announce_when_live | Hostname/account root locks and fresh related read already separated | Publication/terminal operations; provisioning/test_usage_postgres_concurrency.py |
| provisioning/virtualmin_usage_service.py:current_state | Existing domain lock boundary then fresh related state | Usage publication/terminal writer; provisioning/test_usage_postgres_concurrency.py |
| provisioning/virtualmin_usage_service.py:publish_snapshot | Account identity/terminal fence retained | Restore/delete/usage publishers; provisioning/test_usage_postgres_concurrency.py |
| provisioning/virtualmin_views.py:virtualmin_accounts_sync | Root-only account lock followed by related loading | Account sync/terminal operations; provisioning/test_usage_postgres_concurrency.py |
| provisioning/migration_artifact_cleanup.py:_claim | Removed unused node joins; no source/target acquisition inversion | Migration admission; provisioning/test_migration_artifact_cleanup.py and zero-site guard |
| orders/hosting_fulfilment.py:_lock (Service) | Service root-only lock, then plan read from current FK; retained | Staff plan retarget; orders/test_hosting_plan_lock_concurrency.py |
| provisioning/virtualmin_tasks.py:_validate_service_for_provisioning_secure | Existing Customer -> Service -> Plan split; PR 2 uses recurring Customer boundary and Plan NO KEY UPDATE | Cancellation and plan edit; common/test_configuration_row_locks.py; provisioning/test_provisioning_cancellation_lock_concurrency.py |
| domains/nameserver_changes.py:_claim_resume | Existing Domain-only lock; shared Registrar configuration is not unintentionally locked | Unrelated registration; domains/test_nameserver_registrar_lock_concurrency.py |

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

Observed proof so far:

- PR 1's 633 focused PostgreSQL tests pass. The FK-retarget regression fails when
  the outer base-row lock is replaced with a cleared-join locking query; the
  public billing-edit regression fails again when the Customer lock is moved
  after the fiscal reads (the invoice stores the pre-edit name and email).
- PR 2's cleanup-versus-completed-rerun test produces PostgreSQL's actual
  `deadlock detected` on the old admission. Both participants complete after the
  lock-order correction. Same-bridge claims serialize; unfinished hints preserve
  terminal precedence without node/account locks; changed hints release locks
  even inside an outer atomic transaction.
- The old shared TLD lock blocks an unrelated Domain's `COMMIT`; the old plan
  lock blocks an unrelated customer's Service insert/commit. NO KEY UPDATE lets
  both references commit while a real configuration UPDATE still waits until
  the paused operation releases its lock.
- Reconciliation observes cancellation's exact Customer-lock wait and no longer
  dispatches a provisioning task from its pre-cancellation service snapshot.
  The eventual provisioning worker's existing inactive-Service refusal remains.
- Reverting the four PR 2 behavioral corrections in an isolated clone reproduces
  blocked Service inserts, blocked Domain COMMIT, and actual PostgreSQL deadlocks
  between completed-migration rerun/cleanup and cancellation/reconciliation.
  Restoring the corrections makes all seven unchanged PostgreSQL controls pass.
- The helper rejects a locking subquery before issuing SQL; this refusal fails
  against the earlier helper. An ordinary uncorrelated membership subquery stays
  supported with two statements. The complete helper and public billing-batch
  controls pass together (19 tests).
- Structural normalization uses the zero-site guard plus the existing business
  regressions. Protected payment convergence is not advertised as a newly
  reproduced public mandate race, and erasure proof uses actual rendered/stored
  email rather than a stale model object in isolation.
