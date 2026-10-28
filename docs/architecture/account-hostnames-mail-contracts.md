# Hosted mail contracts (ADR-0061 Phase 5)

These rules bind every component that enables hosted mail, changes mailboxes, publishes mail DNS, configures node mail
or runs a native mail action. Hosted mail stays opt-in per domain. Mail-enabled moves and recoveries stay refused until
the held-restore and bridge rules of the [execution plan](account-hostnames-dns-mail-plan.md) are proven.

## 1. Shared rules

### 1.1 Results, retry permission and effect certainty
- Services return `Result[T, str]` with fixed public codes. A result from a native action or a DNS provider carries a
  `Retriability`.
- `Retriability` only says whether another attempt is **permitted**. It never says whether an effect exists.
- Every intent row persists an **effect marker** `effect ∈ {none, possible, applied}`, plus `inflight` (the identity of
  the call in progress). Intent rows are a mail operation, a mailbox change and a node mail job.
  - Before an effect-capable native call or DNS write is dispatched, `inflight` is recorded.
  - A definitive success sets `applied`.
  - An UNKNOWN result, a refusal from a stage outside `PRE_WRITE_STAGES` (§6.4), or lease expiry while something is in
    flight sets `possible`.
  - A refusal from a pre-write stage leaves the marker unchanged.
  - The marker never decreases. `prepare_mail_domain` is effect-neutral: its only effect is an unused staged key.
- **Release rule.** A transition that releases an exclusion (`cancelled`, `failed`, superseded, or a closed node job) is
  allowed only when one of these holds:
  1. `effect == none`;
  2. every effect is reconciled. That needs all three of:
     - the native journal of the identity reports `absent`, `completed` or `released`;
     - every DNS outbox row bound to the intent is terminal, with its applied and absent records recorded;
     - the observed end state matches the configuration mode.

  Otherwise the row stays `needs_review` (or `attention` for node jobs) and keeps its exclusion.

### 1.2 Identity, fencing and quiescence
- Every effect-capable native action receives a UUID persisted before dispatch, and retries reuse it. A new intent or a
  new node-job cycle gets a new identity.
- The native runner refuses a mutating action without an identity (`mail_operation_identity_required`). Only
  `inspect_node` and `inspect_domain` may run without one.
- Every result write is a compare-and-set on `(pk, status, lease_token, lease_expires_at > now)` under the canonical
  locks. An expired owner never finalizes.
- Staff actions and sweeps act only on rows without a live lease. Their first step reconciles the original identity.

### 1.3 Lock orders
- **Mail:** Account → Server → Name (`lock_for_publication`) → Service → MailConfiguration → MailOperation →
  MailboxChange → Zone → ZoneOperation → Record.
  - A path that needs only some of these rows takes them in this order.
  - Generic zone paths never lock mail rows.
- **Node mail jobs:** Server → Job.
- No database lock is held across Ansible, DNS provider or resolver calls. The pattern is: persist the intent, commit,
  do the I/O, then re-lock, compare-and-set and record.

### 1.4 Audit
State changes are audited as `configuration_changed`, with `metadata.component` set to `hosting_mail`,
`hosting_mail_node` or `hosting_mailbox`. Receivers live in `virtualmin_mail_signals.py`.

## 2. Enrollment

### 2.1 The confirmed plan
The owner confirms one plan. It is never rewritten, and `plan_sha256` is the SHA-256 of its canonical JSON.
```python
class MailSlotState(TypedDict):          # always all three slots: dkim, spf, mx
    slot: Literal["dkim", "spf", "mx"]
    name: str; record_type: Literal["TXT", "MX"]
    before: list[dict[str, object]]      # complete RRset observed while planning
    desired: list[dict[str, object]]     # complete RRset after enrollment (== before when no write is needed)

class MailEnrollmentPlan(TypedDict):
    version: Literal[2]; kind: Literal["hosted_mail"]; intent: Literal["enable", "disable"]
    dns_path: Literal["managed", "external"]
    native: dict[str, object]            # node_hostname, profile, domain_id, owner, dkim{selector, record_name, record_value}
    slots: list[MailSlotState]
    changes: dict[str, object]           # sparse deltas, for display only
    roster: dict[str, object]            # enable: mailboxes [{local_part, quota_mb}] (at least one), aliases [{local_part, targets}]
    spf_receipt: dict[str, object]       # public summary of a fresh SPF safety receipt
    local_delivery_notice: str
    disable: dict[str, object] | None    # disable: replacement MX and enrollment provenance
```
The roster holds between 1 and `ServicePlan.email_accounts` mailboxes. A limit of `None` or 0 refuses the proposal with
`mail_mailbox_limit`. Passwords are entered at confirmation. They are never part of the plan.

### 2.2 Slot states
Each observation classifies every slot as `before`, `desired` or `other`; a slot whose `before` equals its `desired`
counts as both. Observations are compared slot by slot, never by the whole-zone digest.

| Point | dkim | spf | mx | Otherwise |
|---|---|---|---|---|
| Before claim, managed DNS | before | before | before | cancel `mail_plan_changed` |
| Before claim, external DNS | desired | desired | before | still `before` → defer `mail_dns_records_pending`; `other` → cancel |
| Before native enablement | desired | desired | before | park `mail_plan_changed` |
| Before the MX write or MX instruction | desired | desired | before | park |
| Final verification | desired | desired | desired | park `mail_readiness_unproven` |

### 2.3 Preparation
1. **Request.** `request_mail_proposal(account, *, actor, request)` runs under the canonical locks.
   - The request is `MailEnableInput` (the roster) or `MailDisableInput` (the replacement MX).
   - Owner admission, the retained-bridge check (§2.9) and node capability must all pass.
   - It stores `proposal = {version: 2, state: "preparing", request_id, intent, actor_id, generation, binding, input,
     prepare_until}` on the mail configuration. That replaces any earlier proposal.
2. **Worker.** The proposal worker:
   - runs `prepare_mail_domain(request_id=…)` for enable;
   - observes every slot;
   - takes a fresh SPF receipt (§3.4);
   - builds the plan.
3. **Staging.** A compare-and-set stages the plan only while all of these hold: the proposal is still `preparing` with
   the same `request_id`, `prepare_until` has not passed, the account generation is unchanged, and admission still
   passes. Otherwise the result is `mail_preparation_stale` and nothing is written.

Preparation takes no account exclusion. A staged proposal must be confirmed within 20 minutes.

### 2.4 Checkpoints and stages
Enable checkpoints: `claimed → preflight → dns_auth_inflight → dns_auth_verified → native_inflight → native_verified →
roster_inflight → roster_verified → mx_inflight → mx_verified`. Each `*_inflight` checkpoint is recorded before any
dispatch. A step that writes nothing still passes its checkpoints and records `{"write": "none"}`.

| Stage | Action | Exit on failure |
|---|---|---|
| Confirm | `request_mail_enrollment(..., roster_secrets)` creates the queued operation and a `held` roster change holding the encrypted passwords | existing refusals |
| Before claim | Slot states (§2.2) and a proven node certificate | defer 15 min; 24 h after creation → `cancelled/mail_prerequisites_expired` |
| Preflight | Run `prepare_mail_domain` again, with the same DKIM as the plan, and take a fresh SPF receipt | mismatch: cancel only while `effect == none`, otherwise park |
| Authentication | Managed DNS: the auth outbox row (dkim, spf), then wait `dns_auth`. External DNS: no write | UNKNOWN → park `mail_dns_outcome_unknown` |
| Native | Re-check the slot states, then `enable_mail_domain(identity=operation.pk)`. Local delivery stays **deferred** (§2.6) | §2.7 |
| Roster | `run_roster_change` runs the held change inline under the operation lease: create mailboxes and aliases, prove IMAPS login, open local delivery, prove local routing | park, withdrawing first (§2.6) |
| MX | Re-check the slot states. Managed DNS: the MX outbox row. External DNS: show the exact MX RRset. Then wait `mx` | expiry → §2.5 |
| Finish | Observe the native domain and all slots outside the transaction. Then, under the locks: write `readiness` with `provenance`, call `enable_hosted()`, mark `completed` | park `mail_readiness_unproven` |

Rules for the finish step:
- `native_mail_ready` requires all of: mail enabled; matching domain id and owner; the confirmed DKIM; unexpired
  certificates for every mail service; and every roster mailbox present and enabled.
- It never reads the node's own `ready` field, which is always false by design.
- Readiness older than one hour is stale.

DKIM and SPF are published before native enablement, and MX is always last. The DKIM record has no signer until
enablement. The SPF change takes effect at once, so it is published only with a fresh, bound SPF receipt.

### 2.5 Waits
```python
class MailWait(TypedDict):
    kind: Literal["dns_auth", "mx", "retire_ttl", "queue_drain"]
    started_at: str; deadline: str; next_observation_at: str
    expected: dict[str, str]             # slot -> sha256 of the expected RRset, or {"queue": "empty"}
```
- **Storage.** Waits live in `operation.result["waits"]`.
- **Replay.** Re-entering a wait reuses its stored start and deadline.
- **Deadlines.** `dns_auth` and `mx`: `provisioning.mail_dns_wait_hours` (72). `retire_ttl`: the largest replaced MX
  TTL. `queue_drain`: `provisioning.mail_queue_drain_hours` (120).
- **Expiry** keeps every effect and the exclusion, and parks `mail_<kind>_wait_expired` through the withdrawal rule.

### 2.6 Local delivery
- **Deferred at enablement.** Enabling installs a per-domain Postfix `retry:4.3.2` transport entry, so every delivery to
  the domain is queued and never bounced. The acceptance probe uses an address-specific exception.
- **Opened by the roster.** The roster change removes the entry and flushes the queue, but only after every mailbox has
  proven its IMAPS login. It then proves local routing with `sendmail -bv`. MX is published only after that proof.
- **Withdrawal before parking.** An enable operation that parks after `native_verified`, while MX is not yet
  authoritatively ours, first runs `disable_mail_domain(mode="withdraw")` under its live lease, with identity
  `uuid5(operation.pk, "withdraw")`.
  - Withdrawal removes local acceptance and the deferral, keeps every mailbox and message, and answers inbound `RCPT`
    for the domain with 450.
  - Queued messages then route through DNS to the current provider.
  - A failed or uncertain withdrawal parks `mail_withdraw_unproven`.
  - A park from `native_inflight` runs no withdrawal; the staff release path reconciles it first.
- **Consent text:** "When hosted mail is switched on, messages sent to @domain from websites on this server are held
  on this server, not bounced, until your new mailboxes have been created and checked. They are then delivered to those
  mailboxes. From then until your MX change is seen, such messages go to the new mailboxes, not to your current
  provider. If setup stops, or the MX change is not seen within N hours, local delivery is withdrawn: held and later
  messages go to your current provider through DNS, messages already delivered stay in the new mailboxes, and
  deliveries to this server from outside are deferred, not rejected."

### 2.7 Failure and resolution

| Event | Retry | Effect | Outcome |
|---|---|---|---|
| Prerequisite missing before claim | defer | none | `queued` |
| `other` slot state before claim | no | none | `cancelled/mail_plan_changed`, releases |
| Pre-write native refusal (busy, in progress) | within the lease, ≤ 30 min | unchanged | then `needs_review/mail_native_unavailable` |
| NOT_RETRIABLE at a pre-write stage | no | unchanged | `failed` if `effect == none`, else `needs_review` |
| NOT_RETRIABLE after a write, or UNKNOWN | no | possible | `needs_review` |
| DNS row UNKNOWN or parked | no | possible | `needs_review/mail_dns_outcome_unknown` |
| Slot state violated at native enablement or MX | no | unchanged | `needs_review/mail_plan_changed` |
| Lease expiry with something in flight | no | possible | `needs_review/mail_execution_ownership_expired` |

- **Reconcile-only DNS ticks.** While the parent is `needs_review`, the outbox tick only reconciles. It reads the
  provider inventory, looks up in-flight records by owner tag, and never writes to the provider.
  - When every intended record is proven present or proven absent, the row becomes terminal (`completed`, or `failed`
    with the applied and absent lists).
  - The generic zone-operation retry refuses `mail_records` rows with `mail_records_recovery_owned`.
- **`recover_mail_dns(operation_id, *, actor)`.** This is the only way to resume DNS writes. It requires:
  - `needs_review` with no live lease;
  - error code `mail_dns_outcome_unknown` or `mail_dns_auth_wait_expired`;
  - a parked or waiting outbox row;
  - current eligibility and slot states.

  In one transaction it moves the parent to `running` at the same checkpoint and the row to `waiting`.
- **`supersede_mail_operation(operation_id, *, actor)`.** It requires all of:
  - no live lease;
  - the release rule;
  - a native end state compatible with external mail (never enabled, or withdrawn);
  - every bound outbox row terminal, with its evidence copied to the operation.

  The zone exclusion lifts only when the outbox row is terminal. The account exclusion lifts only at supersede.
- **The roster change follows its operation.** Every terminal transition of an operation also terminalizes its roster
  change in the same transaction. That is allowed only while the roster's own marker is `none` or its journal is
  reconciled.

### 2.8 Disable
- **Planning branch.** The disable plan has its own planning branch, with the owner-supplied replacement MX.
- **Removal.** It removes only material this enrollment created, according to the `provenance` stored in readiness:
  `spf_include_added`, `dkim_record_created`, `mx_before` and the record ids.
- **Checkpoints.** `claimed → preflight → mx_inflight → mx_verified`, wait `retire_ttl`, then `native_inflight`
  (`disable_mail_domain(mode="retire")`, waiting `queue_drain` while the domain's queue is not empty), then
  `native_verified → dns_auth_inflight → dns_auth_verified`. Finally write `retirement`, call `disable_hosted()` and mark
  `completed`. Node DKIM keys are kept.

### 2.9 Retained bridges
- Proposal, confirmation, claim, renew and checkpoint all refuse while the account has a `MigrationBridge` whose status
  is not `torn_down`.
- The check reads the bridge row itself, never `previous_ttl`. That value is cleared before teardown, and a cutover
  whose TTL lowering was skipped never sets it.

## 3. Mail DNS publication

### 3.1 Outbox rows
- **One row per group and direction.** Each slot group gets its own `HostedZoneOperation(kind="mail_records")`: `auth`
  (dkim, spf) and `mx`, in each direction. A row's identity is recorded in the mail operation as
  `zone_operation_ids[group]`.
- **Revisions.** Each row creates the next zone revision.
- **Written records** get `managed_by="praho"`, `managed_slot` ∈ {`mail_dkim`, `mail_spf`, `mail_mx`} and
  `evidence = {"mail_operation_id", "previous": {rdata, ttl, managed_by, managed_slot}}`.

### 3.2 The `mail_records` handler
- **Dispatch.** The zone-operation step dispatches `mail_records` to its own tick, never to the generic apply path.
- **Scope.** The tick touches only the record ids in its evidence.
  - It refuses while any other zone record is pending by content: `desired_deleted`, or `rdata`/`ttl` different from
    the applied values.
  - On completion it advances the untouched records' and the zone's applied revision in one transaction.
- **Lock order.** Account → Name → MailOperation → Zone → ZoneOperation → Records.
- **I/O.** The tick persists `record_<slot>_inflight` and commits, calls the provider outside any transaction, then
  re-locks and compares-and-sets against the zone-operation lease.
  - An UNKNOWN create is resolved by owner-tag lookup and is never POSTed again.
- **Writes.** A tick writes only while the parent mail operation is `running` or `awaiting_dns`, at the matching
  checkpoint, with the same `plan_sha256`. While the parent is `needs_review`, it reconciles only (§2.7).

### 3.3 Source revalidation
- `observe_managed_mail_dns_source(..., bound_operation_id)` tolerates a live `mail_records` row only when that row
  belongs to the bound operation.
- For that row, it accepts only the row's own unapplied records.
- Every other live zone operation refuses the observation.

### 3.4 SPF safety
- **Analysis.** `analyse_spf_proposal` runs fresh at preparation, at preflight, before external instructions are shown,
  and before the auth row's first write. `check_spf_receipt` runs immediately before the provider write, inside the
  receipt's validity.
- **Dependencies.** The receipt's dependencies must not intersect any planned slot change (MX included) or any zone
  record that is pending by content. Otherwise the result is `mail_spf_dependency_changed`, before any write.
- **External DNS.** The same checks apply to the owner's published SPF before claim.

## 4. Mailbox changes

### 4.1 Preconditions and states
- **When a change may run.** A mailbox change is short. It runs only while all of these hold:
  - the account and service are `active`;
  - the account has no retained bridge;
  - the mode is hosted. An enrollment-owned roster change is exempt from this one.
- **Fields.** `VirtualminMailboxChange` stores `kind`, `address`, a non-secret `payload`, `secret` (an encrypted map of
  passwords, kept until the change is terminal), `effect`, `inflight`, the stored public `receipt` and the lease fields.
- **Statuses.** `held`, `pending`, `applying`, `needs_review`, `applied`, `failed`, `cancelled`.
- **Open changes.** A configuration has at most one open change (`held`, `pending`, `applying` or `needs_review`).

### 4.2 Exclusion
- **Two-sided.** `account_has_active_operation` counts an open change, so moves, restores, backups and deletes refuse
  while one exists, and the reverse holds too.
  - `ignore_mail_operation_id` also ignores the operation's own roster change.
  - `ignore_mailbox_change_id` ignores exactly one change, by primary key.
- **Suspension** yields only to an `applying` change. `suspend_account` locks the Account row, refuses while a change
  is `applying`, and starts its suspend job in the same transaction; the state reconciler also yields to an `applying`
  change. A change claim runs under the Account lock and refuses while the account or service is not `active`, or while
  a suspend or unsuspend job is running.

### 4.3 Admission
Admission runs under Account → Server → Name → Service → Configuration → Change.
1. The actor is an active `owner` or `tech`; otherwise `mail_forbidden`.
2. The mode is hosted; otherwise `mail_not_hosted`.
3. The account and service are active; otherwise `mail_mutation_account_suspended`.
4. No retained bridge; otherwise `mail_mutation_bridge_retained`.
5. No other open change; otherwise `mail_mutation_pending`. No other account operation, open mail operation or restore
   hold; otherwise `mail_operation_active`.
6. The local part matches `[A-Za-z0-9_.+%=-]{1,64}`, and the password and quota bounds hold.
7. A create reserves capacity: it is refused when observed mailboxes + 1 exceeds `email_accounts`. A limit of `None`
   or 0 refuses. A delete credits nothing until it is applied.
8. Alias targets must be enabled local mailboxes from the last applied inventory. A target that is an alias, forwards
   elsewhere or is external is refused with `mail_alias_target_invalid`.
9. A password change on a locked mailbox requires `confirm_unlock`; otherwise `mail_mailbox_locked`.
10. A replayed submission returns the existing change. A different payload under the same submission is
    `mail_submission_conflict`.

### 4.4 Worker, recovery and replay
- **Claim.** The claim re-runs admission steps 1–5, exempting only its own change, then compares-and-sets
  `pending → applying` with a 15-minute lease.
- **Native call.** `apply_mail_change` runs outside any transaction, with identity = the change's primary key. Every
  result write requires the matching live lease.

| Result | Status | Effect |
|---|---|---|
| Ok | `applied`: receipt stored, usage updated from the receipt, secret cleared | applied |
| RETRIABLE refusal before a write | `pending`, +5 min, at most 12 attempts | unchanged |
| NOT_RETRIABLE refusal before a write | `failed` if `effect == none`, else `needs_review` | unchanged |
| Refusal after a write, or UNKNOWN | `needs_review`, secret kept | possible |

- **Sweep.** Every 5 minutes:
  - `applying` with an expired lease → `needs_review/mail_mutation_ownership_expired`;
  - a lost `pending` dispatch is dispatched again.
- **Staff replay.** It starts with the read-only `query_mail_operation(identity)`:
  - `completed` finalizes read-only from the stored receipt;
  - `absent` re-runs full admission, then applies under the same identity, or cancels;
  - `applying` resumes only after active-state admission and the suspension fence. Until then, nothing is dispatched.
- **Native fence.** On a disabled domain the native side refuses an effectful resume with `mail_domain_suspended`.

## 5. Node mail jobs

### 5.1 Jobs and cycles
- **Row.** A node mail job is a `VirtualminProvisioningJob` with `operation="configure_mail_node"`, `account=None`, and
  at most one open job (`pending`, `running` or `attention`) per server. Each row is one cycle.
- **`parameters`.** Phases (`["setup","certificate"]` or `["upgrade","certificate"]`), a per-phase UUID persisted at
  insert, and a 3600 s budget.
- **New cycles:**
  - a server not yet configured opens setup;
  - a configured server whose last completed cycle is older than 24 h opens upgrade-then-certificate. On a current node,
    the upgrade reports `unchanged`.
- **Capability.** Enrollment reads node capability only through the database query `node_mail_capability(server)`.

### 5.2 Outcomes

| Result | Next |
|---|---|
| Phase succeeded | next phase, or `completed` |
| Certificate candidate unproven, or `retained_previous` | pending +1 h, same UUID; missing TLS defers mail only |
| `mail_node_bundle_upgrade_required` | insert an upgrade phase (once per row); the certificate keeps its UUID |
| RETRIABLE refusal before a write | pending +5 min; after 24 attempts → `attention/mail_node_retries_exhausted` |
| NOT_RETRIABLE before a write, with `effect == none` | `failed` |
| NOT_RETRIABLE after a write, or any refusal while `effect != none` | `attention`, effect `possible` |
| UNKNOWN, or budget expiry | `attention`, effect `possible`, UUIDs kept |

- `mail_operation_busy` is RETRIABLE only together with the effect marker. A busy reply never lowers the marker.
- The generic job paths exclude `configure_mail_node`: claim expiry, budget expiry, failed-job retirement, and staff
  resolve.
- Mail node jobs close only through `close_node_mail_job`, under the release rule.
- Web deployment requests a job after node activation and never fails because of it.

### 5.3 Resuming a certificate operation after the shipped helpers change
This applies when a certificate operation was interrupted and the shipped helpers now differ from the installed bundle.
- **Trust checks**, under the node lock and with no writes: `/usr/lib/praho/mail` and every parent directory are real,
  root-owned and not group- or other-writable, and every installed bundle file matches the digest in the operation's
  staged `before.json`.
- **Copy and hand-over.** Resume copies those exact bytes into `/run/praho-mail-d<identity hex>/` and verifies them
  again. It then closes the lock and execs `/usr/bin/python3` on the copy's `praho-mail.py`, with only the action,
  identity, node and a fixed `PATH` in the environment. Both the old start-permit code and the installed boot guard
  accept that path.
- **Re-validation.** The delegated process takes the lock itself and re-validates the journal:
  - an operation that a same-identity replay already completed returns the completed receipt;
  - a lost lock returns `mail_operation_busy`.
- **Domain actions** refuse `mail_node_operation_in_progress` unless `node.json` is `ready`.
- **Cleanup.** The playbook removes the copy afterwards.
- **Repair.** In both cases the job stays `attention` and the fence stays up:
  - **A tampered install** (trust checks fail): incident, drain, rebuild.
  - **A broken old helper:** the staff action `abandon_node_certificate_operation` calls
    `abandon_certificate_operation(identity)`. That action restores the staged old pair and the `before.json` journal,
    removes only that operation's fence, and marks the tombstone `abandoned`. A fresh identity then recovers.

## 6. Native interfaces

### 6.1 Entry scripts
- **Two entry scripts.** Domain actions run from `praho-mail-domain.py` and `praho-mail-domain.pl`. Neither file is in
  the installed bundle (`NATIVE_FILES`), and the existing dispatch table in `praho-mail.py` stays unchanged.
- **Imports and lock.** The domain entry imports only `operation_lock` and `hostname` from the staged `praho-mail.py`,
  takes the same node lock, and emits the same `MAIL_RESULT` envelope.
- **Lock modes.** Every action is exclusive except `query_mail_operation`, which is shared.
- **Secrets** travel only on the command's standard input. They never appear in the environment, receipts, journals,
  rows (except the encrypted change secret), audit or logs.

| Action | Inputs | Receipt payload |
|---|---|---|
| `prepare_mail_domain` | domain, owner, account name | `domain_id, owner, owner_uid, mail_enabled, dkim{selector, record_name, record_value}, dkim_state` |
| `enable_mail_domain` | + expected `{domain_id, dkim_sha256}` | + `outcome`, `acceptance{local_delivery, imaps_993, pop3s_995, submissions_465, smtp25_auth_absent}`, `certificates[]` |
| `disable_mail_domain` | + `{domain_id, mode: retire\|withdraw}` | `outcome, mail_accepted: false, inbound_deferred: true, accepted_queue_empty, mailboxes_retained: true` |
| `apply_mail_change` | non-secret change JSON; secrets on stdin | `change_id, outcome, mailbox_count, inventory_sha256, items[], aliases[], maps_sha256, delivery_opened` |
| `release_mail_operation` | `{identity, intent_sha256}` | `released: true, observed{mail_enabled, mail_accepted, dkim_sha256, mailboxes, aliases}` |
| `query_mail_operation` | `{identity}` | `journal: absent\|applying\|completed\|failed_effectful\|released, steps[], receipt` |

### 6.2 Journals
- **Location and contents.** `/var/lib/praho/mail/domain-operations/<identity>.json` records the action, the domain id,
  `intent_sha256` of the non-secret intent, the status, the completed steps, the probe login and the stored public
  receipt.
- **Write order.** The journal is written before the first mutating step, so a missing journal proves that this
  identity had no effect.
- **Steps and resume.** On resume, each completed step is observed again before the next one runs.

| Action | Steps |
|---|---|
| `enable_mail_domain` | `dkim_installed → delivery_deferred → mail_enabled → probe_created → probe_proven → probe_removed` |
| `disable_mail_domain` | `queue_checked → acceptance_removed → deferral_removed → inbound_deferred` |
| `apply_mail_change` | `validated → native_applied → verified → submitters_published`, plus `delivery_opened → routing_verified` for a roster |

- **Replay outcomes.** A completed identity returns its stored receipt. A different `intent_sha256` under the same
  identity is `mail_setup_review_required`, and another identity while one is `applying` is
  `mail_node_operation_in_progress`; both refuse before any write.
- **Recovery.** The platform always replays the owning identity. When that can't finish, staff run
  `release_mail_operation`, which runs only cleanup steps and records the observed end state.

### 6.3 Codes and stages
- **New codes, NOT_RETRIABLE:** `mail_domain_not_prepared`, `mail_dkim_mismatch`, `mail_domain_acceptance_failed`,
  `mail_domain_not_enabled`, `mail_change_conflict`, `mail_mailbox_locked`, `mail_alias_target_refused`,
  `mail_domain_suspended`.
- **New code, RETRIABLE:** `mail_domain_queue_not_empty`.
- **New stages:**
  - `domain_preflight`, `domain_dkim`, `domain_defer`, `domain_enable`, `domain_acceptance`, `domain_disable`,
    `domain_queue`, `domain_resume`;
  - `change_preflight`, `change_apply`, `change_verify`, `change_submitters`, `change_open`, `change_routing`;
  - `release_cleanup`.
- **Where they are registered.** Every code and stage appears in the native public set, the lab harness and the
  platform's safe set.

### 6.4 Pre-write stages
A refusal is pre-write only when it comes from one of these stages:

| Action | Pre-write stages |
|---|---|
| `setup` | `inspection`, `preflight`, `node_certificate` |
| `reconcile_node_certificate` | `certificate_preflight`, `certificate_candidate` |
| `upgrade_bundle` | `bundle_preflight` |
| domain actions | `inspection`, `domain_preflight`, `change_preflight` |
