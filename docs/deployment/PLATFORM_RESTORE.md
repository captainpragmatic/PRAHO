# Restore a Platform backup

PRAHO has two separately deployed applications. Platform owns the business database and uploaded
media. Portal is an API proxy; its local session database is disposable and must be rebuilt rather
than copied from a backup. A Platform restore does not provision or restore customer Virtualmin
servers. Their backups have a separate recovery process.

The source-controlled entrypoints are:

| Deployment | Repository source | Installed entrypoint |
| --- | --- | --- |
| Native | `deploy/ansible/roles/praho-native/templates/restore-platform-native.sh.j2` | `/opt/praho/scripts/restore-platform.sh` |
| Docker | `deploy/scripts/restore-platform.sh` | Run from the deployment checkout, or `make restore` |

`/opt/praho` is the native server installation directory, configured by Ansible's `project_root`.
It is not a second source repository. Ansible renders the native script using the deployed database,
ports and directory configuration. Redeploying this role installs the explicit Platform name and
removes the old native `scripts/restore.sh` entrypoint. `make restore` and `make restore-latest`
retain their existing names and invoke the renamed Docker script.

## Recovery inputs

Keep these available independently of the failed server:

- The selected database backup and its companion media archive, with matching base names and
  recorded checksums. Native PostgreSQL backups use `.dump`; Docker backups use `.sql.gz`.
- The matching application revision and supported PostgreSQL major version. Restoring data does
  not automatically make an older application compatible with that schema or encryption format.
- The complete Platform environment and encryption keyring, including keys needed to decrypt
  historical values. A database backup contains encrypted credentials, not a replacement for the
  keys that open them. Preserve secret-context UUIDs, row identities and credential natural keys.
- Portal's filtered environment and both services' matching HMAC configuration. Rebuild Portal's
  local state directory with the Portal OS identity and migration commands from its service unit.
- Native deployment credentials/configuration under `/opt/praho/credentials` and the appropriate
  service units. Keep private configuration outside Git and restrict access to recovery operators.

A backup is not a complete disaster recovery solution until its off-server location and the
independent recovery path for the keys/configuration have also been tested.

## Before restoring

1. Confirm the hostname, machine identity, target database and application revision. A localhost
   database check alone cannot distinguish a recovery VM from the real staging or production host.
2. Preserve the target's current environment, keys and data. Plan for writes since the selected
   recovery point; replacing the database loses those later writes.
3. Validate checksums and archive readability. Native example:

   ```bash
   pg_restore --list /opt/praho/backups/praho_backup_TIMESTAMP_PID.dump
   pg_restore --file=/dev/null /opt/praho/backups/praho_backup_TIMESTAMP_PID.dump
   tar -tzf /opt/praho/backups/praho_backup_TIMESTAMP_PID.media.tar.gz
   ```

4. Check the selected backup has its expected media pair. The native script warns and leaves media
   unchanged if restoring a legacy dump without a companion archive. That is not proof of complete
   database/media recovery.
5. For an isolated rehearsal, prepare dependencies before copying data or keys. Block external
   networking, disable actual workers and application timers, and use a dummy email backend.
   Restored payment/provider credentials remain real credentials even when an environment flag says
   "test". Do not validate them against external providers during the drill.

## Native restore

For coordinated native deployments, first hold both origins and drain workers using the native
deployment/recovery procedure. Confirm the Portal hold separately on its host. On Platform, use:

```bash
/opt/praho/scripts/restore-platform.sh --leave-stopped /opt/praho/backups/praho_backup_TIMESTAMP_PID.dump
```

This explicit recovery mode requires Platform's durable ingress/worker holds and an inactive
qcluster. It runs a fresh safety backup as `praho` using the private installed environment while
backup scheduling stays held. It restores Platform's local database/media and leaves services
stopped and all gates intact. Verify the recovery point and migration set, then resume through
the coordinated launcher so both hosts and authenticated callbacks are checked before reopening.
Split hosts require this mode. An ordinary restore refuses to clear an active maintenance hold.

For a legacy combined installation without coordinated holds, the existing interface remains:

Run as root on the confirmed target, using the Ansible-rendered script:

```bash
/opt/praho/scripts/restore-platform.sh /opt/praho/backups/praho_backup_TIMESTAMP_PID.dump
# Or deliberately select the latest native dump:
/opt/praho/scripts/restore-platform.sh --latest
```

Review the selected recovery point and answer `yes` only on the intended target. The script:

- Privately stages and validates the selected inputs before downtime or mutation.
- Runs `praho-backup.service`, which supplies the `praho` user and deployed environment for the
  mandatory safety backup. It verifies fresh service journal evidence and a completed nonempty
  database/media pair. A lock-contention skip, missing service, failed backup or missing evidence
  must abort before database replacement. The backup timer need not be active.
- Stops Platform, Portal and Qcluster, replaces the local PostgreSQL database and restores media.
  Root opens the private staged archive; extraction runs unprivileged as `praho` through stdin.
- Pauses orphaned-media deletion for seven days, then starts the applications and worker and checks
  HTTP readiness. Files outside the selected media archive are retained, so use a fresh media
  directory when proving recovery of the selected archive's exact contents.

Require the explicit `Restore completed successfully` message as well as exit status zero. Answering
`no` cancels with exit status zero. If SQL/media recovery or readiness fails after writers stop,
applications remain offline. Inspect the failure and preserved safety backup before restarting.
Never bypass backup ownership or weaken the root-only staging directory to make recovery proceed.

## Docker restore

From the matching deployment checkout:

```bash
./deploy/scripts/restore-platform.sh ./backups/praho_backup_TIMESTAMP_PID.sql.gz --env staging
./deploy/scripts/restore-platform.sh --latest --env staging
# The Make interface remains available:
make restore DEPLOY_ENV=staging
```

The Docker entrypoint retains its existing `--check` and `--leave-stopped` interfaces used by full
rollback. Use the appropriate environment/stack from `DEPLOYMENT.md`; native custom dumps and
Docker SQL gzip backups are different input formats.

## Verify recovery

Check the restored migration set, important record counts and archive contents against the selected
backup. Compare secret ciphertext together with row/context UUIDs and natural keys before normal
readers update access/audit metadata. Verify decryption locally without printing secrets or calling
external provider APIs. Check authenticated Platform pages and an HMAC-signed Portal-to-Platform
request, then verify the applications' OS/database isolation.

Record what was deliberately excluded. A seeded authenticated session does not prove password or
MFA entry. An inert worker does not prove live task processing. An empty media archive cannot prove
recovery of actual customer uploads. Production workers and external integrations need a separate,
controlled re-enablement step after operator acceptance.

## Rehearsal evidence: 2026-10-28

The hosting plan-change recovery procedure below is a separate, newly introduced
obligation. The historical rehearsal in this section did not exercise its records,
payments or native applications.

A disposable Ubuntu 26.04 VM on the operator's Proxmox cluster restored the staging native backup
`praho_backup_20261027_224844_201279.dump` with its media pair using application revision
`ec3b40dc9ec89d5faa411e8d7b32ba3830559140` and PostgreSQL 16. The corrected native restore took
18 seconds after bootstrap. The deployed script's safety-backup ownership failure and private media
permission failure were reproduced first, with regression tests for both and for absent completion
proof/inactive service collection. See [issue #760](https://github.com/captainpragmatic/PRAHO/issues/760).

Verification compared the restored user, vault credential, provider, 215 settings and empty business
and server tables with a separate reference restore of the selected backup. All 148 migration records
were present. Normal readers decrypted the credential and resolved the provider token locally.
Authenticated setup/status pages and signed Portal session validation passed. Workers were inert,
external traffic was blocked by QEMU isolation plus a guest firewall, and the restored task queue
remained empty. Staging had no customer/invoice rows or media files; password/MFA entry, real task
processing, provider API access, off-server backup retrieval and independent key recovery were not
exercised. The disposable VM, disk, transport archives and ephemeral key were removed afterward.

This evidence validates the repaired script, not an unmodified release. The fixes and filename change
must be reviewed and deployed before the live server gains this behavior. Operational host identities,
cleanup inventory exceptions and exact execution evidence are retained in the private staging KB.

## Hosting plan-change recovery

Use when #840 records or processor attempts exist in the restored database, or a
deployment must stop accepting changes while earlier agreements remain unresolved.
See [ADR-0074](../ADRs/ADR-0074-paid-hosting-plan-changes.md) and
[recurring operations](../domain/RECURRING_BILLING.md#paid-hosting-plan-changes).

Keep new acceptance disabled with `billing.hosting_plan_changes_enabled=false`.
An existing worker version must still understand `PlanChange`, its interval
allocations, payment attempts, review events, notices and native outbox. Preserve
all of them with Payments, proforma/invoice lineage, refund/storno evidence and
the matching encryption keyring. Restoring an older backup can omit payments or
provider submissions that happened afterward: inventory that gap before any new
charge, rather than assuming the restored queue is complete.

1. Inspect the exact service/customer/change/document/attempt identities and the
   actual processor facts using authorized operator tools. A queued task or elapsed
   lease is not proof of no submission. Never log client secrets, credential
   material or full native evidence into a ticket.
2. Recover through the existing `billing-plan-change-payments` schedule and normal
   document convergence. Retrieve a known original PaymentIntent. An unknown create
   can replay only its original payload/key inside the persisted safe replay window;
   after that window it needs review, not a fresh intent. Cancellation/expiry needs
   never-issued or exact provider-cancellation evidence. Late verified money after
   application authority ends remains `paid_review`.
3. Process pending `PlanChangeReviewEvent` rows through
   `billing-plan-change-financial-review`. Disputed/refunded source evidence already
   blocks new commercial native dispatch before the sweep finishes. Resolve actual
   financial liabilities with the existing refund/storno process; do not manually
   clear FSM state, guess a partial refund's interval allocation or assume a refund
   reverses a later plan/resource assignment.
4. Reconcile `applying_limits` / `limits_attention` through
   `billing-plan-change-fulfilment` and the existing native job recovery lane. Current
   canonical-node receipt proof is required for completion. A resource failure does
   not refund an accepted payment or authorize charging again. A downgrade that
   reaches its boundary retains the agreed lower billing terms while unsafe native
   reduction waits. Its first due reconciliation emits one HIGH/review-required
   staff event in `/audit/review/`; inspect that queue. Preserve
   `staff_escalated_at` with the immutable event history. Reviewing the event is an
   acknowledgement, not proof that native limits applied or authority to reprice.
5. Before retrying create/restore/migration repair, distinguish unissued work from
   the exact already-issued token-bound frozen parent. Only the latter may retain
   its approved repair authority during later financial review. Never use a
   generic authority flag, old readback or job status edit as an exception. Preserve
   fencing/leases and current owner/node binding; an uncertain restore must not
   reactivate its domain before verification.
6. Preserve historical agreement currency and original covered document IDs. A valid
   later currency transition or unrelated new renewal does not rewrite the old
   agreement. Do not "repair" a current-currency mismatch by editing historical
   quotes, invoice amounts or accepted limits. New target renewals continue to use
   their own independently accepted terms.
7. Reconcile the four billing schedules and verify phase notice/EmailLog linkage.
   Retrying an existing notice must not create another phase obligation, including
   after EmailLog retention. Final send still checks current ownership, recipient,
   privacy, phase and current completion proof. An issued invoice's notice follows
   actual document issuance even when commercial application is in review.

Leave acceptance off until the specific financial and native uncertainty is
resolved and the deployed version passes the rollout checks. Stopping new checkout
must not stop already accepted scheduled boundaries or the consumers that recover
received money. This procedure supplies no evidence that a native or paid browser
rehearsal has occurred.
