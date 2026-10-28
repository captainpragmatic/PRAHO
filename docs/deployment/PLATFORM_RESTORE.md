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
