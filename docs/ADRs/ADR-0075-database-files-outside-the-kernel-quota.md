# ADR-0075: Database Files Stay Outside the Kernel Quota

## Status

**Accepted** — 2026-11-10. Amends the storage assumption in ADR-0068 and the
database enforcement in #776. Amended 2026-11-14 with the over-allowance write hold
(see the amendment below).

## Date

2026-11-10

## Authors

PRAHO maintainers

## Context

#776 charged each tenant's database files to its account group so one kernel cap
covered files and databases. Native Phase 0 tested that on MariaDB 11.8.6: with a
tenant cap on database files, one ordinary autocommit `INSERT` of a value of about
16 KiB or more aborts the shared server (signal 6, `Error (Out of disk space) in
rollback`, upstream MDEV-23901, open since 2020). A cap left low after an abort
makes recovery abort again. Atomic-write settings and headroom do not help, and
such values are ordinary post content and serialized options.

A kernel cap on database files therefore lets any tenant take every neighbour down.

## Decision

Database files are outside the kernel quota. Kernel UID and GID caps govern files
in the account's home. Database size is measured, counted and warned about by
Platform.

- `mysql_chgrp=0` is enforced on every play, and every **effective** Virtualmin
  template is repaired or refused, because Virtualmin reads the account's resolved
  template, not the global value alone. The effective policy must be safe before
  Webmin's `mysql_data` is corrected.
- Every tenant database directory and physical file must be owned by the running
  MariaDB UID and GID, without setgid. A tenant-owned file stays subject to the
  UID quota even with group `mysql`, so ownership by UID matters too.
- The cap fit check compares the cap with `max(uid_used, gid_used, files_bytes)`.
  Canonical usage and warnings still add files and databases (ADR-0068).
- MariaDB's `CAP_SYS_RESOURCE` restriction stays as least privilege. It no longer
  has any role in enforcement.
- Qualification carries `quota_contract`, and its acceptance check is
  `database_outside_quota`. A proof of the old database denial cannot certify the
  opposite policy. `POLICY_VERSION` is unchanged, so notification evidence survives.
- Installed nodes with tenant-charged databases are refused and named, and repaired
  by a quiesced, identity-checked, resumable operation. Rollout is roll-forward only:
  after a repair the previous probe refuses the repaired accounts.

### Alternatives considered

| Approach | Why not |
|---|---|
| Give `mysqld` `CAP_SYS_RESOURCE` so it bypasses quota | Depends on capability inheritance for a non-root service; a mistake silently restores the crash |
| A separate group quota identity for databases | Any cap on database files can still abort the server |

## Consequences

- A tenant's database can grow beyond its allowance, limited only by node disk,
  and can overshoot between hourly readings. Over-allowance action is a separate,
  billing-level control, not crash protection.
- A completely full node disk produces the same abort. Nodes alert operators at 10%
  and 5% free, measured on `f_bavail`.
- Plan-change quotes still compare files plus databases with the target allowance.
- Backup and restore of a database larger than the file cap work. Virtualmin 8.3
  sets both the account's UID and GID caps to unlimited for the whole backup
  (`disable_quotas`, `backups-lib.pl:902`), writes the SQL dump as the tenant into
  `~/.backup`, and restores both caps from the domain's configured quota only
  when the backup process reaches its exit path (`:1012-1013`), whether the
  backup succeeded or failed. Webmin removes `~/.backup` on that same exit
  (`@main::temporary_files`). Restore lifts and restores the caps the same way
  (`:3255`, `:3342`) and imports as root from a root-owned temporary directory.
  Tenant files are therefore uncapped for every backup and restore window, as
  before this decision, and a backup needs free node disk for the dump plus the
  archive. Native acceptance proves the normal and the destination-full paths.
- A backup or restore process killed outright (OOM, reboot, a stopped Webmin)
  never reaches its exit path, so both caps stay unlimited and a tenant-owned
  dump can stay in `~/.backup`. Platform closes this: when a managed account's
  PRAHO backup or restore job ends, completed or failed, after the account's last
  verified receipt, the hosting-limits dispatcher (every 5 minutes) marks that
  receipt stale. The existing managed-limits path then probes the node, applies
  both caps again and verifies all six cap values in a fresh receipt. Refusals are
  retried by the same dispatcher and reach staff as an attention job after the
  retry budget, as for any other limits application. Jobs still running or held
  for staff are left to their own resolution. The probe also reports a leftover
  `~/.backup` (read with `lstat`, never followed), and the completed application
  names it in its status. Each finished backup therefore costs one more quota
  application: a native write that sets unchanged caps when nothing was lifted.
- PRAHO's restores are limited to web features and import no Virtualmin settings. A
  template changed by hand between deploys is refused at the next probe.

## Amendment (2026-11-14): database over-allowance episodes

The billing-level control the Consequences above leave open (#776 Task 7). It is
off until `provisioning.database_overage_enabled` is on, and the write hold must
be in the Terms before that.

- A fresh reading (under 2 hours, same owner, server and chain epoch, no failed
  scan after it) that puts an account with database bytes over its verified
  allowance plus active temporary relief opens an episode. Unverified limits decide
  nothing; an allowance of 0 is unlimited, relief or not.
- Day 0: an email and a system support ticket. Writes stay enabled for
  `provisioning.database_overage_grace_days` (14) from when the notice is sent; the
  deadline moves later if the provider accepted it late. The day-0 notice replaces
  the account's 100% disk warning while the episode is open.
- At the deadline the account's database write privileges are revoked on the node
  and journalled, so they are restored exactly. `SELECT`, `DELETE` and `DROP` stay
  available. The day-14 notice follows a confirmed hold.
- The episode closes after 24 observed hours under the allowance: a reading counts
  once, and a gap of more than 3 hours between readings restarts the 24 hours.
- Once a hold may exist, an episode closes only through a release, or when its
  account was terminated with the node domain.
- Every step is audited as contract evidence.
