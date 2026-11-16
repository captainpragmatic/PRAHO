# Database over-allowance: operations runbook

What staff do when an account's databases put it over its hosting allowance. The behaviour customers
see is in [HOSTING_USAGE_WARNINGS.md](HOSTING_USAGE_WARNINGS.md#databases-over-the-allowance); the
decision is [ADR-0075](../ADRs/ADR-0075-database-files-outside-the-kernel-quota.md).

Settings: `provisioning.database_overage_enabled` (off by default) and
`provisioning.database_overage_grace_days` (14). The write hold must be in the Terms before the flag
goes on. The sweep `database-overages` runs every 15 minutes.

## Reading the attention list

**Business → Database Overage** lists every open episode the sweep can't move on by itself. Each row
opens the service's page (Services → service → **Database over-allowance**), which shows the state,
the deadline, the notices and the last problem. Any staff member can read both pages; only
administrators and managers can extend or waive.

| Shown | What it means | What to do |
|---|---|---|
| Hold deferred over a day | A precondition fails at every sweep. *Last problem* names it: `day0_not_accepted`, `no_fresh_over_reading`, `active_operation`, `suspended_for_migration`, `pending_assignment_covers`, `identity_unknown` (the account moved to another node and the usage collector has not reported its domain there yet; it clears by itself), `inactive`, `flag_off` | Fix the cause if it's wrong (a stuck job, an unreachable node, a day-0 address that failed: correct the customer's email and the next sweep sends day 0 again, with a full grace period); otherwise extend or waive |
| Node refused the hold | The node turned the account's grants down (for example `shared_username`, `wildcard_database`, `definer_outside_scope`). The hold was undone and won't be tried again | Fix the account's grants on the node, then **Extend** (which clears the refusal) to let the next deadline try again, or **Waive** |
| Release pending | A release keeps failing; *Last problem* has the node's answer | Check the node is reachable; the sweep retries every 15 minutes. If it can't recover, see release-all below |
| Release waiting over a day | *Last problem* says `release waiting for a running restore_domain`, `apply_hosting_limits` or `migration`. A release never restores grants over a live writer; jobs parked in attention and migrations in review don't count | Let the job finish, or resolve it; the release follows at the next sweep |
| Grants drifted from the hold | Virtualmin or someone changed the held account's grants (a restore, a user edit). A completed restore or re-create asks for a verify at once | The sweep fences the hold's token and holds again with a new generation; the node keeps each row's original grants for the release. It waits while the flag is off or the account is busy (*Last problem* `re-hold deferred: …`). If the node refuses the new hold, it's undone and left for staff like any refused hold |

While an episode is *holding* or *releasing*, the account counts as busy: backups, restores, migrations,
quota changes, DNS and certificate work on it wait, as they do for any other running operation. A held
episode doesn't block anything. A release stuck in *releasing* keeps the account busy until it completes,
so look at it first when an account's operations all wait.

## When the account's native identity changes

A hold is bound to the domain id and collector installation the usage collector verified on the node. In
grace, the episode follows any change (a move, or the domain recreated on the same node) at the next hold
decision, and waits as `identity_unknown` until the collector has verified the new identity.

Under a hold, the sweep stops asking the node and puts the episode on the attention list:
- *identity changed: domain … was recreated*: the old hold's journal belongs to a domain that no longer
  exists, and releasing it would rewrite the new domain's grants. The episode is back in grace (or closed, if
  it was being waived or released for good) without the node, latched like a refused hold. Check the new
  domain's grants, then extend or waive.
- *installation changed*: the node's collector was reinstalled while the grants are still held under the
  old installation. Nothing is released automatically. Resolve it on the node with the database hold helper
  (release by the old installation's journal), then waive or extend.

## Migrating an account with an episode

Starting a migration suspends the account's episode for it. A held episode is released (its token fenced,
the grants restored and checked) before the migration takes its barrier record, so the move copies the
customer's own grants; if that release doesn't complete, the migration fails before anything moved and the
sweep finishes the release. A cutover migration holds the target again as part of its activation, before
the target admits writes; if the target turns the hold down, the episode is back in grace, due, and shows
as a refused hold for staff. When the migration ends, however it ends, the suspension is cleared and the
next hold decision follows the account to the node it is on. Accounts that are holding or releasing can't
start a migration until that settles.

A recovery from a fenced node can't release anything there. Its start leaves the source's hold journal on
record as abandoned (*Last problem*: `source node fenced for recovery`), and an episode that was holding or
held is held again on the target before the target's runtime is enabled, then verified at the next sweep.
If the target refuses the hold, the recovery still completes and the hold is left for staff as a refused
hold. Extend and waive after a recovery act on the target. If the old node ever comes back, its abandoned
journal is for a domain that no longer runs there: remove the domain, never release onto it.

A component migration records the source's database grants in its review, so it is refused while the
episode is holding, held or releasing: extend (a write window) or waive first, then inspect and review.
Its start suspends an episode in grace like any migration. The component activation hold built for the
target is not used for now: a component move never starts from a held episode.

## Dropped-database cleanup

When the usage collector reports a registered database whose directory is gone, the account is
flagged with the database's name. Never clean up on the directory alone. As root on the node, check by
exact name first:

```bash
mysql -NBe "SELECT 1 FROM information_schema.SCHEMATA WHERE SCHEMA_NAME = '<database>'"
```

- **Empty output, exit code 0:** the database is gone from MariaDB. Remove its registration from the
  domain: `virtualmin delete-database --domain <domain> --name <database> --type mysql`. The next
  hourly reading no longer reports it.
- **A row:** MariaDB still has the database; it isn't missing. Find out why its directory isn't where
  the collector looked before changing anything.
- **An error:** nothing is proven. Leave it and investigate; the account stays unavailable to readings
  until then.

## Extend

Service page → **Database over-allowance** → **Extend**, with 1 to 30 days and a reason. The new
deadline is the later of now and the old deadline, plus the days. If writes are held, the hold is
released first: that is the customer's write window, for example to `OPTIMIZE` a large table, since
`DELETE` doesn't shrink InnoDB files. Extending also clears a refused hold, so the next deadline tries
again. It's refused while a release is still in progress; wait for the sweep.

## Waive

Service page → **Database over-allowance** → **Waive**, with a reason. The episode closes; if writes
may be held, it closes only after the hold is released. Both actions are audited with your name and
reason.

## Release every hold: `release_database_holds --all`

The rollback. First turn `provisioning.database_overage_enabled` off, so no new episode or hold
starts while it runs; releases, closes and verifies keep running with the flag off. Then, on the
Platform host, from `services/platform`:

```bash
python manage.py release_database_holds --all
```

It works through the holding, held and releasing episodes one at a time: each is marked for rollback,
then its hold is fenced and released, and the episode closes as `flag_rollback`. It prints
`<n> released, <m> pending` and exits non-zero while any hold is still in place. Run it again until it
reports `0 pending` and exits 0: an episode whose turn hadn't come when a run stopped isn't marked yet,
and only a later run (or, while it still holds, the normal sweep) releases it.
