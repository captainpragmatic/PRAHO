# Infrastructure migration operational notes

Operational caveats for migrations in this app that are not expressible in the
migration code itself. Recorded here (rather than by editing already-applied
migration files) so the source history of applied migrations stays stable.

## Drift remediation migrations `0003` / `0004` (from #319 / #224)

These two migrations dedup the `DriftRemediationRequest` table and add the
`uniq_open_request_per_report` constraint. Deploy-window caveats:

1. **Pause drift scan schedules during the deploy.** `0004` re-dedups and then
   builds the unique constraint as sequential operations in one transaction (no
   `atomic=False`). On PostgreSQL a concurrent insert from an old-code worker
   between the re-dedup and the constraint build makes the build **fail and
   abort the migration** (safe — no corruption — but it blocks the deploy).
   Disable the `drift_scan` / `apply_scheduled_remediations` / `recover_stale`
   schedules for the migration window, or run the migration during a scan-quiet
   period. (SQLite DDL is weaker; dev only.)

2. **Rolling deploys can transiently mislead.** `0003`'s dedup marks all but the
   newest `in_progress` request `failed`, but a still-running django-q worker on
   the *old* code keeps executing its request — the DB reads "free" while
   provider-side work continues. `created_at` does not identify the live worker,
   so drain the old workers before relying on the deduped state.

3. **`occurrence_count` is not aggregated on collapse.** The dedup leaves the
   surviving row at its own count (typically 1); a legacy critical
   consecutive-network streak can transiently downgrade in severity until the
   scanner rebuilds the counter on the next scans. Expected, self-healing.

4. **Reverses are lossy no-ops.** Both `0003` and `0004` reverse with
   `RunPython.noop`: reversing to `0002` does **not** restore pre-dedup workflow
   state (superseded / failed rewrites persist). Treat these migrations as
   effectively irreversible for data purposes.

5. **Malformed `scheduled` rows.** A `scheduled` request with a NULL
   `scheduled_for` is undispatchable yet counts as open for the constraint.
   Current writers never produce this, but `recover_stale_remediations_task`
   now terminalizes any such row defensively (see its step 2b).
