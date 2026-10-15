# ADR-0059: Differential Virtualmin Backups Are a Chain PRAHO Tracks and Fences

- Status: Accepted
- Date: 2026-10-15
- Authors: PRAHO maintainers
- Related: ADR-0016 (audit coverage), ADR-0034 (FSM transitions), ADR-0051 (hosting-account enabled-state ownership), ADR-0060 (the Virtualmin API user), issue #498
- Evidence: `docs/domain/virtualmin-incremental-contract.md` (lab run against Virtualmin 8.3.0 / webmin-virtual-server 8.3.0-1-gpl)

## Context

A full Virtualmin backup of a large account is slow and big. Virtualmin can make a *differential* backup, which holds only what changed since a base. The saving is real, but a differential is only meaningful against the exact base it was made from, and Virtualmin keeps that base as a single mutable file on the node. Anything that rewrites the file silently turns a later "differential" into something that restores wrongly. PRAHO therefore cannot just pass a flag. It has to know which base is live, prove each archive was made against it, and refuse everything else.

## Decision

### The facts the design rests on

Each is proven in the contract document, in the lab, not read from documentation.

| Fact | Verdict | Consequence |
|---|---|---|
| `differential` (bare) makes a differential, `no-differential` a standalone full; values on the flag are rejected | Q1 | PRAHO sends exactly these, never a value |
| One GNU tar `--listed-incremental` snapshot per domain holds the base. Every full backup that is not `no-differential` deletes and rewrites it | Q2, Q3 | A plain full is a new base. Standalone backups send `no-differential` and leave the base alone |
| A restore deletes the domain's snapshot, and the next `differential` silently runs as a full and becomes the new base | Q8 | A restore ends the chain. PRAHO never trusts "differential" without checking the snapshot |
| An intervening base-resetting full between a base and its differential makes base + differential lose changes | Q5b | The snapshot is fingerprinted on every step |
| A differential alone recreates the domain with only the changed files | Q7 | A differential is never restored without its base |
| Files deleted after the base come back after base + differential, and databases come from the differential's full dump | Q5, Q6 | Stated in the operator label (see Honest limits) |
| A no-change base still changes the snapshot's hash | lab, stage 1 | "Fresh snapshot" can be asserted from the fingerprint |
| Virtualmin's own nightly schedule sends `--no-differential` | Q4 | It never writes the snapshot, so it stays as an independent safety net |

### The chain model

The account row is the only place chain state lives: `chain_base` (the base backup job whose snapshot is on the node), `chain_base_fingerprint` and `chain_epoch`.

- **Base.** A full backup that resets the snapshot. It sends neither flag.
- **Differential.** Sends `differential`. It is pinned at admission to the base, the snapshot fingerprint and the epoch it extends.
- **Epoch.** An integer that moves whenever the chain is cleared. A job carries the epoch it was admitted at, so a late job can never touch a newer chain.
- **Invalidate first.** Admission of anything that can reset or lose the snapshot (a restore, a new base, a migration, a delete, a delete retry) clears `chain_base` and bumps the epoch in the same transaction that creates its job, before dispatch.
- **Fenced transitions.** A base is linked only after its archive and manifest are published, by one transaction that checks the job's execution token and the epoch, and only when the node showed a fresh snapshot (`fp_after` present and different from `fp_before`). A differential re-checks its pins right before dispatch and again in its completion transaction. If the chain moved, the archive is published but not linked, and the job goes to attention.
- **Evidence ends the chain.** A fingerprint mismatch (absent or different snapshot), or a snapshot a differential moved, clears the chain, fenced by epoch.
- **Lineage, not the live pointer, restores.** A pair stays restorable after the live chain ends, because restore reads the manifests' lineage.
- **Manifests are versioned.** A manifest without `manifest_version` is a legacy standalone backup. An unknown version or role is refused, never read as legacy.

### Node-side binding

Base and differential backups do not go through `remote.cgi`. Each is one allowlisted playbook run (`virtualmin_chain_backup.yml`) that runs a script on the node, as root, under `flock` on a per-domain lock. In that single execution it:

1. checks the run token's cancel marker and refuses a cancelled token;
2. reads the snapshot fingerprint (`sha256:size`, or `ABSENT`);
3. for a differential, refuses unless the fingerprint equals the expected one;
4. runs `backup-domain` into a private staging directory;
5. reads the fingerprint again;
6. prints one result line, which the controller parses and cross-checks against the token, mode and domain id.

The archive and the fingerprints it is evidence for therefore come from one locked execution. Anything inconclusive is uncertain. The domain id is read from `list-domains` and validated as digits, never taken from input; the three copies of each input pattern (Python, playbook, script) are pinned equal by a test.

Snapshot writers outside PRAHO are unsupported. A restore or base-resetting backup made in Virtualmin directly is detected by the fingerprint check (the snapshot is gone or different) and refused, never trusted.

### Exclusion and uncertain runs

One account exclusion covers backups, restores, deletes, migrations and lifecycle retries. Admission takes the account row lock, refuses while another operation is active and creates its job row in the same transaction. A backup's source node comes from the locked account row, and admission refuses when the account moved. Delete jobs count as operations. Unknown delete outcomes are parked, not released.

A base or differential that times out, returns an ambiguous playbook error or loses its worker may still be running on the node, or waiting for the lock. It goes to `attention` and **keeps the exclusion**; only an error from the dispatched step counts as uncertain, and a failure before dispatch or after a conclusive step is a plain failure.

- **Confirm stopped.** Writes the job's cancel marker on the node under the lock, then in one transaction clears the chain and releases the account. If the marker cannot be written the job stays in attention. A delayed run of that token can never start afterwards. The archive and its `.dom` sidecar (database passwords) that a stopped step left staged are then removed.
- **Node lost.** Allowed only while the job's server is marked failed or its deployment is destroyed. It fails the job, rotates its execution token, clears the chain and is audited with the actor. It exists for chain jobs and for pair restores. For a pair restore on a node that is only marked failed (its deployment not destroyed), a background task releases the node as soon as it answers, retrying every 15 minutes for a day: under the per-domain lock it writes the cancel marker and takes the 503 section down, and only then removes the staged archives (a node that restarts keeps its Apache files but loses its markers). A reconcile is queued at once, so the account is converged without waiting for the 15-minute sweep.

The reconciler yields only to what writes or deletes the domain (a migration, a restore or delete in any active state, any running job). A backup that is queued or parked does not stop a suspend after non-payment.

### Pair restore and its write barrier

A domain is restored from a pair: the base, then the differential. Admission locks the account, applies the exclusion, clears the chain and budgets both archives and every stage against the broker visibility window. **Preflight** happens before anything destructive: both archives are downloaded and their checksums verified, and the lineage is exact (the differential names this base, was taken against the snapshot the base left, the two share account, domain id, node and epoch, both hold every component, no differential of a differential, known versions only). Then one standalone safety backup of the target, and both archives are pushed.

One locked node execution (`praho-pair-restore.sh`) holds a **two-layer write barrier** for the whole restore:

1. **server-level Apache rewrite rules**, in a file of its own that `restore-domain` never touches, answering 503 for whatever reaches the domain's virtual host: its document root (so also a Host header that names nothing, and the bare IP) or any name in its "Website hostnames", compared case-insensitively with an optional trailing dot. They run before the virtual host's own rewrite rules (`RewriteOptions InheritDownBefore`, Apache 2.4.8 or later). They are loaded and verified before the first restore, re-applied and verified after each restore step, and removed only after verification. Every checkpoint probes the odd spellings (upper case, trailing dot, `mail.`, each alias) on both ports; a spelling that is not refused refuses the restore before anything changes. A domain whose document root cannot be read is refused;
2. `disable-domain`, re-applied and verified immediately after each restore step.

**Lab finding.** The first design used a maintenance *virtual host*. Virtualmin recognises a virtual host that serves the domain and rewrites it during `restore-domain`, so that host leaked requests for the length of each restore. A server-level section is inherited by every virtual host whatever Virtualmin does to them, and did not leak for the plain name. A second lab finding: a server-level `<If>` with a rewrite rule runs after Virtualmin's own virtual-host rewrite rules, which redirect the `webmail.` and `admin.` names (301), and it matched only the raw Host header, so upper-case, trailing-dot and `mail.` spellings were answered 200 (868 of 992 probes inside the barrier window). The rules are therefore server-level rewrite rules inherited before the virtual host's own, keyed on the virtual host; with the same probe over every alias, the odd spellings, an unnamed Host and the bare IP, every request returned 503 throughout both restores, and a second domain on the node kept answering 200.

PRAHO's account is suspended for the duration, so reconcile (ADR-0051) is the only thing that enables the domain again, and it skips any account with an active operation. When an operator confirms a stopped pair restore after a restore step had already run (or when the evidence cannot show that none did), the account also carries a **restore hold**: reconcile and the divergence backstop leave it alone, the safety backup cannot be deleted, and the domain stays disabled until staff choose "Re-enable as is" or "Restore the safety backup" (both audited; the second ends the hold when that restore completes). Any failure after the barrier keeps it up and parks the job in attention with the checkpoints the node reached; ownership is rechecked before each destructive call, and the node checks the cancel marker and each archive's checksum before each restore. An operator's resolution releases the node (cancel marker, barrier down) before the account is released.

### Retention and deletion

A differential cannot be restored without its base, so retention extends the base: a listing includes the base of every retained differential even after the base's own age has passed. Deletion refuses a base that any stored differential names, a backup an unfinished restore names (single, pair, or the safety backup it took first), and the account's live chain base. Lineage is read from every manifest in storage, never from a filtered listing. The pin check and the delete run in one transaction holding the owning account's row lock, the lock restore admission takes. Deletion fails closed: a manifest that cannot be read, is not an object, or carries an unknown version or role stops it.

### The scheduler

An hourly Django-Q schedule, `virtualmin-chain-backups`, is registered whatever the flag says (the task does nothing while the flag is off). Settings: `provisioning.chain_base_interval_days` (default 7), `provisioning.chain_differential_interval_hours` (default 24) and `provisioning.chain_alert_after_failures` (default 3), all minimum 1 and validated at the settings write chokepoint. Accounts are visited stalest first (no chain job yet, then the oldest last chain job), so a sweep that stops at its 20-job cap serves everyone in turn; sweeps that keep stopping at the cap raise one audit alert.

It looks at active accounts on a serving, non-draining node that has a managed deployment, whose service is active and not held off by a domain. For each, in order:

1. an account with another operation (including a migration or a job parked for an operator) is skipped. It is not a failure;
2. no live base, or a base that left no usable evidence, or a base older than the base interval, gets a **base**;
3. otherwise a last backup of this chain older than the differential interval gets a **differential**;
4. otherwise nothing.

It admits jobs through the same admission as staff, so every exclusion and pin applies. A sweep admits at most 20 jobs so that switching the flag on for a large fleet spreads its first bases over several hours.

**It decides from the chain, never from error text.** A differential the node refuses because the snapshot is absent or different has already ended the chain (that is done where the evidence arrives), so the next run finds no live base and takes a base at once. A failure that leaves the chain alone (the node was busy, a metadata read failed) is marked on the failed job as `chain_state: intact`. It is retried as the same role after 30 minutes, doubling to a day, and it never becomes a base. A failure that ended the chain, and one an operator resolved, carry no such mark and are not counted. Connectivity and permission failures mostly arrive as uncertain runs that park the job and hold the account, and an operator resolves them. When the count of consecutive intact failures reaches three, one audit alert (`virtualmin_chain_backup_alert`, severity high, review required) is raised, the same mechanism as the server health alert. An admission refusal that is not the exclusion alerts once a day per account and role.

### Rollout

Readers ship before writers, and `provisioning.incremental_backups_enabled` (default off) gates creating differential backups **and the pair restore**. Lineage-aware restore of a single backup, retention, deletion, "confirm stopped" and "node lost" work whatever the flag says. Turning the flag off stops new bases and differentials (the scheduler and the manual actions) and the pair restore; a single backup stays restorable, and a pair that was admitted before the flag went off finishes. The manual actions ("Take base backup", "Take differential backup", "Restore pair" on the account page, `virtualmin_backup backup --chain-role`, `virtualmin_backup restore --differential-backup-id`) all follow the flag; the service refuses a pair restore while it is off, so the staff page and the CLI cannot disagree. The CLI pair restore runs on the account's own server only. There are no bulk differential actions.

## Consequences

### Honest limits

- **Deleted files reappear.** Virtualmin extracts the differential over the base without replaying deletions (Q5, Q6). A pair restore does not reproduce the domain's state at the differential's time exactly. The operator label says so.
- **Databases come in full.** A differential holds the databases' complete dump, not a delta, so a differential saves file space, not database space.
- **External snapshot writers are unsupported.** Anything that writes the snapshot outside PRAHO (a base-resetting full, or a restore, made in Virtualmin directly) is detected by the fingerprint check and refused, never repaired.
- **One chain per account.** A new base ends the previous chain's ability to take differentials. Earlier pairs stay restorable from their manifests.
- **A pair restore takes the domain offline** behind the 503 page until it is verified.
- **A node without a managed deployment** (registered by hand) cannot run the node-side steps, so the scheduler skips it and the manual actions fail.

### Operations

- The scheduler's first sweeps after enabling the flag are bases, 20 accounts per hour.
- A job in `attention` is a real alert: the account stays held until an operator confirms the step stopped, or declares the node lost.
- Failed-job alerts are audit events; a staff member reviews `requires_review` events.
