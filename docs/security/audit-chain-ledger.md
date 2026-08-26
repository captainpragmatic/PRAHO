# Audit hash-chain ledger and external anchoring (#313)

## What this closes, and what it does not

`AuditEvent` rows carry a keyed per-row MAC (`audit-integrity` domain), which detects
**mutation** of a row. It cannot detect **deletion** — a removed row leaves no trace.

The chain ledger closes that: every event gets an `AuditChainLink` carrying the previous
link's MAC and a monotonic `sequence`, so an insert, a reorder, or a mid-chain deletion
breaks the walk. Chaining alone still cannot detect **tail truncation** — lop off the last
N links, update the head, and the remaining chain verifies clean. That is what the external
anchor is for: each anchor run publishes `(sequence, head MAC, link count)` to a sink
outside the database, MAC'd under a separate key.

**The `AuditChainAnchor` table row is not the control.** It is a local convenience copy in
the same database an attacker would own, and they can delete it alongside the links. The
evidence is what the **sink** holds. Verification compares the sink's highest anchor against
the live chain: a chain that no longer reaches an anchored sequence has been truncated.

## Threat model

The attacker has **database write access** and cannot read application secrets.

| Attack | Detected by | Notes |
|---|---|---|
| Modify a row | per-row MAC (`audit-integrity`) | Pre-existing (#385/#399) |
| Insert a forged row | chain MAC (`audit-chain`) | Needs the chain key to produce a valid link |
| Delete a mid-chain row | chain walk | Successor's `previous_chain_mac` no longer matches |
| Reorder rows | monotonic `sequence` | |
| **Truncate the tail** | **external anchor only** | Undetectable without a shipped-off-host sink |
| Delete rows **and** re-run backfill | anchor | Backfill cannot reproduce anchored sequences it no longer has |

## Keys — provision three, separately

| Domain | Env var | Who should read it |
|---|---|---|
| `audit-integrity` | `AUDIT_INTEGRITY_SECRET` | The app |
| `audit-chain` | `AUDIT_CHAIN_SECRET` | The app |
| `audit-anchor` | `AUDIT_ANCHOR_SECRET` | **Ideally only the verifier, not the app** |

The domains are cryptographically independent so neither MAC can be replayed as material
for the other. The anchor key is the one that must survive an attacker who has recovered
the chain key — provision it apart from the application's secret store where you can.
Unprovisioned domains fall back to HKDF over `SECRET_KEY`, which is *not* the intended
production posture for `audit-anchor`.

## Rollout — the ledger ships DARK

`AUDIT_CHAIN_ENABLED` defaults to **false**. Deploying this code changes nothing until an
operator walks the sequence below; the append hook stays dark until the historical backfill
has run, because live appends interleaving with the backfill would corrupt the sequence.

1. **Deploy** with `AUDIT_CHAIN_ENABLED=false` (the default). Zero behavior change.
2. **Provision** `AUDIT_CHAIN_SECRET` and `AUDIT_ANCHOR_SECRET`.
3. **Backfill** the existing events:
   ```bash
   python manage.py backfill_audit_chain --dry-run     # preflight counts
   python manage.py backfill_audit_chain               # batched, resumable, idempotent
   ```
   Safe to interrupt and re-run: an event that already has a link is skipped, and a resumed
   run continues the same chain (ordering is `timestamp` then `id` as a deterministic
   tiebreaker). Tune with `--batch-size` (default 1000 rows per transaction).
4. **Enable live appends**: `AUDIT_CHAIN_ENABLED=true`. New events are chained from here.
5. **Anchor on a schedule** — this is the step that makes truncation detectable, so it is
   not optional:
   ```bash
   python manage.py anchor_audit_chain
   ```
   Anchor cadence is your truncation-detection window: events created after the last anchor
   can still be truncated undetectably. Run it at least as often as you would want to
   notice a tampering incident.
6. **Ship the anchor sink off-host.** `AUDIT_ANCHOR_SINK=logfile` (default) appends one JSON
   record per line to `AUDIT_ANCHOR_LOG_PATH`, fsync'd before the local row is written. In
   production point that at `/var/log/praho/` alongside the other logs **and confirm the log
   pipeline ships it off-host** — an anchor file sitting on the compromised box buys nothing.
   `AUDIT_ANCHOR_SINK=none` disables external publication entirely: anchors stay local and
   **tail truncation stays undetectable**.
7. **Require the chain**: `AUDIT_CHAIN_REQUIRE=true`. An `AuditEvent` with no chain link is
   now a critical finding rather than benign. Flip only after step 3 completed and step 4 has
   been live long enough that no unchained events remain.

## Verifying

```bash
python manage.py run_integrity_check --type chain_verification   # walks the whole ledger
python manage.py run_integrity_check --type all --period 7d --alert
```

## Residual risk after full rollout

- **Anchor-cadence window** — events between the last anchor and a truncation are not
  covered. Shorten the cadence to shrink it.
- **Pre-genesis rows** — events that predate the backfill are chained by it, but the chain
  attests only that the ledger has been self-consistent *since* the backfill; it cannot
  testify about deletions that happened before.
- **Sink integrity is operational** — if the anchor file is never shipped off-host, an
  attacker with host access deletes it with everything else. The cryptography is only as
  good as that pipeline.
- **`timestamp` is now caller-settable.** `AuditEvent.timestamp` moved from `auto_now_add`
  to `default=timezone.now` so the value exists before `pre_save` (which is what allows
  create+stamp in a single INSERT). A caller can therefore pass a backdated timestamp. It is
  covered by both the per-row MAC and the chain link, so it cannot be altered after the
  fact — but it can be set wrong at creation by application code.
