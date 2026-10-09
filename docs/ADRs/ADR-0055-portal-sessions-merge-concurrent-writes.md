# ADR-0055: Portal Sessions Merge Concurrent Writes

- Status: Accepted
- Date: 2026-10-10
- Authors: PRAHO maintainers
- Related: ADR-0017 (portal sessions), ADR-0050 (portal infrastructure tables)

## Context

Portal sessions are server-side Django database sessions in the portal's SQLite file. Django's
database backend saves the whole session dict on every save. Two requests of one customer that load
the same session and both save it race. The later save writes back the earlier one's stale view and
undoes its changes, for example:

- a cart edit;
- a company switch (`selected_customer_id`, name and role);
- a validation refresh.

Docker portals already run two worker processes. Threaded workers make the race likely everywhere.

## Decision

`SESSION_ENGINE` is `apps.common.session_store`, a subclass of Django's database `SessionStore`.

**What it remembers.** The session exactly as it loaded it:

- the stored text;
- a deep copy of the decoded dict, so in-place mutation of a nested value counts as a change.

**How it saves.**

- It applies only what this request changed, with an autocommit compare-and-swap on the stored text:
  `UPDATE ... SET session_data, expire_date WHERE session_key = ? AND session_data = <text it loaded>`.
- With no contention, that single statement is the whole save.
- If another request saved in between, it re-reads the row, applies the same changes to it and tries
  again. Attempts are bounded, with a short random backoff.
- A successful write becomes the new baseline, so a save in the middle of a request does not re-apply
  its changes at the end.

**Merge semantics.**

- **Single keys** are last-writer-wins when two requests change the same key, as before.
- **Key groups** move together. If a request changed any key in a group, the whole group is stored as
  that request saw it, so a mixed combination can never be stored. The groups:
  - company context: `selected_customer_id/name/role`, `active_customer_id`;
  - validation: `validated_at`, `next_validate_at`, `membership_hash`, `user_memberships`,
    `user_memberships_fetched_at`;
  - identity: `user_id`, `email`, `customer_id`, `session_auth_hash`, `authenticated_at`,
    `session_created_at`;
  - account health: `account_health_data`, `account_health_fetched_at`.
- **Record maps** (`order_checkout_attempts`, `gift_purchase_forms`) merge per record, so two tabs
  keep both purchases in progress.
- **Other lists and dicts**, including the cart, are one value. A concurrent edit to the same value is
  last-writer-wins.

**Revocation is preserved.**

- A row that is gone (logout, flush, revocation) is never recreated. The save raises `UpdateError`,
  which the session middleware turns into `SessionInterrupted`. Only a confirmed missing row does that;
  a database error such as a lock propagates as itself.
- Rotating the key (`cycle_key`) of a session that was authenticated when loaded:
  - applies its changes onto the latest row;
  - deletes exactly the stored text it read;
  - then creates the new key from the merged data.

  If a concurrent logout deleted the row, rotation raises `SessionInterrupted` instead of minting a
  new authenticated session. A pre-login session rotates exactly as Django does.

**Compatibility.**

- The class keeps Django's name, `SessionStore`. Django imports `engine.SessionStore`, and the signing
  salt comes from the class name, so sessions written before the change keep decoding, and old and new
  workers share sessions during a rolling deploy.
- The async methods delegate to the sync ones, so no async path keeps the whole-dict overwrite.

**No global `transaction_mode`.** The compare-and-swap is one autocommit statement, so no read-then-write
transaction needs SQLite's `IMMEDIATE` mode.

## Consequences

- **Same-key edits.** Concurrent requests no longer undo each other's unrelated changes. Two requests
  editing the same key, or the same group, still resolve last-writer-wins. That is documented, not
  merged.
- **A stale validation group.** A stale request that rewrites `user_memberships` restores the validation
  group as it saw it, possibly with an older `membership_hash`. The next validation detects the hash
  mismatch and refetches within one cycle, and Platform re-checks membership on every call.
- **Cookie expiry.** The cookie expiry is computed by the middleware from the request's own view; the
  stored row's expiry follows the merged data.
- **Cost.** A contended save costs one extra read per attempt. The common case is one `UPDATE`, as
  before.
