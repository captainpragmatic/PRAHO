# CrowdSec host contract (protocol 1)

This is the restricted interface for ADR-0067. The signed bouncer 0.0.36 failed
CIDR qualification; the selected reproducible 0.0.36-praho.1 build passes native
packet checks. Host-role and production gates remain separate. See the
[candidate comparison](crowdsec-bouncer-trials.md) and implementation ledger.

## Owned host state

Role: `deploy/ansible/roles/crowdsec/`, disabled unless `crowdsec_enabled: true`;
`crowdsec_simulation: true` by default. Engine `1.8.2`, signed nftables package
`0.0.36`, separately installed patched bouncer `0.0.36-praho.1`.
Artifact lock: `deploy/crowdsec/artifacts.lock.json`.
Hub leaves are copied by exact lock hash, never installed as collections.

Root-owned private configuration: `/etc/praho-crowdsec/config.json`.
Keys: `protocol` (1), `installation_id` (UUID), `configuration_digest` (64 lower-case
hex SHA-256 of canonical policy), `simulation` (boolean), `protected_cidrs` (canonical
inventory CIDRs), `database_witness` (`device` and `inode`) and `policy`.
Policy fields are exactly `schema: 1`, `host_kind: node|portal`, `simulation`,
`protected_cidrs`, `artifact_lock_sha256`, `bouncer_binary_sha256` and
`managed_files` (fixed absolute path to SHA-256 mapping). The digest hashes UTF-8
JSON with sorted keys, separators `,` and `:`, and no nonfinite numbers. It excludes
installation UUID, database witness and credential contents. Root-owned installation
state: `/var/lib/praho-crowdsec/`.
The root-private `engine-applied.sha256` and `bouncer-applied.sha256` files in that
directory each contain the exact applied configuration digest plus one newline.
Before changing policy files or service runtime, invalidate the affected witness;
write it only after successful service convergence. This prevents interrupted
changes or a rollback from qualifying old running state against new disk bytes.
Health, snapshots and receipt reads require both matching witnesses. They are
excluded from the policy hash to avoid self-reference.
The LAPI database is fixed at `/var/lib/crowdsec/data/crowdsec.db`; replacement
requires reenrollment, never automatic identity regeneration during convergence.
Enrollment must bind the database incarnation: a dedicated installation UUID
machine marker created once through supported cscli plus recorded database
device/inode. Read only that nonsecret machine ID; never machine credentials.
Restores or database-file replacement require reenrollment even if config survives.

Owned nftables schema: family `ip` table `praho_crowdsec4`, family `ip6` table
`praho_crowdsec6`, chain `input`
type `filter`, hook `input`, priority `-10`, policy `accept`. Sets `protected` have
the family's address type and `interval` flag; `bans` have address type and
`interval,timeout` flags. Two ordered rules: source address in `@protected` returns, source
address in `@bans` drops. No other owned rules/hooks are admitted. Bouncer uses
set-only mode with `set_only_intervals: true`, `blacklists_ipv4: bans`,
`blacklists_ipv6: bans`. Installed binary: `/usr/local/libexec/praho-crowdsec-bouncer`.
The systemd override preserves the signed package's original binary. Distinct
table names avoid the candidate's name-only table lookup across address families.

LAPI: `127.0.0.1:8080`. No public listener; no outbound CAPI, console or telemetry.
Gateway principal `praho-crowdsec`, home `/home/praho-crowdsec`, shell `/bin/sh`;
root-owned `.ssh/authorized_keys`, key option `restrict`. Canonical sshd Match:
`ForceCommand sudo -n /usr/local/libexec/praho-crowdsec-gateway`, `PermitTTY no`,
`DisableForwarding yes`. Global forwarding policy remains disabled. Sudo permits
that executable with no arguments only, with `env_reset`, a fixed secure PATH and
an exact `env_keep += "SSH_ORIGINAL_COMMAND"` exception so command rejection survives sudo.
The helper refuses nonempty SSH_ORIGINAL_COMMAND, command-line arguments and TTY.

## Wire envelope

One UTF-8 JSON object, EOF terminated. Fields exactly: `protocol` (integer 1),
`request_id` (UUID), `installation_id` (expected UUID), `configuration_digest`
(expected 64 lower-case hex), `operation` (enum), `payload` (object).
Duplicate keys, unknown fields, trailing objects, nonfinite numbers, arbitrary
commands/paths/URLs, malformed types and oversized input are errors.

Operations/payload: `health: {}`, `snapshot: {"after_alert_id": nonnegative integer}`,
`receipt_get: {"request_id": UUID}`. Mutations use the exact payloads below.
An unsupported or malformed request has no mutation authority.

Success fields exactly: `protocol`, `request_id`, `installation_id`,
`configuration_digest`, `operation`, `result`. Errors use nonzero exit status;
consumers must discard the entire response on any error or malformed/truncated JSON.
No secrets or native exception text in errors. Limits: 64 KiB stdin, 8 MiB stdout,
10,000 active decisions, 1,000 alerts per batch, 30-second wall deadline.

Snapshot results contain `decisions`, `alerts`, `alert_watermark`, `has_more`,
`observed_at`. Read exact approved summary columns in one read-only SQLite
transaction, sanitize and buffer all output, close transaction, then emit JSON.
Use pinned schema validation and fail on drift. Never select raw samples, events,
metadata, account identifiers or messages. IDs may have gaps; watermark advances
to last returned alert, or retained maximum when catch-up is complete. Decisions
always form a complete active snapshot. Schema incompatibility, identity mismatch,
oversize output or nonzero exit advances no cursor and changes no mirror rows.

Each decision has `id`, `created_at`, `expires_at`, `scenario`, `type`, `scope`,
`value`, `origin`, `simulated`. Each alert has `id`, `created_at`, `scenario`,
`event_count`, `scope`, `value`, `simulated`. Scope is canonical `ip` or `range`;
aggregate alerts without a source have null scope and value. Timestamps include
a timezone. Labels use a bounded alphabet; manual/import summaries normalize to
`cscli/manual` and `cscli/import` so import filenames cannot escape as scenarios.

Health fields are exactly `observed_at`, `simulation`, `engine`, `bouncer`,
`firewall`, `clock`, `configuration`. Engine and bouncer each expose `active`
(boolean) and `version` (string or null). Firewall exposes `qualified` and
`ban_sets_empty` (boolean or null when unobservable); configuration exposes
`qualified`. Clock exposes `synchronized`, `qualified`, `offset_seconds`,
`maximum_error_seconds`, `estimated_error_seconds`; numeric observations may be
null. Qualification requires synchronization and all three errors within one
second. Unsupported clock inspection fails qualification. Active processes and
an exact firewall schema do not establish recent bouncer pulls or decision/kernel
agreement; the Security page reports those separately.

An absent `receipt_get` returns exactly `{"status":"unknown","evidence":"no_receipt"}`.
Absence of a receipt is never proof that an earlier mutation did not happen.

## Audited mutations and receipts

`ban_put` payload keys are exactly:

```json
{
  "provenance_id": "UUID",
  "revision": 1,
  "kind": "manual",
  "scope": "ip",
  "value": "198.51.100.8",
  "expires_at": "2026-11-04T12:05:00Z",
  "source": null
}
```

Replica kind is `replica` and requires `source` with exactly `installation_id`,
`decision_id`, `scenario`, `configuration_digest`. The source installation differs
from the destination and the scenario belongs to the fixed sharing candidates.
Platform additionally requires explicit current coverage approval and fresh
qualified source/target clocks; the helper independently checks the replica clock.
IPv4-mapped host literals are normalized to IPv4 before creating a ban. CIDRs are
specific canonical networks; overlap with inventory/staff protection is rejected
in either containment direction. Simulation refuses both create kinds.

The helper freezes the effective deadline on first admission, at or before the
requested absolute expiry and the host limit (five minutes Portal, four hours
node). It never renews it. LAPI receives a fixed `stop_at` and duration so a delayed
POST cannot acquire a fresh lifetime. Pinned LAPI replaces supplied native UUIDs;
the private scenario marker and journal provide PRAHO provenance instead.

`revoke` has exactly `provenance_id`, positive `revision` and `decision`. The last
field is null for owned provenance, or the complete decision object returned by a
snapshot for a native decision. Recheck the fingerprint and native UUID before
supported LAPI deletion; a reused numeric ID cannot name a different decision.
An owned decision cannot be paired with another provenance or fingerprint.
Record the tombstone before network mutation. An earlier unresolved create keeps
revocation uncertain until observed and removed, or until its fixed deadline.

`allowlist_replace` has exactly positive `revision` and sorted canonical `cidrs`
(at most 256). It reconciles the complete `praho-staff` list; inventory protection
is immutable. Adding an allowed address can expire an overlapping broader ban and
therefore affect other addresses. Verify both the list and affected decisions.
The pinned LAPI trusts precomputed manual decisions even when allowlisted: an
earlier unresolved POST must also reconcile before full replacement success.

Root-private `operations.sqlite3` and `actions.lock` live in the existing private
state directory. Persist issuance before LAPI/CLI work, release SQLite transactions
before I/O, and serialize mutations with the file lock. CLI children inherit that
fence so a dead parent cannot admit a competing writer while its CLI still runs.
Never update CrowdSec tables directly. Receipts are namespaced by installation.
Canonical payload SHA-256 hashes UTF-8 JSON of `{"operation": operation,
"payload": payload}`, sorted keys, compact separators and no nonfinite values.
Reusing a request UUID with different canonical content is refused.

Known mutation/receipt results have exactly `status`, `evidence`, `request_id`,
`operation`, `payload_digest`, `provenance_id`, `revision`, `decision_ids`,
`expires_at`, `observed_at`. Status is `succeeded`, `unknown`, `superseded` or
`rejected`. IDs are verified observations of the intended decisions, not arbitrary
caller IDs. A business refusal returns a recorded result with exit zero; protocol
or qualification failures return nonzero and commit no Platform observation.

Receipt reads make no writes. An uncertain create is never re-POSTed. Only a
positively reconciled revoke/list repair may repeat the same recorded request;
`pending_create` and `operation_pending` remain read-only waits. Changing helper
configuration does not discard an old receipt belonging to the same installation.
LAPI confirmation does not prove immediate kernel removal or complete enforcement.

## Portal acquisition and privacy

Portal policies additionally bind three committed local leaves under
`praho_portal.files` in the artifact lock: parser `praho-portal-auth.yaml` and
scenarios `praho-portal-auth-bf.yaml`, `praho-portal-auth-throttle.yaml`. Nodes do
not install them. Acquisition reads only
`/var/log/praho/portal/portal-auth.jsonl`; native enablement rejects another path.

Events have exactly six keys: `schema: 1`, UTC `timestamp`, enumerated `event`,
canonical `ip` or null, daily keyed `account` pseudonym or null, enumerated `reason`.
No email, user/session ID, credentials, request body, URL, exception or event sample
is emitted. The parser copies IP/service/event/reason into metadata and omits the
account pseudonym. Password/MFA failures and actual login/MFA/reset middleware
throttles are counted; infrastructure failures and passive reset requests are not.
These scenarios remain local. No port-scan coverage is claimed.

The writer uses private bounded rotating files and a per-write OS lock/reopen so
Gunicorn workers do not keep writing to unlinked backups. A busy or failed writer
reports degradation without refusing a valid login. `/status/` reports conservative
per-worker last-recording observations, not global pipeline readiness.

Completed password/MFA success sends the trusted client IP inside the existing
signed API body. After the authentication/session transaction commits, Platform
records all active memberships in a separate bounded transaction under a fresh
user lock. Recording failure preserves the session. Anonymization deletes the
observations, export includes them, and seven-day pruning rechecks age at DELETE
so a concurrent refreshed login survives. Customer matches are database queries;
they prioritize CRITICAL warnings and preserve the recorded ban's fixed expiry.

## Qualification integration

Base profile remains `virtualmin-web-only-v2`. Adoption explicitly selects
`virtualmin-web-only-v2+crowdsec-v1` and requires fresh evidence. Profile choice
must persist independently from synchronization enablement; never downgrade
automatically. Every inspection, digest, review, admission and execution consumer
must agree. Extension admits only the above owned schema, loopback 8080 and the
exact restricted gateway principal/effective SSH policy. Unexpected nft facilities,
public LAPI or unrestricted SSH still fail. Native inspection emits sanitized
complete technical facts; application validation never trusts a mere installed flag.
