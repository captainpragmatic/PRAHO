# CrowdSec foundation contract (protocol 1)

This is the interface for ADR-0067's first wave. The signed bouncer 0.0.36 failed
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
`receipt_get: {"request_id": UUID}`. The initial gateway implements read-only
operations only; `ban_put`, `revoke`, `allowlist_replace` are reserved and refused
until the audited-actions wave. No side effects from an unsupported request.

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
agreement; the Security page must report those separately in the later wave.

The initial `receipt_get` returns exactly `{"status":"unknown","evidence":"no_receipt"}`.
Absence of a receipt is never proof that an earlier mutation did not happen.

## Qualification integration

Base profile remains `virtualmin-web-only-v2`. Adoption explicitly selects
`virtualmin-web-only-v2+crowdsec-v1` and requires fresh evidence. Profile choice
must persist independently from synchronization enablement; never downgrade
automatically. Every inspection, digest, review, admission and execution consumer
must agree. Extension admits only the above owned schema, loopback 8080 and the
exact restricted gateway principal/effective SSH policy. Unexpected nft facilities,
public LAPI or unrestricted SSH still fail. Native inspection emits sanitized
complete technical facts; application validation never trusts a mere installed flag.
