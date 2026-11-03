# CrowdSec foundation contract (protocol 1)

This is the interface for ADR-0067's first wave. Bouncer 0.0.36 failed native
IPv4/IPv6 CIDR qualification on 2026-11-03; the suite remains red. Never enable
enforcement to work around a failed gate. See the implementation ledger.

## Owned host state

Role: `deploy/ansible/roles/crowdsec/`, disabled unless `crowdsec_enabled: true`;
`crowdsec_simulation: true` by default. Engine `1.8.2`, nftables bouncer `0.0.36`.
Artifact lock: `deploy/crowdsec/artifacts.lock.json`.
Hub leaves are copied by exact lock hash, never installed as collections.

Root-owned private configuration: `/etc/praho-crowdsec/config.json`.
Keys: `protocol` (1), `installation_id` (UUID), `configuration_digest` (64 lower-case
hex SHA-256 of canonical policy), `simulation` (boolean), `protected_cidrs` (canonical
inventory CIDRs). Root-owned installation state: `/var/lib/praho-crowdsec/`.
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
`timeout` flag. Two ordered rules: source address in `@protected` returns, source
address in `@bans` drops. No other owned rules/hooks are admitted. Bouncer uses
set-only mode, `blacklists_ipv4: bans`, `blacklists_ipv6: bans`. This schema itself
is a candidate: test CIDR behaviour against actual bouncer before adoption. Distinct
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

## Qualification integration

Base profile remains `virtualmin-web-only-v2`. Adoption explicitly selects
`virtualmin-web-only-v2+crowdsec-v1` and requires fresh evidence. Profile choice
must persist independently from synchronization enablement; never downgrade
automatically. Every inspection, digest, review, admission and execution consumer
must agree. Extension admits only the above owned schema, loopback 8080 and the
exact restricted gateway principal/effective SSH policy. Unexpected nft facilities,
public LAPI or unrestricted SSH still fail. Native inspection emits sanitized
complete technical facts; application validation never trusts a mere installed flag.
