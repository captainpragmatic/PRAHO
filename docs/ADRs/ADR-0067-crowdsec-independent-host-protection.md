# ADR-0067: CrowdSec independent host protection and Platform pull

- Status: Accepted design; qualification candidates, not deployment approval
- Date: 2026-11-03
- Author: Claudiu Ciungan
- Related: #767, #770, #769, ADR-0016, ADR-0017, ADR-0020, ADR-0030, ADR-0035, ADR-0060

## Context

Each host must protect itself while Platform is unavailable. Customer workloads run
on hosting nodes, so no new inbound connection into Platform is acceptable. A
central LAPI and cloud remediation synchronization violate that boundary. Existing
fail2ban is local only and has no staff view. Portal rate limiting does not remove
host traffic, and bans on shared customer addresses need urgent visibility.

## Decision

Deliver #767 before #770. Every host retains independent engine, loopback LAPI and
nftables enforcement. Platform initiates every connection and owns a sanitized
database mirror. Production Portal uses native systemd/Caddy on #769's separate
host, direct HTTPS and DNS-only DNS records. Staging uses the same host helper
locally. Platform-only production hosts receive no CrowdSec. Docker-published
Portal ports are outside this INPUT-only design.

### Reproducible qualification candidates

Qualification candidates are engine `1.8.2`, nftables bouncer `0.0.36`, Hub commit
`58d35d108bb310f2ca0bf16c043715f15477adc1`, repository primary fingerprint
`6A89E3C2303A901A889971D3376ED5326E93CD0C`. The committed
[`artifacts.lock.json`](../../deploy/crowdsec/artifacts.lock.json) records package
bytes for amd64/arm64, signed metadata identities and selected leaf hashes.
Package authenticity does not prove runtime compatibility. Never silently move a
pin when qualification fails. Bouncer `0.0.38` is absent from this repository and
does not change its nftables implementation from `0.0.36`.

Install individual parser/scenario leaves only. Initial selection: syslog, SSH,
Apache, Caddy, Webmin, date and HTTP parsers; SSH brute force/user enumeration,
slow brute force, SSH CVE-2024-6387, HTTP CVE-2021-41773/42013, HTTP probing and
Webmin brute force. This is an explicit minimal set, not full collections. Leaves
requiring external data, automatic discovery, GeoIP, RDNS, CDN allowlists and
mutable Hub refresh are excluded. Host-native parser/acquisition fixtures must
still prove coverage; package presence is insufficient.

Before installation, configure telemetry/online-client/console exclusion, pinned
Hub policy and service-start guards. PRAHO owns only its dedicated INPUT chains
and protected-address sets. The bouncer owns only its ban sets, in set-only mode.
Preserve UFW and unrelated tables. Inventory protections cannot be weakened by
staff-managed allowlists. Reject protected CIDR overlap in either containment
direction, even when a proposed ban is wider than a protected subnet.

CrowdSec is disabled by default. Explicit enablement starts in simulation. Simulation stops the bouncer,
clears owned ban sets, refuses manual/replicated creates, and permits revocation
and allowlist repair. Remove fail2ban only after replacement installation and
native qualification are proven. Preserve unchanged `virtualmin-web-only-v2`
behavior; adoption selects `virtualmin-web-only-v2+crowdsec-v1` and requires fresh
evidence. Persist profile selection independently of synchronization enablement,
so disabling synchronization cannot resurrect an older attestation.

### Restricted host interface

Use one `praho-crowdsec` SSH identity with strict enrolled host keys, forced fixed
root-owned helper, working login shell, no forwarding and no PTY. Staging invokes
that helper via a no-arguments sudo grant. Preserve `SSH_ORIGINAL_COMMAND` through
sudo so the helper can reject arbitrary commands. No shell interpolation of input.

Protocol v1 carries request UUID, expected installation UUID and configuration
digest. Operations: `health`, `snapshot`, `ban_put`, `revoke`,
`allowlist_replace`, `receipt_get`. Initial read-only delivery refuses the three
mutation operations until durable audited action machinery exists. Reject unknown
fields, duplicate keys, trailing input, commands, paths and URLs. Limits are
64 KiB request, 8 MiB snapshot, 10,000 decisions, 1,000 alerts and 30 seconds.
The exact contract is [crowdsec-contract.md](../security/crowdsec-contract.md).

Upstream alert listing defaults to 100 and LAPI lacks the required pagination.
Read approved summary columns from the role's fixed SQLite database in one
read-only bounded transaction. Validate the pinned schema, buffer sanitized data,
close the transaction, then return JSON. Mutations use supported local LAPI/cscli
operations; never write CrowdSec's database directly. Include a complete active
decision snapshot, alert watermark and explicit `has_more`. Decision freshness
and alert catch-up are separate. Truncation, schema drift, identity mismatch or
nonzero exit commits neither mirror changes nor cursors.

### Identity, scheduling and uncertainty

Each physical LAPI installation has independent identity. Bind enrollment to the
actual database incarnation; retain retired history and require explicit
reenrollment on database replacement. Do not recreate an absent enrollment marker
on ordinary role convergence. The Platform `security` app owns source identity,
decision/alert mirrors, sync state, allowlists, action issuance, target results
and replication provenance. No raw log lines, messages, samples or event metadata
are mirrored.

Coalesce minute work before enqueueing; fence claim token, generation, lease and
connection identity. Never hold database locks across remote I/O. Persist action
issuance before dispatch; bind idempotency keys to canonical payloads and retain
helper receipts plus monotonic provenance revisions. A timeout after dispatch is
unknown until read-only reconciliation resolves it. An absent marker cannot prove
that a request had no effect. Revocation suppresses the source decision and all
PRAHO replicas; unresolved earlier creates prevent claiming complete revocation
until reconciliation or expiry.

Copy only explicitly qualified administrative SSH brute-force/user-enumeration
and the pinned SSH/HTTP CVE scenarios. Verify administrative SSH provenance:
customer SFTP uses a distinct source and stays local. HTTP probing, Webmin and
Portal authentication also stay local. Do not claim initial port-scan coverage.
Replicas never replicate, preserve original absolute expiry and retain provenance.
Portal replica expiry is fixed on first admission to the earlier of source expiry
and admission plus five minutes; it is never renewed. Unqualified clocks suspend
copying. Retain ended decisions 90 days, alerts 30 days and customer-IP observations
seven days.

### Staff visibility and Portal

`/security/` reads Platform's database only: decisions, simulated alerts, filters,
source freshness, action outcomes, separate detection/enforcement health. Admins
manage all; support/managers view and revoke; billing has no access. Desktop and
mobile navigation share that explicit policy. Use shared UI, i18n, CSRF and audit
coverage; page rendering never contacts a host.

Caddy overwrites forwarding headers and strips incoming Cloudflare IP headers.
Dedicated sanitized events cover actual password failures, second-factor failures,
reset requests and middleware throttle refusals. Use a daily keyed account
pseudonym, never raw account identifiers or secrets. Preserve private failure
categories through both API-client normalization layers while browser responses
stay generic. Infrastructure failures do not count as attacks.

Only complete password/MFA success records the authenticated forwarded customer
IP, for all active memberships. Integrate seven-day observations into export and
existing anonymization, including login/erasure races. Matching active IP/CIDR bans
appear first as CRITICAL warnings while short bans remain enforced. A recording
failure exposes degraded protection without refusing a successful login.

## Delivery and verification

First wave: ADR/artifact lock, optional qualification extension, shared simulation
role, read-only gateway. Freeze interfaces before parallel ownership. Integrate
qualification before enabling the role. Later waves add mirror/scheduling, read-only
page, audited actions, replication, Portal instrumentation and Portal protection.
Each behavior follows a meaningful failing test, implementation, then regression
verification. Keep signed changes small and record progress in the
[implementation ledger](../security/crowdsec-implementation.md).

Use Ubuntu 26.04 systemd/SSH/UFW fixtures and nftables namespaces. Explicit
`make test-crowdsec-docker` runs nightly and in every release candidate that cannot
reuse the nightly's proof for its commit (amended November 2026, ADR-0036; it left
the merge queue). Prove restricted SSH, bounded snapshots over 100 alerts, schema/replacement
refusal, real HTTPS drops after positive controls, protected access, both address
families and CIDRs, UFW/reboot/restart/simulation ownership, real PostgreSQL races,
Portal throttle/header/MFA/outage/erasure paths, RBAC/CSRF, and 390/820/1280 px UI.
Run repository lint, types, audit, integration and security checks plus an
independent silent-failure review. Passing userspace Docker tests proves behavior
on the runner kernel; production still requires the actual Ubuntu 26.04 kernel,
qualified clocks, #769 topology and rehearsed console recovery.

Default durations: node four hours, Portal five minutes; stale after three minutes.
Observe simulation for 48 hours, then one enforcing node for 24 hours before
expansion. Qualify Portal separately. No production rollout follows merely from
merging an implementation PR.

## Consequences

Hosts keep local protection during Platform outages. Platform remains the sole
initiator and staff pages remain available without host RPCs. Exact source identity,
strict bounded snapshots and uncertain-action reconciliation increase complexity,
but prevent silent data loss, accidental expiry renewal and unsafe blind retries.
Candidate failures block dependent work rather than weakening these contracts.

## References

- [CrowdSec 1.8.2 alert listing](https://github.com/crowdsecurity/crowdsec/blob/v1.8.2/pkg/database/alerts.go)
- [Bouncer 0.0.36 nftables](https://github.com/crowdsecurity/cs-firewall-bouncer/blob/v0.0.36/pkg/nftables/nftables.go)
- [Bouncer 0.0.36 to 0.0.38](https://github.com/crowdsecurity/cs-firewall-bouncer/compare/v0.0.36...v0.0.38)
- [Signed package metadata](https://packagecloud.io/crowdsec/crowdsec/any/dists/any/InRelease)

## Qualification amendment, 2026-11-03

The signed bouncer 0.0.36 fails real IPv4/IPv6 CIDR enforcement. Under authorization
to try both remediation paths, upstream experimental PR #523 and a smaller
release-derived set-only patch both passed the 13 core packet cases. The working
simulation candidate is `0.0.36-praho.1`, built reproducibly from the original
source commit with pinned Go 1.27.3 and unchanged dependencies. Further qualification
rejected upstream PR #523 because a real zero-second LAPI duration creates a
permanent ban. The PRAHO patch handles elapsed durations, preserves kernel expiry
across stops, restarts from a full snapshot after a failed atomic write, and uses
a bounded socket buffer proven with 10,000 decisions. Install it separately from the signed package binary and
use interval+timeout ban sets with the opt-in backend. Exact hashes and source
provenance are locked. See [the trials](../security/crowdsec-bouncer-trials.md).
This amends the candidate artifact choice; it does not waive host installation,
configuration, kernel or rollout qualification.
