# CrowdSec bouncer qualification trials

Date: 2026-11-03. Authorization: test both a reproducible patch and an upstream
alternative. Design: [ADR-0067](../ADRs/ADR-0067-crowdsec-independent-host-protection.md).

| Candidate | Source | Native result | Delivery implication |
|---|---|---|---|
| Signed package 0.0.36 | Repository lock | 2 host controls pass; both CIDR cases fail | Rejected as enforcing binary |
| Released 0.0.38 / main | Same nftables source blob as 0.0.36 | Source confirms unchanged prefix stripping | No fixed released alternative |
| Upstream PR #523 | `8be9a74e69208dfcd1eb5d3de0af25e85c1171ce` | First 13 packet cases pass; zero-duration case fails | Rejected without a duration fix |
| 0.0.36-praho.1 | Pinned release plus opt-in interval patch | Packet/elapsed-duration/recovery cases and 10,000-decision capacity pass | Selected userspace-qualified candidate; actual-host production gate remains |

## What the packet checks prove

Actual TLS/HTTPS traffic reaches every test source before enforcement. The same
cases then prove individual IPv4/IPv6 bans, first/interior/last range members,
outside neighbors, protected administrative access, overlapping host/range
revocation, independent expiry, restart from current LAPI state, both families
together, empty-set reconciliation and preservation of an unrelated nftables table.
The actual bouncer binary runs; only the local LAPI is replaced at its boundary.

The corrected LAPI fixture emits complete deletion records and remaining TTLs
on startup. Pinned engine source confirms that normal writes create new IDs,
expiration moves `until` to now, and repeated same-ID responses carry a shrinking
remaining duration. Arbitrary full-TTL resurrection after revocation is not a
normal engine sequence and was not used as a required qualification assertion.
This does not weaken helper-side receipt/revision/tombstone requirements.

Original package confirmation after these fixture corrections still produced
exactly 2 passes / 2 CIDR failures. Candidate checks therefore prove the specific
range fix rather than merely broad regression success.

## Upstream alternative

[PR #523](https://github.com/crowdsecurity/cs-firewall-bouncer/pull/523) enables
experimental ranges using interval sets and a new dependency. Exact source tar
SHA-256: `a3538683dff9c72db9e78e181baf6d968f26ea5b457460d070c79b1b84707c0e`.
Trial arm64 binary SHA-256:
`5c69ae7d991fa887d7c3ba0680ac0a3b3bbe924c01a5beafe92209b1274cbef8`.
It was cross-built with Go 1.26.3. Upstream unit tests passed; native packet
qualification passed 12 cases together and the final dual-stack case on a focused
rerun after repairing the unrelated-table fixture literal. No upstream defect is
claimed from the earlier malformed fixture or incomplete deletion records.

An additional native case failed: an elapsed decision with duration `0s` becomes
a permanent ban. A positive-duration overlapping range still works, isolating the
failure to expired membership rather than packet routing. This is a real LAPI
sequence: pinned engine 1.8.2 selects against the stream's starting time and rounds
remaining duration during serialization, so a decision can reach zero or negative
duration before its response is consumed. The PR's `ruleFromDecision` maps zero to
an unbounded expiry. The alternative therefore requires a duration fix before it
can be qualified. The PRAHO patch passes the same case.

The latest released version and main retained nftables source blob
`dbd97cfefb2d5a2b39ef4c3c8b955593f1de74ae`. A tested open PR is useful prior art,
but it is not a maintained released artifact or an automatically approved pin.

## Reproducible release-derived patch

The selected trial keeps upstream default behavior, adding opt-in
`nftables.set_only_intervals: true` for PRAHO's existing set-only ownership model.
It validates a complete frame before atomically replacing both families' ban
sets, partitions overlaps by maximum applicable expiry without enumerating IPs,
preserves the first expiry of a live decision and keeps revocation history only
until that expiry. A 10,000-active-decision limit refuses a batch without dropping
existing state. Unsupported decision types/scopes are filtered before parsing,
preserving upstream behavior. Family-aware table lookup avoids name collisions.

Go unit tests were first observed failing against unchanged source and the
supported-type regression was separately observed failing before correction.
All upstream Go tests and the new interval tests pass. The final Go 1.27.3 build
passed the core packet and elapsed-duration cases. Three further real-kernel cases
prove expiry while stopped, failed atomic-write resynchronization, and 10,000
disjoint decisions with correct HTTPS/protected behavior. A bounded, verified
per-socket send buffer carries the complete atomic frame without host sysctl
changes. An independent no-cache rebuild reproduced both architecture binaries
and the license/source archive byte-for-byte. Exact source, patch, recipe, dependency and
binary hashes are in [the artifact lock](../../deploy/crowdsec/artifacts.lock.json).

The builder image is pinned by OCI digest. Dependencies are validated by unchanged
`go.mod`/`go.sum`, vendored, and compiled/tested without network access. Build paths
and timestamps are normalized. No new dependency is added. Build with
`make build-crowdsec-patched`; run Go tests with `make test-crowdsec-patch` and native
checks with `make test-crowdsec-docker`. The explicit rejected-package reproduction
uses `CROWDSEC_BOUNCER_REJECTED_PACKAGE=1`, retaining its expected CIDR failures.

## Limits

Actual packet tests used arm64 Ubuntu 26.04.1 userspace on runner kernel
`7.0.14-linuxkit`; amd64 bytes were cross-built and reproduced, not runtime-tested
on amd64 hardware. Separate native role/gateway suites establish installation,
acquisition, convergence, UFW reload/container reboot and restricted read-only
execution on the same runner kernel. They do not establish recent bouncer pulls,
complete ongoing enforcement, amd64 runtime or production-kernel qualification.
See the [implementation ledger](crowdsec-implementation.md).
