# CrowdSec implementation ledger

Baseline: `9fd0d62fcbb288e9e766e6ede9403a4b2745f3eb`.
Updated: 2026-11-04. Design: [ADR-0067](../ADRs/ADR-0067-crowdsec-independent-host-protection.md).

## Current boundary

The signed package bouncer fails native CIDR enforcement. Both requested remedies
have now passed the 13 core packet cases. The upstream alternative then failed
the real LAPI zero-duration case by creating a permanent ban. The selected
`0.0.36-praho.1` patched build passed that case, real failure recovery and
10,000-decision capacity; a clean rebuild reproduced both binaries and the
license/source archive. The complete shared-role trajectory now passes, including
acquisition, convergence, enforcing/simulation transitions, UFW reload, container
reboot and interrupted-apply/rollback repair. The default CI target uses locked
bytes; the rejected package remains an explicit negative reproduction.
Foundation delivery is verified at the userspace/runner-kernel boundary. Mirror
and page work is in a separate checkout; no production enablement follows.

| Order | Outcome | State |
|---|---|---|
| 1 | KB decisions, ADR-0067, exact package/Hub/build lock, gateway contract | Recorded; both remedies tested; patched build selected |
| 2 | Optional persistent qualification profile and all consumers | Implemented; base preservation, exact native evidence and one-way legacy retirement verified |
| 3 | Shared simulation role | Complete native installation/convergence/acquisition/lifecycle and failure-repair trajectory passes |
| 4 | Read-only restricted gateway | 86 unit and 14 native SSH/schema/identity/privacy cases pass; strict applied-state witnesses |
| 5 | Mirror, coalesced work, fencing and retention | In progress in isolated checkout; first six real PostgreSQL ownership cases pass |
| 6 | Read-only Security page | In progress in isolated checkout; DB-only rendering, role/navigation/filter cases pass |
| 7 | Audited actions and uncertain-result reconciliation | Pending mirror/gateway |
| 8 | Qualified replication and revoke races | Pending actions |
| 9 | Portal sanitized instrumentation/customer observations | Pending foundation |
| 10 | Staging source, separately qualified Portal protection | Pending #767; production also #769 |

## Native rejection evidence

Run `CROWDSEC_BOUNCER_REJECTED_PACKAGE=1 CROWDSEC_ARTIFACT_DIR=<package-cache>
make test-crowdsec-docker`, or omit the cache variable to download the original
package with size/hash verification. Restrict to the four original cases with
`PYTEST_ADDOPTS='-k test_pinned_bouncer_enforces_https_and_preserves_protected_addresses'`.
The test executes the actual package binary, with only its local LAPI stream
replaced by a protocol-shaped test server. HTTPS and nftables packet handling are
real. Every source first receives HTTP 200 over TLS; each individual-host ban then
drops HTTPS while the protected source remains reachable even when present in bans.

| Decision | First banned source after decision | Neighbor inside range after decision |
|---|---|---|
| IPv4 host `198.51.100.8` | Dropped | `198.51.100.9` remains reachable (correct control) |
| IPv6 host `fd00:767::8` | Dropped | `fd00:767::9` remains reachable (correct control) |
| IPv4 `198.51.100.8/30` | Dropped | `198.51.100.9` returns HTTPS 200 (failure) |
| IPv6 `fd00:767::8/126` | Dropped | `fd00:767::9` returns HTTPS 200 (failure) |

Fresh result after distinct-family table names: **2 passed, 2 failed**, 21.47 s.
Fixture: Ubuntu 26.04.1 userspace, aarch64, runner kernel `7.0.14-linuxkit`.
arm64 package SHA-256: `b2bc84b28c2ea41823e047f824f4fdd84e65c504865615b4a7d3cb4002ddaa75`.
Each nftables set contains only the first address with nearly five minutes left.
This proves the arm64 candidate is unsuitable, without claiming amd64 runtime,
engine acquisition, installation, dual-stack coexistence or production-kernel qualification.

Source explains the result: `normalizedDecisions` strips the CIDR prefix and
reconstructs a decision without scope; `commitAddedDecisions` inserts one key and
timeout. The timeout-only set matches upstream's own set construction. Adding an
interval flag cannot recover discarded range information. An independent review
confirmed positive controls, routing, correct CIDR bounds, package identity and
the causal source path. The same nftables source blob
`dbd97cfefb2d5a2b39ef4c3c8b955593f1de74ae` appears in both v0.0.36 and v0.0.38.

## Verified artifacts

The repository primary fingerprint and signing subkey match the lock. Archived
InRelease verifies with a good signature. Both compressed index hashes match its
SHA-256 section; all four package versions, architecture, URL, size and actual
bytes match those indexes. All 14 selected Hub leaf hashes match the pinned
commit; parsed YAML has no collection or external data-download dependency.
See [artifact provenance](../../deploy/crowdsec/README.md).

Foundation regression evidence: `make test-crowdsec` passes 194 tests;
the focused Platform profile/review suite passes 29 tests and seven subtests.
The broader related Platform suite passed 103 tests and 65 subtests. Existing
`make test-ssh` passes all 25 tests. The integration target, with browser access,
explicit dev settings, `--nomigrations` and the Docker marker excluded, passes
1,338 tests and 961 subtests (11 existing backend-specific skips). Native CrowdSec
tests run separately. Full project lint/types, audit coverage, migration checksums
and additive forward/reverse DDL checks pass. The strict security scanner passed
after the four signed foundation commits, scanning 15 changed service files with
1,072 rules and reporting no blocking findings. A prior zero-file precommit scan
was not counted as security evidence. All 34 native cases pass (33 final-suite
cases plus the full role trajectory).

## Integration findings to preserve

- Persist a selected profile on `VirtualminServer`, independently of synchronization;
  bind it in connection identity and carry it through review/execution/admission.
  Existing schema-1 evidence forbids extra top-level keys: use bounded service and
  firewall facts, with profile-aware hashing. Preserve base canonical SSH digests.
- All three firewall validators now recognize exact ownership before omitting
  volatile ban members/expiry from review digests; protected membership remains
  bound. Routine bans preserve reviews while unknown facilities still fail.
- Preserve gateway Match settings in both Ansible variable builders on SSH reruns.
  Preserve only `SSH_ORIGINAL_COMMAND` through sudo so arbitrary exec is rejected.
- SQLite summary columns and PRAGMA types are verified against the signed native
  engine. Bind the installation UUID to a
  dedicated cscli-created machine marker and recorded DB device/inode. Never
  recreate that marker during routine convergence or accept DB replacement silently.
- Use distinct IPv4/IPv6 table names; family-aware lookup and simultaneous
  dual-stack enforcement are verified by real packet tests.
- Applied-state witnesses must be invalidated before changing files/runtime and
  written only after successful service convergence. An interrupted apply once
  returned success while a real SSH alert still used the old non-simulation
  runtime. The regression now verifies actual post-repair alerts, degraded reads
  during failure, and B-start/crash followed by rollback to A.
- CLI policy guards must resolve pinned Cobra aliases and interposed global flags.
  Native tests verify refusal of singular mutation aliases and preserve reads.

## Remaining gates

The candidate blocker is resolved; see [the comparison](crowdsec-bouncer-trials.md).
Foundation userspace integration and final trusted-manifest binding are verified.
Later gates include the complete PostgreSQL race suite, UI/Portal paths,
48-hour simulation, enforcing canary and actual
Ubuntu 26.04 production-kernel qualification. No deployment or production claim
follows from the documentation, signed artifacts, host controls or existing tests.
