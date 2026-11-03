# CrowdSec implementation ledger

Baseline: `9fd0d62fcbb288e9e766e6ede9403a4b2745f3eb`.
Updated: 2026-11-03. Design: [ADR-0067](../ADRs/ADR-0067-crowdsec-independent-host-protection.md).

## Current boundary

The exact nftables bouncer candidate **fails native CIDR enforcement**. Dependent
implementation requires an explicit revised artifact choice; do not weaken CIDR
acceptance, silently substitute a package, or enable the role. The real acceptance
tests remain failing, and Integration CI invokes the explicit target for PRs and
merge groups. No runtime role, profile, gateway, mirror or Portal change has landed.

| Order | Outcome | State |
|---|---|---|
| 1 | KB decisions, ADR-0067, exact package/Hub lock, gateway contract | Recorded; candidate rejected by native gate |
| 2 | Optional persistent qualification profile and all consumers | Audited; no edits, awaiting viable candidate |
| 3 | Shared simulation role | Blocked by bouncer CIDR failure |
| 4 | Read-only restricted gateway | Schema/identity/SSH contracts audited; no implementation |
| 5 | Mirror, coalesced work, fencing and retention | Pending foundation |
| 6 | Read-only Security page | Pending mirror |
| 7 | Audited actions and uncertain-result reconciliation | Pending mirror/gateway |
| 8 | Qualified replication and revoke races | Pending actions |
| 9 | Portal sanitized instrumentation/customer observations | Pending foundation |
| 10 | Staging source, separately qualified Portal protection | Pending #767; production also #769 |

## Native rejection evidence

Run `CROWDSEC_ARTIFACT_DIR=<package-cache> make test-crowdsec-docker`, or omit the
cache variable to download the locked package with size/hash verification.
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

Existing regression evidence: `make test-ssh` passed 25 tests. `make test-deploy`
passed 344 tests and 33 subtests, with one Ansible temporary-directory sandbox
failure; its focused rerun passed with `ANSIBLE_REMOTE_TEMP` inside the writable
temporary directory. Focused Ruff and Python syntax checks passed for the new
native test. KB frontmatter/path validation passed. Full application verification
is still required when runtime implementation proceeds.

## Integration findings to preserve

- Persist a selected profile on `VirtualminServer`, independently of synchronization;
  bind it in connection identity and carry it through review/execution/admission.
  Existing schema-1 evidence forbids extra top-level keys: use bounded service and
  firewall facts, with profile-aware hashing. Preserve base canonical SSH digests.
- Three firewall validators reject the new schema today. Validate exact ownership
  before omitting volatile ban members/expiry from review digests; keep protected
  membership bound. Otherwise routine bans invalidate reviews or exceed bounds.
- Preserve gateway Match settings in both Ansible variable builders on SSH reruns.
  Preserve only `SSH_ORIGINAL_COMMAND` through sudo so arbitrary exec is rejected.
- SQLite summary columns are present in pinned generated schema; actual PRAGMA
  types still need native engine qualification. Bind the installation UUID to a
  dedicated cscli-created machine marker and recorded DB device/inode. Never
  recreate that marker during routine convergence or accept DB replacement silently.
- Use distinct IPv4/IPv6 table names: pinned bouncer table lookup compares name
  without family. Simultaneous dual-stack enforcement still requires a native test.

## Remaining gates

The fixed artifact choice must be revised before dependent work. All subsequent
plan requirements remain open, including actual SSH rejection tests, engine
installation/convergence/telemetry, real SQLite snapshot bounds/schema/replacement,
PostgreSQL races, UI/Portal paths, 48-hour simulation, enforcing canary and actual
Ubuntu 26.04 production-kernel qualification. No deployment or production claim
follows from the documentation, signed artifacts, host controls or existing tests.
