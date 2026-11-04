# CrowdSec implementation ledger

Original baseline: `9fd0d62fcbb288e9e766e6ede9403a4b2745f3eb`.
Integrated master: `5107c72377a0c53d3b81aad9b3bd8e39bb9452d9`.
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
Host protection, the fenced mirror, audited actions, qualified copying and Portal
instrumentation are integrated. Native evidence is at the userspace/runner-kernel
boundary; actual staging enrollment and production enablement remain operational
acceptance gates.

| Order | Outcome | State |
|---|---|---|
| 1 | KB decisions, ADR-0067, exact package/Hub/build lock, gateway contract | Recorded; both remedies tested; patched build selected |
| 2 | Optional persistent qualification profile and all consumers | Implemented; base preservation, exact native evidence and one-way legacy retirement verified |
| 3 | Shared simulation role | Complete native installation/convergence/acquisition/lifecycle, interrupted repair and explicit installation-bound fail2ban retirement pass |
| 4 | Bounded restricted gateway | Strict schema/identity/privacy checks, supported LAPI mutations, immutable receipts, late-create repair and applied-state witnesses pass unit/native qualification |
| 5 | Mirror, coalesced work, fencing and retention | Integrated; independent PostgreSQL connections prove ownership, connection/generation fencing, catch-up and retention |
| 6 | Database-only Security page | Explicit shared navigation/RBAC policy, source management, filters, separate freshness/health and Chromium checks at 390/820/1280 px |
| 7 | Audited actions and uncertain-result reconciliation | Integrated; issuance precedes I/O, immutable request identities and per-target results preserve unknown outcomes; native receipts and actual transport adapter verified |
| 8 | Qualified replication and revoke races | Integrated; exact scenario/acquisition/ingress approvals, no loops, fixed Portal admission expiry and delayed-create/revoke races pass PostgreSQL checks |
| 9 | Portal sanitized instrumentation/customer observations | Integrated; real middleware/MFA/outage paths, concurrent rotation, signed successful-login IPs, CRITICAL matching, export and both erasure race orders verified |
| 10 | Staging source, separately qualified Portal protection | Local staging enrollment UI/settings/role and native Portal qualification implemented; actual enrollment/observation pending, production also requires #769 |

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

## Integrated application verification

The combined PostgreSQL run passes **350 tests**, including Security, Portal
authentication/MFA, customer observations and current master's teardown
regressions. A broader authentication/users/audit/qualification selection passes
**2,694 tests**; the complete final Security app passes **170 tests**. Security
tests use independent connections and observed blocking for
duplicate work, publication drift, admission/revoke, delayed remote creation,
receipt reconciliation, erasure and retention refresh. Network calls hold no
source database locks. Both new schema branches migrate forward and reverse,
then merge without losing either feature's tables.

The complete native CrowdSec run passes **43 cases**, including eight mutation
cases and the Portal role trajectory. Positive HTTPS controls precede actual
IPv4/IPv6 drops; protected access continues, simulation clears owned bans and
does not reuse historical simulated alerts for enforcement. These fixtures
generate contract-shaped Portal events; actual application middleware/auth paths
are exercised separately. They do not run the complete deployed two-service
Portal stack or prove synchronized production clocks.

The Portal suite passes **2,231 tests and 1,588 subtests** (three existing skips,
four existing deselections). The integrated root run needed a focused rerun of
eight sandbox socket failures; all ten tests in those two modules passed with
local socket access. The non-Docker CrowdSec suite passes **277 tests**, and all
**25 existing SSH tests** pass. Full type checks pass for **762 Platform** and
**113 Portal** files. The initial local verification recorded the following
results; the revised head must also pass the complete remote gates below:

| Check | Result |
|---|---|
| `make test-integration` (Docker excluded and run separately) | 1,523 passed; 961 subtests passed; 11 existing skips; 108 deselections |
| `make test-deploy` | 622 passed; 33 subtests passed |
| `make test-deploy-docker` | 29 passed, including real HTTPS forwarding-header replacement |
| `make lint` and `make check-types` | All phases pass; 762 Platform and 113 Portal files type-check |
| `make test-i18n` and `make i18n-check` | 144 tests pass; complete, compiled, extraction-stable Romanian catalogs |
| `make check-migrations` | 156 checksums verified, model state unchanged, table names/comments preserved |
| `make test-security` | Portal business-data/import isolation passes |
| Strict committed-code Semgrep against integrated master | 72 changed files, 1,072 configured rules, zero introduced findings; no rule timeouts |
| Real Chromium Security surfaces | 24 cases at 390/820/1280 px; 44 px effective targets, 16 px fields, local table scrolling |

The existing full native run covers 43 cases; after adding explicit fail2ban
retirement, the complete affected role trajectory passes again (695.59 seconds).
Simulation preserves active legacy protection; qualified enforcing adoption
records durable intent before purging it. Ordinary deploys, queued handlers,
interrupted apply, rollback and later simulation cannot revive retired protection.
The helper separately passes strict typing and lint. No helper/artifact pin changed
for this retirement extension.

The first aggregate integration run identified missing `InterfaceError` fallback
handling and an ambiguous transport method name. Fault tests were observed red
before fixing the internal recorder and both queue handlers; 39 focused SQLite
tests and 14 subtests then pass, followed by the complete PostgreSQL and integration
runs above. The outer authentication boundary already preserved valid sessions.
The adapter now uses `send_request`, preserving the Virtualmin coverage guard.
Uniform credential-refusal tests retain identical signed responses across unknown,
inactive, locked and wrong-password cases, including their fixed private category.
The code-derived audit document is regenerated; audit fixtures resolve the actual
model ContentType instead of assuming database ID 1.

Both scanner false positives are explained at their exact sites: SQLite timeout
PRAGMAs accept only the fixed integer or an integer read from that connection,
and the source form has its CSRF token as the first child. CSRF denial paths pass.
These are narrow annotations, not disabled guards or test suppressions.

## Remote review status

The complete implementation is consolidated in the ready-for-review
[#861](https://github.com/captainpragmatic/PRAHO/pull/861). The nine predecessor
drafts are closed; no predecessor merge is required. It will land through the
repository's squash merge queue after its required checks pass.

The first complete remote run exposed four gaps that the earlier local selections
did not cover: builder-CPU-dependent toolchain text in the license archive,
SQLite secret-context trigger loss when rebuilding the node table, incomplete
status-page user fixtures, and customer-IP observation erasure coverage. Those
failures are merge blockers and require regression verification on the repaired
head and its queued squash commit. Local amd64-builder emulation is unavailable
(`exec format error`); GitHub's native amd64 qualification verifies that build.

An additional full native rerun passed 43 cases but found inconsistent interval
JSON during a concurrent 10,000-decision set dump. Two controlled reproductions
returned an inverted range with 276 or more seconds of TTL left, while live
point-membership and HTTPS checks passed. After the qualified stop preserved
kernel sets, exact cardinalities were 9,998 IPv4 and two IPv6 decisions, with all
boundaries and protected access intact. The capacity test now proves live
enforcement, stops the writer, and performs the unchanged strict cardinality,
endpoint and gap checks on stable sets. The affected native test passes; no
malformed range is accepted, no assertion removed, and no runtime binary changed.

Review also reproduced two Portal gaps: deployed settings replaced the dedicated
event logger, and MFA-management APIs omitted the privately verified refusal
category. Shared logging configuration now keeps the approved acquisition sink
in effective production/staging settings, and recording health requires an
approved handler to accept the record. Fresh-process logging/settings regressions
pass 36 tests and 16 subtests; all 18 existing event/privacy/rotation cases pass.
MFA metadata is assigned at the actual password/code verification boundaries and
survives both Portal normalizers without changing browser messages or sessions.
The focused Platform suite passes 91 tests and 83 subtests, and Portal regression
passes 33 tests and 19 subtests. Validation, policy, limit and infrastructure
refusals remain excluded from authentication-failure counts.

The real Platform-to-Portal refusal test also requires Portal's declared
dependencies. An isolated Platform/dev-only environment reproduced the remote
failure as a missing `altcha` import. The two Platform test jobs and full-suite
release-candidate job now include the Portal dependency group; service import
isolation remains enforced. The same isolated environment with that declaration
passes six refusal/trajectory tests and 26 subtests. Existing credential tests
assert the two exact private categories separately and retain the identical
public error envelope, audit count and enabled-factor assertions.

A local whole-Platform run exposed one fixture that claimed an unconfigured
seller address without overriding inherited company settings. Explicit injected
address settings reproduced it; blank settings on that single case preserve its
assertions, and the complete PDF module passes 41 tests under the injected
environment. A separate two-process cold-open probe reproduced local Darwin
`ENOENT` during simultaneous creation of the same lock inode, while the directory
remained linked. The concurrent-rotation fixture initializes the private lock
through the real handler and closes it before forking. It retains all 100 exact
worker events, requires actual rotation and verifies that the shared inode stays
stable. No writer retry, timeout budget or runtime protection changed. Final
required checks still run on the published head and its queued squash commit.

The required CI native phase passed on GitHub's amd64 runner. Inspection of the
longer aggregate phase then found that `make test-integration` also collects
`tests/deploy/`, repeating the same 44 CrowdSec native cases. CI now excludes
exactly those files from that aggregate step, after their mandatory dedicated
execution. Local Make defaults and all unrelated Docker coverage remain intact.
Actual collection proves that 44 dedicated cases and 1,600 aggregate cases are
disjoint and reproduce the full 1,644-case set, including all 36 other
`*_docker.py` cases and all 53 Caddy cases. Generated UUID parameter labels are
normalized without collapsing distinct cases for this comparison. The workflow
guard was observed failing before the scoped exclusion; all 52 CI-contract
tests pass afterward. The revised required job must still finish on its final
head and queued commit.

A Linux control also reproduced immediate inode reuse in a replacement fixture:
unlinking the database and writing invalid bytes reached SQLite's corruption
error instead of the expected identity error. The CLI already rejects both.
The fixture now creates a valid copy while the original inode remains allocated,
atomically replaces it, verifies the unchanged machine marker, and requires the
exact changed-witness refusal. Production protection remains unchanged.

GitGuardian's GitHub App flags two public
`CROWDSEC_SSH_CONFIG_DIGESTS` values as generic high-entropy secrets. These are
SHA-256 fingerprints of the complete canonical sshd configurations for the two
supported `AuthorizedKeysFile` variants; they contain no key or credential data.
The focused `test_ssh_extension_has_exact_forced_command_and_preserves_base_digest`
checks recompute both from the public template and pass. The findings require
false-positive classification in the GitGuardian dashboard/check-run UI;
repository ggshield ignore settings do not classify GitHub App incidents.
No guard was disabled, hash obscured, or secret material added to resolve them.

Romanian catalog additions use the standard gettext extraction names, retain
existing translations and ship compiled runtime catalogs. The current master's
read-only catalog guard is retained alongside the native CrowdSec CI target.

## Integration findings to preserve

Master's assigned-hosting-limits change (#849) landed while this implementation
was queued. The integration retains its current-row/batched connection identities,
original-key authority, quota fields and native acceptance gates alongside the
CrowdSec profile, artifact/key bindings and one-way legacy retirement. Additive
`0037_merge_crowdsec_hosting_limits` joins both provisioning branches; neither
parent's frozen migrations changed. All 166 checksums and schema checks pass
against both parents. Focused behavior, audit, scheduler, controller and workflow
checks pass, as do complete lint/types (789 Platform and 113 Portal files).

The reviewed catalog merge preserves runtime translations from both parents and
passes compilation and fresh extraction with 7,339 active Platform entries.
Collection after integration proves 44 dedicated native cases plus 1,636 aggregate
cases exactly cover the full 1,680-case selection. Actual SQLite/PostgreSQL
initialization, existing CrowdSec forward/reverse identity guards and legacy
admission checks pass; the additional branch-order history checks were still
running at publication. Required PR and queued-commit checks run on the combined
tree before merging.

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
- Supported native LAPI creates can assign their own decision UUID and accept a
  manual POST despite allowlist membership. Bind results to observed native
  decision IDs/UUIDs, persist intent before dispatch and preserve pending-create
  barriers before declaring revoke/allowlist repair complete.
- Coverage approvals bind the exact acquired journal/listener and separately
  proven administrative-only SSH/customer-SFTP exclusion. A familiar scenario or
  journal name alone never authorizes propagation.
- The optional customer observation runs after the successful authentication
  transaction commits, then re-locks the current user in a bounded independent
  transaction. Deferred commit errors cannot undo a valid session; erasure in
  either lock order leaves no revived observation.
- Portal events use a six-field whitelist and daily keyed account pseudonyms.
  A private interprocess lock and reopen-before-write preserve current rotated
  files across workers. Outages do not count as attacks, and recording failure
  degrades status without introducing a login refusal.

## Remaining gates

The candidate blocker is resolved; see [the comparison](crowdsec-bouncer-trials.md).
Userspace integration and trusted-manifest binding are verified. Actual-host
gates remain: enroll the selected staging installation, prove synchronized
clocks and real acquisition/ingress, rehearse console recovery, observe
simulation for 48 hours, then one enforcing node for 24 hours. Portal is qualified
separately and production requires #769's split-host topology and the actual
Ubuntu 26.04 kernel. Both architecture binaries are reproducible; local native
runtime evidence is arm64 only. No deployment or production acceptance follows
from documentation, signed artifacts, host controls or runner-kernel tests.
