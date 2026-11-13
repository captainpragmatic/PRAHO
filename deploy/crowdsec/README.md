# CrowdSec qualification artifacts

The original signed bouncer **failed CIDR qualification**. The selected patched
build passes packet qualification; host-role and production gates remain open.
See the [comparison](../../docs/security/crowdsec-bouncer-trials.md) and
[ledger](../../docs/security/crowdsec-implementation.md).
The [operations procedure](../../docs/security/crowdsec-operations.md) covers
explicit inventory selection, policy preview, simulation and host qualification.

`artifacts.lock.json` pins exact packages, the reproducible patched build and
14 individually selected Hub leaves with explicit host scope. The signing
key is public. `provenance/` archives the signed InRelease and exact compressed
indexes used on 2026-11-03, so future repository rotation cannot erase the evidence.
Local Git attributes preserve these cryptographic inputs byte-for-byte, including
upstream signed whitespace.
Package and generated binary bytes are not committed. The packet tests verify the
selected build's size and hash before execution. Explicit rejected-package trials
download the locked package or read `CROWDSEC_ARTIFACT_DIR`, then verify size, hash
and package version before extracting its binary. TLS/HTTPS and nftables handling
are real; the packet fixture replaces only the local LAPI stream and executes no
package maintainer scripts. Separate role fixtures qualify actual installation.

Verification chain: compare the signing key's primary fingerprint with
`6A89E3C2303A901A889971D3376ED5326E93CD0C`; verify the archived InRelease signature
with that key; compare each compressed index's SHA-256 and length against the
signed SHA-256 section; decompress each index and match package name, exact
version, architecture, filename, size and SHA-256 with the lock; finally verify
actual downloaded package bytes. The signing subkey is
`C358C5638A13ACC3A665A9419EB2753BF09DFB77`.

Hub leaf URLs bind the immutable commit as well as SHA-256. No collections or
leaves with external `data` dependencies are selected. Replication candidates
are an allowlist for future qualification, never authorization to copy generic
SSH alerts without proving the administrative listener provenance. HTTP probing
and Webmin authentication remain local. Package authenticity and leaf hashes
do not establish runtime compatibility or detection coverage.

`make build-crowdsec-patched` reproduces both architecture binaries. The default
`make test-crowdsec-docker` selects these locked bytes and builds them if absent.
`CROWDSEC_BOUNCER_REJECTED_PACKAGE=1` explicitly reproduces the original package's
two CIDR failures. Trial overrides require both `CROWDSEC_BOUNCER_BINARY` and its
explicit `CROWDSEC_BOUNCER_SHA256`; the normal target accepts only locked hashes.
The release candidate's CrowdSec job runs this target when no nightly proved it on the candidate's commit.
