# CrowdSec qualification artifacts

These are **rejected qualification candidates**, not deployable approvals. The
actual bouncer fails IPv4/IPv6 CIDR enforcement; `make test-crowdsec-docker` keeps
that acceptance gate visible. See the [ledger](../../docs/security/crowdsec-implementation.md).

`artifacts.lock.json` pins exact packages and 14 selected Hub leaves. The signing
key is public. `provenance/` archives the signed InRelease and exact compressed
indexes used on 2026-11-03, so future repository rotation cannot erase the evidence.
Local Git attributes preserve these cryptographic inputs byte-for-byte, including
upstream signed whitespace.
Package binaries are not committed. Tests download the appropriate locked package
or read `CROWDSEC_ARTIFACT_DIR`, then verify size, hash and package version before
executing its bouncer binary. TLS/HTTPS and nftables handling are real; the test
replaces only the local LAPI stream. No package maintainer scripts are executed.

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
