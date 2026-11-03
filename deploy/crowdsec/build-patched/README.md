# Reproducible set-only interval candidate

`make build-crowdsec-patched` builds both Linux architectures from the exact
upstream 0.0.36 source commit, using a digest-pinned Go 1.27.3 image. Source,
patch, recipe, build script, module manifests, vendor tree and output hashes are
recorded in `../artifacts.lock.json`. Dependencies retain upstream `go.mod` and
`go.sum`, pass `go mod verify`, and are vendored before the network-disabled
test/build stages. This patch adds no external dependency. `-trimpath`, fixed
version/build metadata and an empty build ID remove local path/time inputs.

Outputs are under the ignored `build/crowdsec-patched/` directory. To repeat an
independent build with fresh Docker layers:

```sh
CROWDSEC_PATCH_NO_CACHE=1 CROWDSEC_PATCHED_OUTPUT=/tmp/crowdsec-rebuilt make build-crowdsec-patched
```

`CROWDSEC_PATCH_SOURCE` optionally supplies an already downloaded source archive;
the recipe still checks its committed SHA-256. `make test-crowdsec-patch` runs all
upstream tests and the additional Go tests. `CROWDSEC_PATCH_BASELINE=1` deliberately
runs those new tests against the unchanged source and remains red.

## Scope and semantics

The patch is explicitly enabled with `nftables.set_only_intervals: true`. It
requires pre-existing, correctly typed interval+timeout sets in set-only mode.
It never creates a table, rule or set in that mode. Default upstream operation
retains its existing path; table lookup additionally checks address family.

The command loop submits one complete stream frame to the backend. Unsupported
decision types/scopes are ignored before parsing remediation metadata, preserving
the configured ban-only behavior. Malformed supported decisions reject the whole
frame, without changing committed state or kernel rules. Both address families
are replaced in one netlink transaction, touching only the configured ban sets.

Active owners are identified by LAPI decision ID. A repeated live ID cannot renew
its first admitted absolute expiry. An endpoint sweep computes a disjoint exact
address union; every segment expires at the latest expiry of its actual owners.
Deleting one decision preserves independent overlapping owners. No address
enumeration or CIDR broadening is used. Sub-millisecond remainders are omitted
rather than encoded as a permanent zero timeout. Kernel timeouts provide expiry
even while the bouncer is stopped; an empty frame also reclaims expired state.

Known revocations suppress replay until the original expiry; unknown-ID deletes
suppress same-frame creates. History is reclaimed after the original expiry,
matching the real LAPI's remaining-duration stream. This is not a durable action
receipt/tombstone service; PRAHO's audited mutation layer has that separate duty.
Normal and error stops preserve existing kernel timeout sets. Simulation clears
them explicitly after stopping enforcement. A failed interval transaction exits
nonzero, causing a complete startup snapshot rather than losing an already
consumed stream delta. Each atomic transaction requests a bounded 8 MiB netlink
send buffer and verifies the actual grant, avoiding the kernel's small default
buffer without changing any systemwide sysctl.

The 10,000 active-decision bound refuses a whole oversized update without dropping
previous live enforcement. A restart uses the LAPI's complete current startup
snapshot and remaining durations.

## Evidence and limits

The new Go tests failed against unchanged source before implementation. A further
captcha-plus-ban test reproduced a review finding before its fix. Unit coverage
includes IPv4/IPv6 maximum endpoints and `/0`, an independent small-address oracle,
overlaps, immutable live expiry, revocations, malformed batches and capacity.

Both architecture outputs matched byte-for-byte after an independent no-cache
build. The maintained-toolchain candidate passed the native Docker suite,
including real TLS HTTPS drops, exact CIDR boundaries, protected addresses,
overlap/revoke/expiry/restart behavior and preservation of unrelated dual-stack
policy. Native `/0` coverage is not claimed; protected-network admission rejects
such actions. Docker proves the runner kernel and Ubuntu 26.04 userspace, not the
production Ubuntu 26.04 kernel or production acceptance.

The build also produces `license-notices.tar.gz`, with deterministic archive
metadata. It carries upstream MIT, PRAHO GPL-3.0-or-later, Go BSD/PATENTS and
vendored license/notice texts, together with the exact upstream source archive,
patch, recipe, tests and provenance. The role verifies its locked bytes before
installation under `/usr/local/share/doc/praho-crowdsec-bouncer`.
