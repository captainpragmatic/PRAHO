# CrowdSec foundation operations

Use when qualifying the opt-in host role from [ADR-0067](../ADRs/ADR-0067-crowdsec-independent-host-protection.md).
This procedure prepares independent local detection and the read-only gateway.
The Platform mirror, Security page, mutation receipts and replication are later
deliveries in [the ledger](crowdsec-implementation.md).

## Prepare a reviewed host policy

Use Ubuntu 26.04, working console recovery, qualified host clocks and an enrolled
SSH host key. Preserve the existing administrative SSH connection while changing
SSH policy. The controller needs the repository's Ansible environment, `gpg` and
`gpgv`; build artifacts locally with `make build-crowdsec-patched`.

Use an ignored inventory file with the selected host in the `praho` group for SSH
hardening and the `crowdsec` group for the new role. Retain the host's existing
reviewed SSH role variables, administrative keys, port and allowed source CIDRs.
Prepare an ignored YAML policy file containing:

```yaml
ssh_crowdsec_gateway_enabled: true
crowdsec_enabled: true
crowdsec_host_kind: node
crowdsec_simulation: true
crowdsec_enforcement_qualified: false
crowdsec_gateway_public_key: "ssh-ed25519 REPLACE_WITH_DEDICATED_PUBLIC_KEY"
crowdsec_protected_cidrs:
  - 192.0.2.2/32  # Replace with the reviewed administrative/Platform inventory.
  - 2001:db8::2/128
```

The example addresses are documentation placeholders. The protected list must
include every administrative and Platform connection source, in both address
families where used. Loopback is always protected. Use a dedicated gateway key,
separate from the administrative identity. Keep its private half outside the
repository. Platform enrollment must contain the exact host keys and the separate
gateway public key through `PRAHO_CROWDSEC_SSH_PUBLIC_KEY_PATH`.

## Adopt simulation on one host

Both targets require an explicit inventory, host limit and policy file. Paths are
relative to the repository root. First apply the existing transactional SSH role
with the gateway extension, then install CrowdSec:

```sh
make crowdsec-ssh CROWDSEC_INVENTORY=deploy/local/crowdsec-inventory.yml \
  CROWDSEC_LIMIT=qualification-node CROWDSEC_POLICY=deploy/local/crowdsec-policy.yml
make crowdsec-adopt CROWDSEC_INVENTORY=deploy/local/crowdsec-inventory.yml \
  CROWDSEC_LIMIT=qualification-node CROWDSEC_POLICY=deploy/local/crowdsec-policy.yml
```

The role checks the effective restricted SSH context before creating a login key.
It authenticates repository metadata and checks artifact bytes before package
installation, installs guards before maintainer scripts run, pins individual Hub
leaves and rejects unowned configuration. The engine listens only on loopback;
the bouncer remains stopped and owned ban sets are empty in simulation.

To inspect a desired policy before installing it, set `crowdsec_policy_preview:
true` in the reviewed variables file and run the adoption target. Preflight and
rendering print the digest, then end the play before changing CrowdSec host state.
Set preview back to false for adoption.

Record the emitted `PRAHO_CROWDSEC_CONFIGURATION_DIGEST` and
`PRAHO_CROWDSEC_INSTALLATION_ID`. Bind both in the initial gateway request and
require a matching health response. Repeat the same adoption command to
verify convergence. Adding, changing or removing policy requires a fresh digest
and new extension qualification. Setting `crowdsec_enabled: false` leaves the role
untouched; to withdraw enforcement, apply `crowdsec_simulation: true` instead.

The Virtualmin profile selection is persistent. Explicitly select
`virtualmin-web-only-v2+crowdsec-v1` with the reviewed configuration digest before
requesting fresh inspection/review. This withdraws prior admission; disabling
synchronization cannot return the host to an older base-profile attestation.

## Verify and advance

Use `make test-crowdsec`, `make test-crowdsec-patch` and
`make test-crowdsec-docker` for the committed contracts. Native fixtures use actual
Ubuntu userspace, systemd, SSH, nftables and TLS traffic on the runner kernel.
They do not qualify another architecture or the production Ubuntu kernel.

On the actual host, prove acquisition from its configured SSH/HTTP logs, simulated
alerts, telemetry exclusion, exact firewall ownership, protected access, UFW
reload, reboot and bouncer restart. Gateway `engine.active`, `bouncer.active` and
`firewall.qualified` are separate facts. They do not establish recent bouncer pulls
or agreement between all LAPI decisions and kernel membership. Observe actual
enforcement and expose uncertainty when those facts are unavailable.

Observe simulation for 48 hours. Only after fresh native evidence for the actual
host/kernel and rehearsed console recovery, set `crowdsec_enforcement_qualified:
true` and `crowdsec_simulation: false`; preview this new policy to obtain its
digest. Set `crowdsec_expected_configuration_digest` to that value and turn preview
off before applying. Enforcing adoption requires this exact digest. Observe one
enforcing node for 24 hours before expanding. Portal has a separate qualification
and production requires #769's split-host topology.

## Staging and recovery

An explicitly shared staging host may use `crowdsec_host_kind: portal`,
`crowdsec_staging_local_source: true` and `crowdsec_local_reader_user` naming its
existing nonroot Platform service account. This grants only no-argument execution
of the same fixed helper through sudo. Node qualification refuses this local grant.
Registering the source and Portal authentication instrumentation are later work.

For enforcement recovery, use the console to apply the reviewed simulation policy.
The role stops the bouncer, removes its start permission and clears only owned ban
sets. Protected-address repair remains independent from ban membership. Ordinary
bouncer stop/restart preserves existing kernel expiry timers; simulation explicitly
clears them. Preserve UFW and unrelated nftables tables during recovery.

If role convergence itself is failing, use the console to stop this bouncer,
remove its start permission and flush its two owned sets:

```sh
systemctl stop crowdsec-firewall-bouncer.service
rm -f -- /etc/praho-crowdsec/enforcement-ready
nft flush set ip praho_crowdsec4 bans
nft flush set ip6 praho_crowdsec6 bans
```

Check each command's result, administrative reachability and empty owned ban sets.
Repair the reviewed configuration and converge simulation before requalifying
enforcement. An interrupted or failed simulation transition is not completed
simulation; old kernel timers can remain until expiry or explicit recovery.

Database identity is bound to a generated installation marker and the database's
device/inode. Replacement or restore fails closed. Preserve the retired source's
history and explicitly reenroll a new installation after inspection; the role
does not regenerate identity during convergence. Do not delete identity files to
make a mismatch disappear. No automatic reenrollment or fleet rollout is included.
