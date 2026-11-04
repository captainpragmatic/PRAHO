# CrowdSec operations and qualification

Use when qualifying the opt-in host role from [ADR-0067](../ADRs/ADR-0067-crowdsec-independent-host-protection.md).
This procedure prepares independent local detection, restricted host management,
the Platform mirror and Portal instrumentation. The
[ledger](crowdsec-implementation.md) separates verified implementation from
actual-host rollout acceptance.

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

## Retire existing fail2ban explicitly

Simulation preserves an existing fail2ban installation. Its removal is a separate
explicit choice: after qualifying the enforcing replacement, add
`crowdsec_retire_fail2ban: true` to that reviewed enforcing policy and apply it.
The default is false; simulation and unqualified retirement requests are refused
before host changes. Preview also prints the requested retirement choice.

After applied-state witnesses and canonical engine/bouncer/firewall health pass,
the role writes a root-private, installation-bound **pending** retirement intent
before stopping or purging fail2ban. It records **complete** only after verifying
replacement health, package absence, inactive legacy service and removed jail.
If interrupted, converge the qualified enforcing policy again to finish; a
pending marker does not claim completed removal.

Ordinary common-role deployments and already-queued restart handlers re-read this
state and cannot reinstall or restart retired protection, even when the inventory
flag is omitted or CrowdSec later returns to simulation. Malformed or mismatched
state fails closed. Do not delete the marker to silence an enrollment mismatch.
The unchanged Virtualmin base profile retains its existing purge policy; only
the explicitly selected CrowdSec extension defers legacy removal to this path.

## Staging and recovery

An explicitly shared staging host may use `crowdsec_host_kind: portal`,
`crowdsec_staging_local_source: true` and `crowdsec_local_reader_user` naming its
existing nonroot Platform service account. This grants only no-argument execution
of the same fixed helper through sudo. Node qualification refuses this local grant.
Register the source explicitly using the workflow below.

The Portal service must already run as its isolated nonroot identity with private
`/var/log/praho/portal` (0700). The role creates `portal-auth.jsonl` for that user
(0600); rotation and its lock sidecar also stay private. Keep DNS records DNS-only
and serve direct HTTPS. Caddy overwrites forwarding headers and strips incoming
Cloudflare client-IP headers; Portal trusts only the enrolled proxy CIDRs.

## Enable Platform reads and Portal instrumentation

Enable each facility explicitly in the appropriate service environment. Values
below are examples to enable a qualified staging installation; they are disabled
by default. Paths name separately enrolled operator-owned key files, never keys
in the repository.

```dotenv
# Platform only
PRAHO_CROWDSEC_SYNC_ENABLED=true
PRAHO_CROWDSEC_LOCAL_SOURCE_ENABLED=true
PRAHO_CROWDSEC_SSH_PUBLIC_KEY_PATH=/etc/praho/keys/crowdsec.pub
PRAHO_CROWDSEC_SSH_PRIVATE_KEY_PATH=/etc/praho/keys/crowdsec
CROWDSEC_CUSTOMER_IP_OBSERVATIONS_ENABLED=true
```

The selected Django **staging** settings module authorizes local transport; an
environment variable named `ENVIRONMENT` cannot authorize it in production.
For staging, open `/security/` as an administrator, select **Enroll source**, use
kind Portal, local transport, hostname `localhost`, port `0`, no SSH host keys,
and the installation UUID/configuration digest emitted by the role. Leave the
Virtualmin binding empty. In production use strictly enrolled SSH and keep local
transport disabled. Node sources also require the matching persistent CrowdSec
Virtualmin profile. No enrollment request connects to a host.

The existing native deployment registers the task catalog. For an existing
database, its `setup_scheduled_tasks --security-only` management command uses the
normal deployment environment and registers all four host-security schedules.
Minute work is claimed before queueing; restarting workers cannot create
unlimited overlapping reads. Confirm decision freshness separately from alert
catch-up. A three-minute stale report is visible on Security; a failed poll
retains the last snapshot and reports degradation.

Portal-only environment:

```dotenv
CROWDSEC_AUTH_EVENTS_ENABLED=true
CROWDSEC_AUTH_LOG_PATH=/var/log/praho/portal/portal-auth.jsonl
```

Provision an independent `CROWDSEC_AUTH_PSEUDONYM_KEY` through the existing secret
store. If absent, the writer uses a strongly domain-separated daily HMAC derived
from Portal's Django secret. Never paste that key into a note, command output or
proof document. Native environment filtering passes the Portal key to Portal;
Platform node keys and business database credentials stay out of `.portal.env`.
Native enablement refuses an alternate log path because acquisition is fixed.

Exercise actual wrong-password, wrong-MFA and continued throttled requests, plus
reset throttles. Check the private log contains only the six documented event
fields and that the host produces local simulated alerts. Infrastructure/MFA
store failures must produce unavailable responses without attack categories.
Successful complete authentication records the signed client IP for all active
memberships. Check export and anonymization against the observation table.
Observation or log-write failures report degraded recording and preserve a valid
login. Portal `/status/` exposes per-worker last-recording observations; it does
not prove every worker or the complete detection/enforcement pipeline is ready.

## Audited actions and scenario sharing

After qualification, enable `PRAHO_CROWDSEC_ACTIONS_ENABLED=true` on Platform.
Admins can create finite manual bans, replace the complete staff allowlist,
manage sources and approve coverage. Support/managers can view and revoke;
billing has no access. **Action history** links to each request's target results.
New bans require fresh canonical enforcing health and qualified clocks. Simulation
still permits repair/revocation; it refuses new manual and replicated bans.

A timeout after dispatch is **unknown**. Keep the original request identity and
read its receipt; never submit another ban just because its first response was
lost. Missing receipts prove nothing. Earlier unresolved creates prevent claiming
complete revoke/allowlist repair, even when no decision is visible yet. Per-target
results distinguish verified, rejected, superseded, expired and unknown work.
API removal and kernel removal are separate observations. An allowlist addition
can remove an overlapping broader CIDR ban; inspect the affected decision IDs.

Sharing additionally requires `PRAHO_CROWDSEC_REPLICATION_ENABLED=true` and an
explicit current **Scenario sharing** approval on the source. Prepare bounded
native proof JSON with these exact keys: `schema`, `installation_id`, `policy`,
`acquisition_sha256`, `administrative_ssh`, `ssh_journal_unit`,
`ssh_listener_port`, `http_listener_port`, `portal_http_qualified`,
`qualification_sha256`, `ssh_exclusive_administrative`, `customer_sftp_excluded`.
Use the role's complete canonical policy, hash the whole typed document with the
contract's canonical JSON rules, and enter that SHA-256 as the evidence digest.
No event samples, credentials or raw account identifiers belong in this document.
`qualification_sha256` names independently retained actual-host qualification
evidence, not a claimed package-install success.

For administrative SSH, prove the exact journal unit/listener and that customer
SFTP is excluded; both exclusion facts must be true. A journal/listener name alone
does not prove that separation. Node approval also binds the current native
security review and its physical installation UUID. Portal HTTP sharing needs its
own qualified ingress evidence. Only the fixed SSH/CVE candidates may be selected;
probing, Portal/Webmin authentication and customer SFTP remain local. Coverage
withdrawal serializes with admission and stops queued copies. Configuration,
generation, connection or review changes invalidate old authority.

Original expiry remains fixed. Portal copies are capped at five minutes from
their first Platform admission and never renewed. Copying is suspended when
clocks are unqualified. A CRITICAL customer-IP warning prioritizes review without
revoking the recorded ban. Revoke before retiring a source when removal is needed;
retirement preserves independent host protection and history.

## Console recovery

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

Database identity is bound to a generated installation marker and device/inode.
A changed witness fails closed. Every replacement or restore requires source
retirement and fresh installation enrollment, including VM/filesystem rollback
that preserves those metadata. Filesystem witnesses cannot detect every in-place
rollback. Keep restored sources disabled until requalified; preserve retired
history/receipts and resolve pending operations before replacing an installation.
Routine convergence does not regenerate identity. Do not delete identity files
to make a mismatch disappear. No automatic reenrollment or fleet rollout is included.
