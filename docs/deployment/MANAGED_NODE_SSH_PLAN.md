# Managed-node SSH integration

Implemented and reviewed in the SSH-hardening worktree. This extends the tested
native transition to hosting-node provisioning
and maintenance. These application changes and migrations are not part of the
staging application's pinned main revision. No managed-node or production rollout
has been performed.

Verification: 831 infrastructure and related provisioning/lab-adapter tests passed,
including real database enrollment/port propagation and legacy configured-pin
resolution. Both reviews found no remaining material issue after the shared legacy
resolver correction. Model/migration checks, changed Python syntax/lint and native
Terraform validation passed. A live managed-node rehearsal remains required before
a managed-host rollout. The native SSH transition has already passed its real
Ubuntu 24.04/26.04 container drills and the staging host rollout.

## State and trust

- Preserve the controller authentication key as well as the host identity. When
  `external_node_id` exists, provisioning retries must retrieve the existing
  deployment key from the vault rather than generate/overwrite it. Missing
  credentials fail explicitly. A retry must not replace either side of trust.
- Add `NodeDeployment.ssh_port` and `VirtualminServer.ssh_port`, default 22 for
  existing records, validated 1–65535. A linked server reads its deployment's
  current port; the server field is the fallback for manually registered servers.
- Add `NodeDeployment.ssh_host_keys`, public key lines only. Default empty string
  means a legacy node without enrolled trust. Nullable `None` means an explicitly
  new provider VM is awaiting its first enrollment. Nonempty text is the durable pin.
- Mark enrollment pending and reset port to 22 only when a genuinely new provider
  server was created. Retrying an existing external server ID never resets its pin.
  Save that marker with the new provider ID/IP. Existing legacy nodes require an
  operator-configured verified known_hosts entry and never silently rescan trust.
- Legacy Ansible, SSH validation, certificate pinning and linked Virtualmin clients
  share the same configured-pin resolver and CAS enrollment. A fresh unenrolled
  VM cannot use the validation resolver to bypass its bootstrap enrollment.
- For fresh pending VMs, wait for bootstrap SSH, scan once, validate key data and
  save using a compare-and-set on node ID/provider ID/IP/pending marker. A racing
  enrollment cannot replace a winning pin. Reject scan/enrollment failures.
- Render OpenSSH aliases for bare hostnames/IPs and bracketed nonstandard ports
  from the same durable pin. Use HostKeyAlias to keep the identity stable on the
  Ansible connection. Paramiko receives the same keys and RejectPolicy, without
  ambient host keys taking priority over an enrolled node identity.

## Connection and transition

- Add a dedicated managed-node `ssh-hardening.yml` playbook reusing the native
  `ssh-hardening` role via the repository roles path. It receives source CIDRs
  from the existing node-admin allowlist, approved public keys from a root-owned
  controller file, the deployment identity and the rendered pinned known_hosts.
- The native application deploy installs the approved PUBLIC key file at
  `/etc/praho/operator_authorized_keys` for Platform/Q-cluster node operations.
  No human private keys are copied. Missing operator keys/allowlist/trust stops
  node hardening before mutation.
- Invoke the dedicated transition before common-base or either panel's direct
  hardening operation. Do not depend on full initial provisioning to run it.
  Remove competing sshd writers from common-base and panel hardening playbooks.
- Before connecting to an explicitly recorded bootstrap port, probe 9876. If it
  is reachable, require fresh root key authentication against the durable pin,
  with no multiplexing. Authentication/trust failure never falls back to 22.
  A successful connection alone never changes the recorded port. Inspect the
  remote transaction ownership/state through that authenticated connection and
  refuse or wait while a transition owns the host, including pending rollback.
  An idle recovered listener can be used as an ephemeral Ansible connection to
  finish the dedicated transition. Persist 9876 only after that transition has
  committed, released ownership and verified final policy. A stale committed
  owner requires an explicit operator recovery; never automatically steal a lock.
- A successful transition must verify root key access and final effective policy
  before updating database state. On failure surface the error and leave the
  last verified port recorded. A retry can recover a committed remote phase.
- Initial and maintenance runs use the same timed rollback, ownership and phase
  locking already tested for Ubuntu 24.04/26.04. Custom access policy is rejected
  for review rather than overwritten.

## Consumers and firewalls

- Update inventory, SSH readiness, Paramiko validation, quick health, drift
  scanner/remediation and Virtualmin SSH sudo fallback to use the recorded port.
  Virtualmin SSH access becomes key-only; its HTTP API port remains 10000.
- Host firewall and fail2ban consume the verified SSH port. Remove hardcoded
  port-22 allow rules that would be restored by a subsequent panel deploy.
- New gateway/Terraform firewalls allow bootstrap 22 plus target 9876 under the
  same existing administrator CIDRs. Existing provider firewalls need 9876
  opened before migration; the bounded controller reachability probe detects a
  missing rule before changing SSH. Do not delete/recreate existing firewalls.
- Preserve the lab's explicit forwarded SSH endpoints. Its context manager may
  adapt the transition hook only for its validated disposable targets; no
  production skip flag. Keep legacy/test bootstrap-port references intentional.
- Target Ubuntu 26.04 for new Hetzner nodes as well as management hosts. Verify
  provider image identifiers rather than inventing numeric IDs for other clouds.

## Verification

1. Tests first for legacy defaults, fresh enrollment persistence, rejection of
   untrusted legacy nodes, compare-and-set races, recovery on 9876, port propagation,
   linked-server source of truth, registration and key-only clients.
   Include an interrupted handoff with an existing provider ID, durable host pin
   and original authentication key: the vault credential stays unchanged and a
   fresh pinned connection succeeds on 9876.
   Also cover authentication during a pending dual-port phase followed by its
   timer restoring 22: recovery must not persist 9876 while rollback can close it.
2. Check model/migration state and grep every consumer before a deployment that
   includes the migrations. Run Python syntax/lint before reviewers.
3. Run focused infrastructure/provisioning tests and lab adapter tests. Exercise
   both direct maintenance and initial provisioning wiring. Existing native
   unit, Ubuntu SSH and native-runtime tests remain required.
4. Both required plan reviews precede implementation. Review material auth,
   trust, concurrency and migration findings before a hosting-node rollout.
# Supported node images

Automatic node deployment and retry currently support Hetzner with the Ubuntu
26.04 image only. AWS, DigitalOcean and Vultr provisioning is refused before
bookkeeping, key generation or cloud mutations until their image selectors are
verified against the supported Ubuntu 24.04/26.04 releases. Catalog refresh and
credential storage remain available for those providers.

Existing Ubuntu 22.04 nodes must be upgraded or migrated by the operator before
running the mandatory SSH transition or panel maintenance. The SSH role rejects
unsupported distributions in its first task, before changing SSH configuration.
Keep the existing port and verified keys for the operator's OS migration. Do not
retry provisioning to perform an OS upgrade.

Legacy direct Terraform is outside the SDK deployment guard. Operators must
explicitly select and verify an Ubuntu 24.04/26.04 image before applying it. Vultr
uses `os_id`, not `server_image`; verify that effective OS identifier. The legacy
defaults are not an approved supported-image selection.

## Container operator keys

Native deployment installs the approved public-key bundle automatically. Container
operators who enable managed-node deployment must mount that public file into both
Platform and Q-cluster. For example, from the repository root:

```bash
PRAHO_ENV_FILE="$PWD/.env.staging" \
PRAHO_SSH_PUBLIC_KEYS_FILE=/absolute/path/operator_authorized_keys \
  docker compose --env-file .env.staging \
  -f deploy/docker-compose.single-server.yml \
  -f deploy/docker-compose.node-ssh.yml up -d
```

The same overlay works with `docker-compose.platform-only.yml`, `docker-compose.dev.yml`
and local `docker-compose.container-service.yml` execution. It requires an existing
file, mounts it read-only, and fixes the application's key-file setting to that
mount. Do not put private keys in this file. Managed container platforms must provide
an equivalent read-only configuration-file mount for both services. The Portal does
not receive these keys. Deployments that do not provision nodes need no overlay.

Both node deployment entry points validate the approved bundle before changing
bookkeeping or creating cloud resources. Missing, empty or malformed keys return an
explicit prerequisite error. The SSH playbook receives the validated key snapshot.
