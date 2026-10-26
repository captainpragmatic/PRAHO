# SSH access and deployment hardening

Status: native SSH hardening deployed and verified on staging, 2026-10-26.
Both staging applications are deployed and healthy. Managed-node integration is
implemented and reviewed under `MANAGED_NODE_SSH_PLAN.md`, without a managed-host
rollout.
No production rollout is authorized.

## Native staging evidence

- Ubuntu 26.04.1 LTS on the operator's independently inventoried staging host.
- All three selected agent public keys independently authenticated as root on
  9876. Effective policy: `PermitRootLogin prohibit-password`,
  `AuthenticationMethods publickey`, password and keyboard-interactive disabled.
- IPv4/IPv6 SSH listeners are on 9876; the controller verified 22 is unreachable.
- Repeat `make ssh-harden ENV=staging` succeeded, including detection of 9876
  while the operator file still specified the former bootstrap port.
- Six real Ubuntu 24.04/26.04 SSH tests passed: cutover, repeat, invalid keys,
  blocked port and deterministic rollback before/after activation. Activation,
  commit and rollback share phase locking and ownership validation.
- Runtime tests installed PostgreSQL 16 and shared uv-managed Python 3.13 on
  both distributions and verified readability by a separate service user.
- Native deployment defaults to 2 GB swap and one web worker per service on
  staging. Production keeps two web workers per service; its planned hosts have
  4 GB RAM and 2 GB swap. No production host has been changed.
- Both staging application hostnames are DNS-only A records at the verified
  inventory address. Environment-specific names and addresses stay in operator configuration.
- The initial application deploy used main revision
  `296170734f8b4e6a201241437411f42641f67e57`. Subsequent deployments pin the exact
  reviewed merge SHA; the verified live revision belongs in the private inventory.
- Both entire staging sites enforce the seven approved public IPv4 sources plus
  loopback. Controller HTTPS checks passed; unapproved live requests receive 403
  for API, health, static, login and webhook routes, including spoofed headers.
  Production Portal remains public; Platform restriction is a separate rollout.
- The 2 GB swapfile is live and persistent. All five native services are active.
  A backup smoke check created a private PostgreSQL archive and `pg_restore --list`
  read it successfully. A complete isolated restore rehearsal is still pending.

SSH-only rollout completed through the shared playbook. The launch plan's
Tailscale-only ingress restriction remains a separate, pending network step.

## Accepted policy

Root may authenticate with approved public keys. All users must use public keys:
password and keyboard-interactive authentication are disabled. The final SSH port
is 9876. Install all three public keys selected from the operator's SSH agent,
additively, before disabling password access. Keep operator keys in ignored local
configuration, not in committed source. Never copy private keys to a server.

## Research and alternatives

Before this work, the native `common` role opened 22 and configured fail2ban without
sshd hardening. Managed nodes had partial hardening, but clients, host-key lookup,
health checks, drift remediation and cloud firewalls assumed 22. Ubuntu 24.04
socket activation requires updating the listening socket as well as sshd.

Relevant sources inspected:

- `deploy/scripts/native_env.py`, `deploy/ansible/playbooks/native-single-server.yml`,
  `deploy/ansible/roles/common/tasks/main.yml`, the native inventory and jail template.
- `services/platform/infrastructure/ansible/playbooks/common_base.yml`,
  `virtualmin_harden.yml`, `group_vars/all.yml` and `ansible.cfg`.
- `services/platform/apps/infrastructure/ansible_service.py`, `models.py`,
  `deployment_service.py`, `registration_service.py`, `validation_service.py`,
  `drift_scanner.py`, `drift_remediation.py`, `cloud_gateway.py`.
- `services/platform/apps/provisioning/virtualmin_auth_manager.py`, `virtualmin_models.py`.
- Existing deploy tests, native-env tests, node service tests and Virtualmin lab adapters.

Alternatives: changing only sshd loses clients and risks lockout; changing all
defaults to 9876 loses existing nodes and first boot. Use an explicit bootstrap
connection port and persist the verified port for managed nodes. Reuse a single
Ansible role for the policy and transition. Preserve legacy port 22 until each
host has completed its own migration.

## Execution order and verification

### 1. Establish staging key access independently

Use the operator-supplied staging inventory. Verify its host identity and addresses
before making changes; an IPv6 network allocation is not a verified host address.
Do not touch production or infer IPv6 host addresses.

- Export public identities from the agent to a protected temporary directory.
- Connect with strict host-key checking; on this brand-new host permit first-use
  `accept-new` once and retain the observed host key. Never replace a known key.
- Use the supplied password only through an interactive password prompt if the
  initial key login fails. Inspect the hostname, OS, addresses, SSH and firewall
  configuration before changing anything.
- Actual login banner: Ubuntu 26.04.1, matching IPv4 and IPv6 address
  2a01:4f9:c015:4d96::1. PAM requires a first-login password change. Generate a
  random replacement in a root-operator-owned 0600 recovery file within a 0700
  temporary directory before submitting it through a non-echoing pexpect PTY.
  Disable child logs and never print captured buffers or credentials. Prove the
  replacement through a separate password-only root connection (with the same
  pinned host key) before changing authorized_keys. On ambiguous outcome, test
  the saved replacement first, never blindly repeat rotation.
- Add missing public keys to root's authorized_keys without removing existing
  keys. Preserve permissions (root-owned directory 0700, file 0600); reject
  symlink/unexpected file types rather than redirecting into them.
- For each public key, independently connect using `IdentityFile=<public file>`,
  `IdentitiesOnly=yes`, `BatchMode=yes`, publickey-only authentication and
  `ControlMaster=no`/`ControlPath=none`. Use `-F /dev/null` and explicit agent,
  user, port, StrictHostKeyChecking=yes and pinned UserKnownHostsFile so inherited
  identities cannot falsely satisfy the check. Require all three to succeed. Make no
  sshd or firewall change in this first step.

Both required reviews completed. Bootstrap execution succeeded: three keys added,
three isolated root key logins passed, root .ssh/authorized_keys permissions are
0700/0600. The staging host has approximately 1 GiB RAM and 20 GiB
disk. At that bootstrap checkpoint SSH remained on 22; the verified cutover to 9876
followed. The initial expired password was rotated and privately retained
for recovery, with a successful fresh password login before key enrollment.

### 2. Add tested SSH deployment inputs

Files: `deploy/scripts/native_env.py`, both native inventories, environment
templates, Makefile, and a new standalone SSH playbook.

- Add explicit current connection port (default 9876 for normal deployment),
  operator public-key file and verified known-hosts file inputs. First bootstrap
  can explicitly select 22; no password is stored in environment files.
- Provide an SSH-only Make target usable before application/DNS configuration.
  Normal deploy invokes the same role. Runtime clients never silently choose
  password authentication.
- Failing tests first in `tests/deploy/` for input validation, literal env parsing,
  agent-based access and the standalone/deploy wiring. Then implement and run
  `make test-deploy`, Python syntax and file lint checks.

### 3. Implement and exercise the SSH transition

New shared role under `deploy/ansible/roles/ssh-hardening/`; reused by management
and node playbooks. This role owns a supported Ubuntu/Debian sshd baseline.
Existing custom Match/chroot/access restrictions must be detected and reviewed,
not silently overwritten. Validate candidate configuration before activation.

- Preflight root/controller credentials, public key data, current connection,
  target port and trusted host key. Fail before SSH/firewall mutation on missing
  inputs. Approved operator keys are additive to provisioning/deployment keys.
- Open 9876 in the host firewall before changing listeners. Cloud firewalls must
  allow 9876 first as well. Keep the bootstrap listener available during handoff.
- Remove native common's UFW reset and give the shared role sole ownership of SSH
  allow rules. Native common continues managing HTTP/HTTPS and the default deny
  policy. Node and panel firewall tasks must consume the verified SSH port and
  never reopen 22 after completion. Test normal deploy and repeat-deploy wiring.
- Stage validated policy, update/reload systemd socket units on Ubuntu 24.04 or
  the SSH service where socket activation is absent. Preserve existing sessions.
- Verify a new controller connection on 9876 with publickey-only auth, no SSH
  connection multiplexing, and the SAME host key trusted on the old port. This
  cannot be satisfied by TCP reachability alone.
- Only after that succeeds remove the bootstrap listener and port-22 firewall
  allowance, reload and verify the final fresh connection again. On failure keep
  or restore the previously verified path; surface the failure. Do not continue
  application deployment after incomplete hardening.
- Check effective `sshd -T` policy and fail2ban's port. A disposable Linux SSH
  target must exercise successful cutover, rejected credentials, repeat execution,
  and failure recovery before applying the transition to staging.
- Detect the active SSH socket/service at runtime. For supported Ubuntu 24.04 and
  26.04 systemd units, require ssh.service KillMode=process (preserved sessions).
  When ssh.socket is active, manage an explicit ListenStream reset/drop-in for
  the chosen ports, daemon-reload, then restart socket and service together. With
  inactive socket, reload/restart ssh.service. Reject unsupported service units,
  nonempty SSHD_OPTS or unrecognized custom SSH unit overrides before mutation.
  Test both actual distributions with disposable systemd targets.
- Keep a root-only backup of config/socket overrides and arm a bounded systemd
  rollback timer before activation. A failed/unreachable controller leaves the
  timer able to restore the previously verified listeners. Cancel only after
  fresh authenticated proof. Use another protected rollback snapshot for the
  final single-port activation so its rollback restores the verified dual-port
  state, not an obsolete port. Retain backups for operator recovery.
- During handoff set the active inventory host's ansible_port to 9876, reset its
  connection, and run an actual remote command before removing 22. All proofs
  use publickey-only authentication with multiplexing disabled.

### 4. Make managed-node connections follow the verified port

Files: infrastructure/provisioning models and migrations; `ansible_service.py`,
`validation_service.py`, `drift_scanner.py`, `drift_remediation.py`,
`registration_service.py`, `virtualmin_auth_manager.py`, node group vars,
`common_base.yml`, hardening playbooks, provider firewall definitions and lab adapters.

- Persist current SSH port on NodeDeployment and VirtualminServer, defaulting
  existing records to 22. Registration copies the verified node port.
- Persist the node's enrolled SSH host public keys in a node-scoped database
  field (public data), not a deleted per-run scan file. Explicit enrollment is
  part of fresh cloud-server creation only. Import an operator-configured pin
  for existing nodes; missing trust refuses migration and requires enrollment.
  Render temporary OpenSSH files and Paramiko HostKeys from that same durable
  pin for both IP/FQDN and old/new-port names. Never replace a conflicting pin.
- Move node hardening before panel installation. Persist 9876 only after the
  role proves successful cutover. Interrupted first-run recovery checks the new
  port with the pinned identity before retrying the explicitly recorded old path;
  never use a host-key/authentication failure as a reason to replace trust.
- Use a dedicated transition operation for both initial deployment and direct
  security-maintenance entry points. Prepare existing provider firewall rules
  explicitly: those nodes bypass create_firewall, and provider APIs currently
  expose no unified update operation. An unchanged provider firewall must cause
  the new-port proof to fail while the old path remains usable.
- Existing cloud firewall preparation is a mandatory operator step before invoking
  migration: add TCP9876 for the same admin source CIDRs in the provider console
  and preserve existing rules. Require an explicit preparation input for legacy
  migrations; newly-created gateway/Terraform firewalls supply both ports. The
  actual authenticated connection on 9876 remains the final end-to-end evidence,
  and failure restores prior access. No auto-delete/recreate provider firewalls.
- Pass the chosen port consistently to readiness checks, inventory, Paramiko,
  host-key lookup/scan, probes and remediation. Preserve scoped lab overrides.
- Cloud firewall bootstrap rules allow 22 and 9876; the completed host policy
  closes 22. Restrict admin CIDRs as existing policy requires. Update fail2ban.
- Feed approved operator public keys from platform configuration into node
  playbooks without leaking secrets. Remove Virtualmin SSH password fallback.
- Write failing behavior tests first for port propagation, legacy defaults,
  trust continuity, partial cutover recovery, registration and key-only clients.
  Run focused infrastructure/provisioning suites, migrations and syntax/lint gates.

### 5. Verify and roll out only to staging

- Internal review and Codex review must resolve critical/high lockout or trust
  regressions before execution. Review all SSH consumers again with repository-wide
  searches; document deliberate bootstrap/lab references to 22.
- Apply the reviewed playbook to the supplied staging host. Confirm each operator
  key works on 9876, passwords/keyboard-interactive are disabled, port22 is closed,
  and a repeat run is successful. Record exact evidence without credentials.
- Application staging deployment remains gated by its own env/DNS preflight and
  existing CI/readiness findings. No production deployment and no unapproved
  commit, tag, branch push or staging branch fast-forward.
