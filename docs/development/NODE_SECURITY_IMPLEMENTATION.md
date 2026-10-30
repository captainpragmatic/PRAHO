# Node security, imported website migration, and provider cleanup

Approved implementation contract. Work starts from master after PR #802. No live
node changes or provider deletions are authorized by a saved operator review alone.

## Delivery ledger

- [ ] 1. Security inspection evidence, explicit operator decisions and independent server capability.
- [ ] 2. Early, convergent dual-stack firewall with SSH ownership and timed recovery.
- [ ] 3. Durable API enrollment, Webmin principals and restricted operator tunnel.
- [ ] 4. Destination admission and archive compatibility across all worker paths.
- [ ] 5. Component-scoped imported website/files/MySQL migration.
- [ ] 6. Three-provider ownership inventory and explicit restore-point retention.
- [ ] 7. Resumable provider teardown with verified per-resource outcomes.
- [ ] Native lab, provider canaries, documentation, reviews and merge queue verification.

### Current checkpoint

The first slice implements the independent security state, immutable bounded
inspection/decision records, privileged source acknowledgment, identity/digest/
freshness checks, and audit signals. It does not yet collect remote inspections,
expose the operator UI, apply hardening, or enforce destination admission. No
live nodes or provider resources have been changed. Source acknowledgment is
never a verification result. All19 tests passed through the standard Django runner
with migration0020 applied. They cover trust/vault changes and history surviving
node teardown. Full repository make lint, migration consistency checks, and focused
type checks passed. The full make test suite and native lab have not run.
Remaining stages above are pending; this checkpoint does not resolve #768.

## Required behavior

Imports remain allowed. Security state is independent of health/status:
`unreviewed`, `acknowledged_source_only`, `verified_web`. Acknowledged sources
retain their existing services and access. Import, inspection, backup and migration
source operations never implicitly harden them. Generated destinations require live
web-only proof before activation. Existing rows start unreviewed without remote
side effects. Introduce inspection/qualification before enforcing placement gates.

Store bounded, versioned inspection findings and proposed changes in immutable,
superseding reviews attached to VirtualminServer. Bind decisions to the exact
digest, connection identity, native/policy versions, actor, reason and time. Apply
and acknowledgment require deployment permission and CSRF POST. Reinspect before
execution; material drift requires a new preview. Serialize hardening with other
mutating node operations. Preview every principal/CIDR, package/service/listener,
firewall change, interruption, recovery limit and mail/DNS dependency.

New panel-scoped role: deploy/ansible/roles/virtualmin-web-only/. Dispatch explicitly
for deployment or approved hardening, including recursive SSH preflight; preserve
Blesta and transport-only behavior. Network: public TCP80/443; administrative
9876/10000 only approved CIDRs; 2222 closed pending #787; SMTP/MySQL loopback;
default deny inbound, outbound allow. Preserve bounded DHCP, ICMP/IPv6 control and
loopback resolver traffic. Converge effective before/after chains and remove stale
rules/CIDRs over both families. Read SSH_CONNECTION remotely, never cached facts.
Coordinate existing SSH transition lock with a separate firewall snapshot/timed
recovery transaction. Add allows before removal, prove pinned fresh SSH before
commit, fence stale rollback timers. Never reset/disable UFW or flush unrelated
nftables. Second convergence run must change nothing.

Installer commit: 232a23d6aebf3ff9ad43d4d2823773ad14770509; SHA256:
996d32a9a2b7e64cc9dc4af7b6d001297fdee867ce34dffae31a7197f230d5ae.
Context-check a minimal patch removing its UFW/firewalld purge; use --minimal and
exclude Firewalld,Fail2ban,Fail2banFirewalld. Probe continuously from a denied
client during install. Qualify actual installed native versions separately. Remove
fail2ban/ProFTPd/Usermin under approved policy. Stop provider-firewall creation only
for new Virtualmin nodes, preserving historical discovery and cleanup.

Persist/reuse the dedicated API credential before root restrictions; fail if vault
storage fails. Prove real API authentication/TLS. Secret stays in enrollment only.
Root/interactive admins become loopback-only, API principal uses approved CIDRs.
Disable existing customer Webmin features before defaults/templates/global changes;
invalidate affected sessions and disable UDP discovery. Use native ACL APIs.
Provide dedicated key-only operator tunnel account allowing only local forwarding
to 127.0.0.1:10000, no commands/other destinations. SSH validator recognizes only
the exact managed Match policy. Preserve usage collector post_command ownership.

Destination predicate is separate from capacity and enforced at admission and
worker dispatch: picker, direct/queued create, reprovision, activation/retry,
ordinary/pair restore, migration, recovery and drain. Restore allowlist is unix,
dir,web,ssl,logrotate,mysql. Inspect archives before destructive dispatch; mixed
service archives need component migration, missing metadata needs inspection.
Update Python builders, pair-restore shell, held migration restore and recovery
SSL replay. Prevent callback recreation of excluded features; retain all other
identity/feature/SSL/path checks. Full-stack original-domain in-place rollback is
permitted on acknowledged sources.

Add imported_web migration contract (field max_length20), using current leases,
reservations, checksummed private spool and target holds. No fake NodeDeployment;
use exact enrolled SSH identity and action-scoped imported transport helpers.
Immutable manifest includes exact web/config/upload paths, isolated MySQL/MariaDB
databases, writers, aliases and retained services. Native feature/path selection
must exclude mail inside home, not merely the mail feature. Qualify callbacks.
Component fence stops only classified site writers/jobs, freezes selected paths
and isolated DB principals, preserving mail/DNS/unrelated processes/authentication.
Unclassifiable/shared writers or paths park needs_review with preparation steps.
Never reuse whole-domain disable, kill-all-owner, password reset or source delete.
Resolve/recheck MX/apex, SPF, mail/webmail aliases, local SMTP and retained-service
DB dependencies before changing only approved website routing. Preserve forward
commit semantics. Independent source domain-ID obligations survive account repoint
and block drain finalization/teardown. Precommit compensation restores only web
state; bridge cleanup removes only owned transport/web artifacts. Preview that
account backups follow the website and require explicit source-backup responsibility
handoff. PRAHO backup binding/retention redesign is separate.

Extend cloud gateway and Hetzner/DigitalOcean/Vultr adapters with typed paginated
inventory/capabilities and exact-ID operations: VM, primary/floating/reserved IPs,
firewall, key, exclusive volume/custom image, server/volume snapshots and backups.
Persist ownership/provenance and dependent IDs before parent deletion; attachment
alone is insufficient ownership. Unknown/shared/base images are preserved or
reconciled, never name-deleted. Missing permission is not an empty inventory.
Immutable destroy plan records digest, exact resource decisions, actor and resumable
progress. UI requires hostname confirmation and explicit keep/delete choice, per
restore point if needed, with charges and expiry. No fresh final snapshot by default.
Keep requires durable snapshot verification before any teardown. Convert supported
backups; unsupported conversion requires documented provider-console preparation
and verified snapshot mapping. Deliberately kept snapshots cannot expire through
DriftSnapshot cleanup, including races. Hetzner deletes backups with VM; DO/Vultr
have temporary retention. Unsupported deletion reports manual action/provider
expiry, never confirmed absence.

Extend #802 fenced node_teardown: secure retained restore points first, close
admission/check obligations, withdraw credentials/DNS, confirm VM gone, remove
approved exclusive dependencies, reinventory. Revalidate ownership/attachments
before each action; accepted DELETE/timeout is not proof. Retry after VM absence
using persisted IDs. Cover UI, async/direct service, manage_node,
cleanup_deployments, failed-deployment cleanup, redeploy and reconciliation.
Unattended cleanup preserves recoverable images without approved retention.
Report deleted/retained/awaiting-expiry/unresolved individually. PRAHO backup
catalog and retention remain unchanged.

## Verification and release

Test first for each behavior; verify actual diff at each coherent boundary. Native
Ubuntu combined SSH/firewall/Webmin tests need allowed/denied IPv4/IPv6 clients,
stale facts/CIDR removal/prechain bypass/installer probing/reboot/idempotence and
injected rollback. Test root/customer/admin sessions and restricted tunnel.
Mixed-service migration fixture proves mail receive/read and DNS remain live
through success/retry/compensation/cleanup, selected data consistent, stale writers
blocked, residual obligations prevent destruction. Three-provider contract matrix
covers ownership, permissions, paging, async timeout, crashes, retention, changed
attachments, expiry races and already-absent VMs. Disposable provider canaries
must show only approved retained resources remain.

Run canonical make checks: focused tests, lint, test, template checks and relevant
native lab suites. Update ADR0060, NODE_DEPLOY_DRILL, VIRTUALMIN_README, changelog.
Use independently reviewable signed-off Conventional Commits/PRs against master,
approximately400lines each. Complete independent review, required checks, queue
per docs/development/MERGING.md and verify actual merged master. Never claim full
delivery from mocked tests alone.
