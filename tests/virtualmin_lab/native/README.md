# Owned Ubuntu native acceptance

These commands use one disposable provider VM, an isolated PostgreSQL database,
and private manifest-bound SSH/vault authority. They never select a fleet or a
customer node. Missing credentials, real test DNS, storage, or native evidence
fail the gate; no container kernel or successful DNS/provider response is substituted.

Use the root Makefile. Keep `NATIVE_VM_MANIFEST`, `NATIVE_S3_MANIFEST` and
`NATIVE_MAIL_MANIFEST` outside the checkout in a private directory. Export the
approved disposable-project `HCLOUD_TOKEN`, narrow `PRAHO_NATIVE_ADMIN_CIDR`,
`NATIVE_DNS_ZONE`, and `DB_NAME=praho_native_workflow` with its dedicated local
PostgreSQL connection. The database name must start with `praho_native_`.

Run the phases sequentially:

1. `make native-vm-create` records exact provider IDs/labels and generated host-key trust.
2. `make native-vm-migrate` initializes only the isolated native database.
3. `make native-vm-prepare` binds real deployment/SSH/API vault rows before installation.
   The private manifest records `platform_fixture.fqdn`. Its approved real A record
   must resolve only to the manifest VM IPv4. An unresolved name stops before installation;
   provide that test DNS fixture and rerun. This command publishes no DNS records.
4. Preparation runs production roles and the public dedicated-API credential proof
   before hardening. It resumes on the recorded SSH port and reuses the encrypted
   credential. The password reaches only the panel-install vars file and is never printed.
5. `make native-vm-register` exercises public deployment registration-resume,
   activation and explicitly reviewed helper preparation.
6. `make test-virtualmin-quotas` proves unprivileged UID/PHP/database denial,
   neighbor isolation, reboot and managed-update persistence on the actual Ubuntu VM.
7. `make native-s3-create` and `make native-s3-verify` prepare the separately owned
   pinned MinIO/KMS fixture. Load its private sibling `.env` into this task's environment;
   the exact `praho-native-<run UUID>` bucket and real SSE-S3 put/get are required.
8. `make test-virtualmin-native-workflow` uses real public Platform services:
   reviewed node adoption; creation using the creation-time allowance after a catalog
   edit; a real backup; resource-only raise with saved billing unchanged; restore of
   the older archive with current limits re-verified; unprivileged marker restoration;
   and staff suspend/resume with both database and native enabled-state checks.
9. Run the separate native notification/mail-sink acceptance and inspect its evidence.
10. Keep failed/uncertain resources and private logs for reconciliation. Exact-owned
    cleanup uses `make native-s3-destroy`, the mail fixture's destroy target, and
    `make native-vm-destroy`. Expiry never authorizes cleanup of an unlabelled resource.

The fixture installer plus public **registration-resume** is an explicit boundary.
It does not prove the full fresh `NodeDeploymentService.deploy_node()` provider-create
and DNS-publication pipeline. That independent gate still requires approved disposable
provider and DNS write authority. `platform_workflow.fresh_deploy_dns` remains `false`.
The PR1 workflow also does not claim a paid upgrade; commercial acceptance belongs to #840.

PostgreSQL unit controls exercise encrypted/idempotent fixture binding, changed-resource
refusal and command isolation. Their mocked provider/SSH boundaries are not native proof.
No native phase has been executed merely because those unit controls pass.

After a reboot, a prior receipt remains historical evidence. In Platform, open
the node's **Hosting policy review**, run **Inspect without changes**, review the
same installation and filesystem with the new boot, and explicitly approve
**Requalify an adopted node after reboot while preserving account holds**. Normal
adoption keeps its exclusion against account/migration work. Isolated
requalification changes no tenant/domain/bandwidth policy, restarts no panel or
mail service, releases no account/bridge/capacity hold and certifies no account
receipt. It still refuses active security, maintenance, deployment and drift
configuration writers. The queued operation retains its node-wide
exclusion if verification is uncertain; use **Reconcile held operation** for
that exact attempt before any other native work. Inspection revokes old current
verification when it observes the changed boot and never changes tenant caps.

Explicit re-adoption preserves the protected original acceptance. It checks the
current Ubuntu/PHP baseline, root ext4 layout, both active quota classes, running
MariaDB identity and capabilities, unit bounding policy and existing table storage.
It then uses a persistently reserved identity in the fixed range 2147000000–2147000031 for bounded
UID, GID and PHP EDQUOT probes under `/var/lib/praho-quota-requalification`.
The native `obtain_lock_unix` allocator lock serializes its creation with supported
account creation and restore. Protected installation-bound provenance is required;
an existing same-named account without that provenance is refused. The account has
a locked password, no home, no login shell and no mailbox. Native allocator maps
and preserved-ID restore collision checks retain that reservation. No tenant
UID/GID limit or data is changed. Verified cleanup must remove the temporary
path and the private probe journal and restore both probe caps/accounting to zero
before a fresh boot qualification is published. Ambiguous ownership, unsupported
storage, failed cleanup or missing original acceptance keeps the node unqualified.
The native VM gate performs another provider-observed reboot and this exact
recovery path after initial acceptance; it remains pending without VM credentials.

For a paused committed migration, requalify the node first, then use the existing
**Keep target** resolution to resume the migration. Its current worker lease may
carry an exactly bound, never-issued quota reservation into a new nonce/epoch
without a released-capacity gap. The old attempt remains terminal history and
cannot dispatch. Issued or uncertain mutations retain the permanent-fence path.
The resumed parent must verify current per-account storage, caps and receipt
before activation. Resolving a partially restored standalone job instead leaves
the account disabled with its existing half-restored hold.
