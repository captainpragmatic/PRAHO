# Owned Ubuntu native acceptance

These commands use one disposable provider VM, an isolated PostgreSQL database,
and private manifest-bound SSH/vault authority. They never select a fleet or a
customer node. Missing credentials, real test DNS, storage, or native evidence
fail the gate; no container kernel or successful DNS/provider response is substituted.

For the complete paid upgrade, renewal-boundary downgrade, warnings, temporary
relief, restore and migration journey, continue with
[commercial native acceptance](COMMERCIAL_ACCEPTANCE.md) after the foundation
qualification below. That procedure retains this original database and vault and
adds an explicitly owned second node, real Portal authentication and a private
Platform SMTP capture.

Use the root Makefile. Keep `NATIVE_VM_MANIFEST`, `NATIVE_S3_MANIFEST` and
`NATIVE_MAIL_MANIFEST` outside the checkout in a private directory. Export the
approved disposable-project `HCLOUD_TOKEN`, narrow `PRAHO_NATIVE_ADMIN_CIDR`,
`NATIVE_DNS_ZONE`, and `DB_NAME=praho_native_workflow` with its dedicated local
PostgreSQL connection. The database name must start with `praho_native_`.

Keep the original private SSH key and the private `<run>.native-crypto.json`
marker with the manifest. Field encryption, the credential vault and sessions
derive independent keys from that exact original key; the marker also binds the
isolated database name. Replacing or re-encoding the key, changing the database,
or resuming an older bound fixture without this marker refuses startup. Use a
fresh isolated fixture for an older test-key database; there is no automatic
rekey. Cleanup retains the same original crypto authority.

The complete fresh-deployment gate uses **one** VM created by the public Platform
pipeline. Export `PRAHO_NATIVE_LOCATION` and `PRAHO_NATIVE_SERVER_TYPE` explicitly,
plus the approved DNS authority references as `PRAHO_NATIVE_CLOUDFLARE_TOKEN` and
`PRAHO_NATIVE_CLOUDFLARE_ZONE_ID`. Do not print or commit their values. The DNS zone
argument must be the approved disposable zone/subzone inside that provider zone.
Use an otherwise empty isolated native database, not the registration-resume fixture's
database. Run these phases sequentially:

1. `make native-vm-fresh-intent` records only private local intent and an original
   SSH/vault identity. It creates no provider resources. Preserve this key after
   interruption; replacing it would lose access to the encrypted native database.
2. `make native-vm-migrate` initializes the isolated native database.
3. `make native-vm-fresh-deploy` first reads the approved DNS zone and synchronizes
   the real provider catalogue, then invokes `NodeDeploymentService.deploy_node()`
   with the actual provider/DNS credentials and an exact-permission fixture actor.
   The pipeline creates the VM, publishes owned DNS, runs production installation,
   validates and registers it. No existing raw-provider VM or successful fake DNS
   answer can satisfy this phase. Real create-response ownership, the billable
   lifetime and the actual completed deployment result are required before its
   exact VM/key receive lab labels. Host trust comes from the public deployment's
   durable enrollment; its original client private key stays unchanged.
4. `make native-vm-register` verifies activation and prepares reviewed inspection
   helpers through the public node-policy operation.
5. `make test-virtualmin-quotas` performs actual UID/PHP/database denial, neighbor
   controls, provider-observed reboots, package update and isolated requalification.
6. `make test-virtualmin-native-fresh-deployment` rechecks the original database
   intent, creator credential, immutable create records, live provider identity,
   owned DNS, public SSH/port/API/TLS validation and current native quota evidence.
   An all-true manifest JSON is never deployment proof.
7. Create/verify the owned storage and mail fixtures, then run the public lifecycle
   workflow described below on this same VM. This does not create a second VM.
8. Use `make native-vm-fresh-destroy` for public exact-resource approval/teardown,
   including after authority expiry. Cleanup-only mode permits only that action.
   Workload protection remains active: remove only this run's disposable accounts
   through public lifecycle operations first. A refusal or uncertain outcome retains
   the manifest, original key and provider IDs for public reconciliation.

The older raw-provider **registration-resume** control is independent and must not
be represented as fresh provider creation. For that control, use a different run
and database and follow this sequence:

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

The raw fixture installer plus public **registration-resume** does not prove the
fresh provider-create/DNS path. Its `platform_workflow.fresh_deploy_dns` remains
`false`. The separate intent-first gate above still requires actual approved
provider/DNS authority and native execution. The PR1 workflow does not claim a
paid upgrade; commercial acceptance belongs to #840.

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
