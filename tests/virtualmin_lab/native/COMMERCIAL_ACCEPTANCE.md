# Commercial, warning and temporary-relief native acceptance

Use when qualifying #776, #840 and #783 together on the same final commit. This
procedure uses two disposable Ubuntu VMs, a fresh isolated Platform database, real
Portal/Platform HTTP, Stripe **sandbox** payments and the normal native workers.
It has not run merely because its unit, browser or container controls pass.

The [foundation instructions](README.md) remain required. Obtain explicit approval
for the disposable provider project, two VM costs, location/size, admin CIDR and
owned DNS subzone. Use sandbox payment credentials and a sandbox webhook endpoint;
never production payment, provider, SMTP or customer credentials. A missing input,
401, expired authority, held operation or unknown native result stops that phase.
Retain its original authority and evidence for reconciliation.

## One original database and vault

Keep all manifests, generated keys, captures and evidence outside the checkout in
one operator-owned directory with mode 0700. Their files must be 0600. Keep these
environment names distinct:

| Name | Purpose |
| --- | --- |
| `NATIVE_VM_MANIFEST` | Original **primary** manifest, used by every Django process |
| `NATIVE_PEER_MANIFEST` | Approved child VM intent/export; never selects Django settings |
| `NATIVE_S3_MANIFEST` | Owned storage fixture |
| `NATIVE_MAIL_MANIFEST` | Separate full-mail emitter/retained-mail fixture |
| `PRAHO_NATIVE_SMTP_MANIFEST` | Live, primary-run-bound Platform SMTP capture |
| `NATIVE_UI_AUTHORITY` | Private loopback Portal/Platform endpoint authority |
| `DB_NAME` | Fresh dedicated PostgreSQL database named `praho_native_…` |

Use the same complete database connection and original private key throughout.
Native field encryption, credential vault and session keys derive from that key.
The private `<run>.native-crypto.json` marker binds the database name and exact key
bytes. An older beta database encrypted with test constants, missing marker after
binding, changed database or re-encoded/replaced key requires a fresh fixture;
there is no automatic rekey. Do not point Django at the child manifest. Retain
both original keys until public teardown confirms their resources absent.

The VM intent lasts six hours. Complete deployment/kernel qualification before
starting the short commercial clock. Do not extend a manifest by editing JSON,
advance the host clock, pass future `at` values, alter saved periods/FSM states,
or copy successful qualification/receipt JSON into another fixture.

## Prepare and qualify both real nodes

1. On the primary, complete the fresh sequence in [README.md](README.md):

   ```bash
   make native-vm-fresh-intent
   make native-vm-migrate
   make native-vm-fresh-deploy
   make native-vm-register
   make test-virtualmin-quotas
   make test-virtualmin-native-fresh-deployment
   ```

   This must establish actual provider-create ownership, owned DNS, enrolled SSH,
   TLS/API validation, UID/GID/PHP/database denial, neighbor controls, reboot,
   package update and current per-boot qualification. HTTP 200 and a manifest flag
   are insufficient.
2. Create/verify the owned S3 and full-mail fixtures, load only the storage
   fixture's private environment, and complete `make test-virtualmin-native-workflow`.
   This provides the run-owned foundation account, genuine backup and restore,
   permanent resource exception with the saved 7.31 RON price, and lifecycle
   controls. It does not prove a commercial change or temporary R.
   Run `make native-commercial-staff-setup` now. This explicitly creates the new
   run-bound staff principal without starting the commercial clock or changing
   the original deployment actor. Start the SMTP/UI services below and complete
   normal staff login/MFA before the peer's UI review steps. Replaying staff setup
   validates the admitted identity; it never restores revoked roles/permissions.
3. Choose a distinct `NATIVE_PEER_MANIFEST` in the same private directory, then:

   ```bash
   make native-peer-intent
   make native-peer-create
   ```

   Intent precedes provider mutation. It binds one new pending deployment to the
   primary run/database/actor, creating provider credential, approved size/region,
   DNS zone, original lifetime and child SSH identity. Creation makes one call to
   the existing `NodeDeploymentService.deploy_node`; it is not a second installer.
   Export requires actual create-response ownership, open billable lifetime,
   public deployment result, live provider/key/DNS ownership and enrolled trust.
   `native-peer-export` can replay only that same identity. An interrupted public
   create retains its original row; use the existing deployment reconciliation,
   retry or exact teardown UI instead of creating a replacement.
4. In the peer's existing **Hosting policy review**, explicitly prepare the current
   helper bundle. Then run:

   ```bash
   make test-virtualmin-peer-quotas
   ```

   This invokes the provider-native gate on the **child path**, while all Django
   processes retain the primary manifest and vault. Inspect and explicitly adopt
   the peer after its actual native proof. Do not import it as a second Server
   pointing at the primary VM or substitute a container kernel.
5. Run `make native-commercial-verify` with both manifest variables set. It freshly
   checks the primary proof and the exact live, qualified peer. This command
   verifies node-pair prerequisites; the commercial/mail outcomes below still
   need their own evidence. It must continue to work with both historical
   deployment records present. Do not delete those records to satisfy the older
   sole-VM fresh-deployment admission guard.

## Start actual mail and HTTP services

In a separate terminal run `make native-smtp-serve`, with
`NATIVE_ACCEPTANCE_LIFETIME_SECONDS=10800` if three hours remain within VM authority.
The capture binds an actual ephemeral listener on literal `127.0.0.1`, publishes
its private run-bound manifest, and stores envelopes plus MIME. Keep it running;
expired, closed, foreign or unknown capture authority must refuse new delivery.

Export `PRAHO_NATIVE_SMTP_MANIFEST` in the Platform and worker terminals, then run
`make native-portal-serve`. This starts the actual isolated Portal and Platform
with production password, HMAC, session/fingerprint, step-up and staff/MFA guards.
It restores the same primary native crypto authority; it provides no Stripe SDK,
native transport or qualification doubles. Follow its private endpoint authority
for the two loopback URLs. Do not use the ordinary `dev-platform` sample-data path
or the doubled full-checkout test server for this physical gate.
After staff login, set the isolated database's `portal.public_base_url` to the
published **Portal** loopback origin before commercial setup. This keeps stored
email links identical for the UI and the separately running native-profile worker;
HTTP is supported only for loopback. Keep the two origins distinct.

The default native email backend remains file-based and correctly refuses mail
handover. The explicit capture opt-in is required. A file render, `EmailLog`, SMTP
acceptance and external inbox delivery are different evidence; the capture proves
the first three together and explicitly does **not** prove an external inbox.

## Initialize only new synthetic commercial history

After both nodes, storage, capture and staff UI are ready, start only the native
schedules and worker (the worker stays in its own terminal):

```bash
make native-virtualmin-schedules
make native-worker
```

Keep billing schedules unregistered. Now start the short commercial clock:

```bash
make native-commercial-setup NATIVE_BOUNDARY_MINUTES=75
```

The helper preserves the foundation Service's saved price, plan and allowance
revision. It creates a separate new owner, validates the previously admitted staff
administrator, creates compatible lower/base/higher Products, one extra web-only Service, and two NEW
monthly subscriptions. The existing pending-to-active FSM transition runs before
their first save. Their initial synthetic historical periods end one month before
the chosen boundary; the real renewal preparer and manual document convergence
then settle the current period ending at that boundary. The synthetic initial
bank record is labeled as fixture history, **not a real transfer or original-sale
acceptance proof**. Later upgrade payment uses real Stripe sandbox behavior.

No existing subscription period/status is edited. Setup replay before acceptance
preserves the initial documents and never prepares the next renewal. Once plan
acceptance starts, use the public recovery path rather than rerunning setup.
Managed account creation itself runs the normal create → `ensure_managed_limits`
→ `apply_hosting_limits` barrier synchronously, publishing its receipt only at the
canonical active-account commit. Setup requires that current receipt; it does not
count a queued create as success. If it refuses with a retained job/hold, inspect
and reconcile that exact job through the existing account/job UI, leaving billing
schedules off, then replay the same setup. Never insert a receipt, duplicate the
account or clear a held job to continue.

The primary manifest's `commercial_acceptance` block identifies the customer,
owner, staff, original deployment actor, two lane Service/Subscription IDs,
Product IDs, exact UTC boundary and actual initial cycle/proforma/invoice IDs.
Private `<run>.commercial-login.json` and `<run>.commercial-staff-login.json`
contain the initial credentials. Do not print, commit or include them in a PR.
Both use production-compatible PBKDF2 before first save. The original deployment
actor, its password and permissions remain unchanged. Enroll staff MFA through the
ordinary UI when required; do not disable enrollment or step-up.

Two lanes are intentional. Preparing a frozen future renewal on one subscription
would push its subsequent first-uncommitted downgrade a month beyond this run.
Both lanes share the exact real boundary, while their agreements remain separate.

## Accept DOWN before preparing its renewal

1. Keep only the native schedules and worker running initially. They perform real read-only safety
   observations, quota execution and warning work. Do **not** register billing
   schedules before accepting DOWN: automatic preparation could freeze its next
   interval and move the downgrade to the following month.
2. Using the new staff login, enable the paid-change canary flag in this isolated
   database. Keep recurring automatic collection off. Check actual sandbox Stripe
   configuration, its signed webhook delivery to this Platform, canonical Portal
   URL, numbering series and fiscal settings. No ANAF production submission is
   authorized by this fixture.
   Set `integrations.stripe_enabled`, `integrations.stripe_secret_key` and
   `integrations.stripe_publishable_key` through the existing encrypted settings
   controls, using only sandbox keys. A test-mode Stripe listener must forward
   **actual** events to the private Platform origin's
   `/integrations/webhooks/stripe/`; set its current signing secret in
   `integrations.stripe_webhook_secret`. The loopback server is not a public
   webhook receiver by itself. Do not substitute a generated success payload,
   local HMAC signature, doubled SDK response or the browser fixture gateway.
3. Log in as the new owner, open DOWN's `/services/<id>/change-plan/`, request a
   fresh usage check, and wait for its actual worker result. Select the generated
   **lower** Product. Accept its explicit effective date, terms and fingerprint.
   Record the scheduled change ID and exact boundary. There must be no immediate
   refund, price reversal or native cap reduction.
4. Now run `make native-billing-schedules`. The actual preparer creates DOWN's
   lower renewal and UP's frozen old-base renewal. Record both original document
   IDs, integer NET/tax/gross cents, periods and line identities before continuing.
   The generated lower price is `floor(base_cents/2)`; the higher target is
   `2*base_cents`. For the unchanged 7.31 RON foundation price these are 365 and
   1462 NET cents. Do not substitute catalog edits or a resource-only exception.

## Paid UP and exact renewal evidence

1. On UP, quote and accept the generated higher Product through the real Portal.
   Its itemization must include the remaining current interval and the already
   frozen future interval. Record quote time, original evidence IDs, fingerprint,
   NET/tax/gross cents and the exact future supplement (`higher-base` NET cents).
2. Complete its actual on-session Stripe sandbox payment and deliver the real
   signed webhook. Keep the provider event, original attempt/PaymentIntent ID,
   local Payment, issued supplement invoice and frozen coverage allocation IDs.
   A browser success screen alone does not establish financial commitment.
3. Wait for normal `apply_hosting_limits`/fulfilment workers. A financially committed
   change remains pending until a current native receipt proves both hard caps,
   domain/UID/GID, owner, node connection, installation/filesystem/boot, epoch and
   base/overlay revisions. Verify the actual node, not a manually inserted receipt.
4. Settle the original frozen future renewal through the customer payment UI while
   it is still early. Its original base amount/lines stay unchanged; its paid
   supplement supplies the difference to the accepted higher terms. Check the
   subscription's exact higher recurring cents and paid-through date and retain
   original document/PDF hashes. Early payment must not change which interval
   contains the actual quote time or charge the supplement twice.
5. Retry the existing submission/status page and replay the same actual provider
   webhook. Require one accepted change, one provider attempt/application and no
   duplicate Payment, invoice, native mutation or phase notice. Use public
   reconciliation after an uncertain response; never manufacture a new attempt.

## Real warning, temporary R and wall-clock expiry

1. Register/check the current RO/EN templates, preferences and warning sweep.
   Enable `provisioning.quota_warnings_enabled` only in this isolated canary, then
   use each node's reviewed public mail-handover operation. Require actual SMTP
   readiness and native emitter reconciliation; verify warnings remained native
   owned until this explicit handover. Keep operator alerts, website mail and any
   existing mailbox traffic intact. Never disable the MTA.
2. Record a low-usage baseline using a real native observation before filling UP.
   Write only a disposable run-named file as that account's Unix user on its
   current canonical node. Use the enrolled fixture SSH identity, strict known
   hosts and the exact private manifest resource; root may invoke `runuser` to
   execute `fallocate`/`dd` as the account, but must not write the file as root.
   Resolve the username/home from the actual owned native account/NSS identity,
   confirm its current receipt, and check live free space/reservations first.
   Keep a fixed filename such as `public_html/.praho-acceptance-<run>` and refuse
   an existing unowned path. Grow in bounded MiB amounts to approximately 95% of
   purchased operational **A**, then use the public usage-refresh action. This
   runs the native probe/canonical publisher; do not insert UsageReading rows.
3. Require the Portal warning against A and an actual warning delivery linked to
   its stored encrypted EmailLog. Use `make native-smtp-verify` with that exact log
   ID:

   ```bash
   NATIVE_SMTP_EMAIL_LOG_ID=<actual-log-uuid> make native-smtp-verify
   ```

   Repeat for each expected log (`--email-log-id` is repeatable in the underlying
   capture CLI). Compare
   envelope, subject, decoded text and HTML and check a single accepted attempt.
   Change the optional warning preference through `/company/notifications/` and
   verify optional mail respects it while critical mail still obeys current
   owner/privacy/hard suppression and final stored-body checks.
4. Enable the temporary-raise canary flag. In staff **Temporary disk relief**, use
   a ticket belonging to this customer and grant a fixed R within
   `min(A/4, 5120 MiB)`. Choose a real aware expiry shortly after the shared boundary
   (for example B+10 minutes), within original authority and the seven-day limit.
   Explicitly acknowledge removal even above A. Record the new
   `ServiceHostingRaise` and composite application. Require native verification
   before the UI claims extra capacity. Prices, documents and base revision stay
   unchanged; warnings still divide usage by A.
5. While R is verified, the disposable file may be grown above `A+E` and below
   `A+E+R`, with measured usage, reserve and neighbor checks. Here
   `E=min(ceil(A/10), 2048 MiB)`; E is never purchased capacity or a downgrade-fit
   allowance. Leave room for other actual account files/database bytes. Take a
   content digest before expiry. Keep ordinary customer writes quiescent so this
   fixture owns the measured change.
6. At actual wall-clock expiry, let the normal dispatcher remove R. Do not call a
   future-time helper or edit the expiry/status. Require the persistent overlay
   revision advance and a fresh matching current receipt for `A+E`, with both
   native hard caps equal. If measured usage remains above that cap, attempt one
   bounded new write as the account user and record actual `EDQUOT`/“Disk quota
   exceeded”; check existing data/digest remains and a neighboring account can
   still write. No deletion or account suspension is an accepted expiry outcome.
   Remove only this run's disposable fill file as that user afterward.

## DOWN at the actual boundary; restore and migrate

Pay DOWN's agreed lower renewal early through the normal customer payment UI.
Before B its native allowance must still be the old base. At actual B, wait for
the scheduled-change and native workers; check exact lower recurring cents, period
and receipt. If the boundary worker is held or usage no longer fits, retain the
lower agreed billing terms and visible attention. Never force the cap below usage,
delete data or restore the old higher price to make acceptance green.

After UP's verified paid change and R removal, use its actual account page:

1. Create a real backup through the existing backup form, write a disposable marker
   as the account user, then restore the original archive through its public
   confirmation flow. The marker must revert while the **current** accepted base,
   expired overlay revision, saved price and current native receipt are preserved.
2. Start the existing **Migrate** form with the qualified peer as destination.
   Require distinct actual provider VM IDs and current destination capacity,
   storage/ownership/quota proof. Follow the actual worker through backup,
   transfer, restore, current limits verification and canonical-node commit.
   Re-read the account on the target and prove the restored marker/content and
   current UID/GID hard caps. A retained disabled source copy is not another
   active account. Do not bypass mail-enabled-account, bridge, owner or DNS holds.
   These generated web-only accounts use the supported unpublished/legacy move;
   do not claim a published customer-DNS cutover from that result.
3. Re-run the real public safety refresh on the canonical target. Old source-node,
   old boot/credential or expired-overlay receipts must not certify current state.
   Reconcile any held attempt through its original public recovery/fence lane;
   elapsed leases alone never release uncertain capacity or enable an account.

## Evidence and exact cleanup

Retain a private report tying the final commit, both provider/deployment IDs,
creator fingerprints, original intents/markers, kernel proofs, current node/account
receipts, quote/payment/document/cycle/application IDs, exact dates/cents, backup
and migration result, raise grant/removal and warning/phase EmailLog IDs together.
Run SMTP verification for every expected stored financial/operational message.
Record external-inbox delivery as a separate gate if required; local SMTP acceptance
does not establish it. Check no native customer notification attempts during the
actual operations and retain operator positive controls plus the separate owned
ten-emitter/retained SMTP+IMAP fixture proof. Do not copy its
`mixed-configured` marker onto either VM or claim that container ran a kernel test.

Delete only these disposable accounts through the public lifecycle, resolve their
retained migration/bridge/backup holds, and stop the owned worker, UI and capture processes.
Then run `make native-peer-destroy` followed by `make native-vm-fresh-destroy`.
Both use public exact-resource destruction approval; workload protection and
uncertain ownership still refuse. Cleanup may use expired authority only for the
exact teardown action. Preserve historical deployment/ownership/lifetime rows and
private keys until absence is confirmed. Remove the exact owned storage/full-mail
fixtures through their destroy targets; do not prune unrelated resources.
If stopped at a purely pending, never-issued peer intent, no VM was created by
that phase. The existing public destruction policy refuses that pending state;
retain the cost-free intent and original key for inspection instead of inventing
a failed/destroyed FSM transition. Do not represent this retained intent as a
completed teardown. Any issued or uncertain create still requires actual provider
inventory and the existing public reconciliation/teardown lane.

Only actual completed evidence satisfies this feature-activation gate. Following
merged #866, disabled hosting code may merge after required CI and merge-queue
checks pass. Keep feature rollout and final issue acceptance pending while
provider/DNS/payment authority, physical execution, mail proof or an unresolved
native outcome is missing. Run these scenarios on staging after promotion and
before enabling new acceptance or customer notifications.
