# Implementation plan: account hostnames, customer DNS and mail (ADR-0061)

Every task: a test that fails first (quote the failure line), the fix, green, `make lint FILE=` for every changed file, then a sibling check (grep the defect's shape). Node-side steps are proven in the Virtualmin lab. Cloudflare and public DNS are faked in tests through `register_dns_gateway` and a patched `authoritative_addresses`. Each phase is its own PR series.

**Branch base.** This work changes the same provisioning code as #693 and the differential-backup work (provisioning migrations 0003 and 0004). Phase 0 starts on the differential-backup branch's tip once its stage 2 is committed; each phase rebases onto master as #693 and the differential-backup PR land. New provisioning migrations start at 0005.

## Design corrections found in pre-flight

- **The DNS path cannot live on `Domain`.** A `Domain` row needs a registrar and a TLD (PROTECT keys) and exists only for domains we registered (`domains/services.py:622`, `operation_services.py:122`). Per-account DNS state hangs off `VirtualminAccount` instead.
- **Virtualmin parameters reject `--`, CR and LF** (`apps/common/validators.py:42`, `SUSPICIOUS_PATTERNS`) and are capped at 1000 characters. So:
  - a PEM never goes through the API; certificates travel by playbook and `install-cert` receives file paths;
  - labels are `[a-z0-9]` only;
  - punycode domains (`xn--`) are rejected today, which is fixed in P0.1.
- **One vhost serves one certificate,** so the account name cannot be a ServerAlias on the customer's vhost. It is a **Virtualmin sub-server of the customer domain** with its own vhost and certificate, its web root a relative symlink to the customer's (`docs/domain/virtualmin-account-subserver-contract.md`). An alias domain was disproved first (`virtualmin-account-alias-contract.md`).
- **Recovery today recreates empty domains** (`virtualmin_disaster_recovery.py:44`), and restore never changes `account.server`. P2.7 adds a real recover-to-node service.
- **Sub-servers appear in `list-domains`** (`type: Sub-server`, `parent_domain`) and would corrupt the account sync, `update_server_statistics` and `list_migration_domains`. They are filtered in P1.6.
- **There is no ACME client.** Virtualmin GPL's DNS-01 needs BIND, and nodes run without it. Certificates are issued on Platform with the Python `acme` and `josepy` libraries, so the Cloudflare token stays off the nodes.

## Status (2026-10-17)

- **Phase 0 is built** (PR #695, merged).
- **P1.0 is done: the sub-server design is proven on Virtualmin 8.3** (`docs/domain/virtualmin-account-subserver-contract.md` on `feat/adr61-phase1-account-hostnames`). The alias attempt before it is recorded in `virtualmin-account-alias-contract.md`. What the lab established, and what every task below relies on:
  - the sub-server has its own vhost on 80 and 443 and its own certificate by SNI, key root-only;
  - its `public_html` replaced by the relative symlink `../../public_html` serves the customer's site, with PHP as the customer's user; no Virtualmin program can do this (`modify-web --document-dir` refuses `..`, a `create-redirect` alias answers 403);
  - `disable-domain` and `enable-domain` reach it only with `subservers`;
  - a customer backup carries it only with `parent`, and an in-place restore of the customer domain keeps it;
  - deleting the customer deletes it; deleting it alone never touches the customer's files;
  - its key is in any archive that carries it, which rules out a wildcard on it unless every such archive is excluded (P1.10).

## Review record

- **Reviewed:** plan v1, phases 0 to 2, by an adversarial plan review (REWORK: 6 HIGH, 4 MEDIUM, 1 LOW, 0 CRITICAL) and a code review of the files it touches (14 findings on existing code: 6 HIGH, 7 MEDIUM, 1 LOW).
- **This version (v2)** answers both. Phases 3 to 5 are reviewed on their own before they start.

## Phase 0: existing bugs, fixed before any feature work

These are live defects today. Each ships with a test that fails without it.

- **P0.1 Accept punycode domains end to end.**
  - Both `apps/common/validators.py` (`SUSPICIOUS_PATTERNS`) and the call-time check in `virtualmin_validators.py` / `virtualmin_gateway.py` stop rejecting valid A-labels (`xn--`). They refuse only a leading `-` (an option injection) and invalid IDNA.
  - Test: `xn--bcher-kva.ro` goes through both validation layers; `--option` and `-x` values are still refused.
- **P0.2 The panel certificate uses the node FQDN.**
  - `ansible_service._build_vars` passes `node_fqdn`, and `virtualmin.yml` uses it for the installer's `--hostname` and both Let's Encrypt steps.
  - Test: the playbook test finds no `inventory_hostname` on those lines.
- **P0.3 Store a node's IPv6 as an address, not a network.**
  - `hcloud_service.py` (~135, ~498) stores `public_net.ipv6.ip`, which the library documents as a CIDR (`…::/64`), so `_configure_dns` publishes an invalid AAAA.
  - Store the `::1` host of the block, normalised with `public_address(v, 6)`, and repair the test fake (`apps/infrastructure/tests/test_hcloud_service.py` ~23), which hides this.
  - First confirm on a lab or real deployment record.
- **P0.4 Reprovisioning sets the server only after the domain exists.**
  - `reprovision_virtualmin_account` (`virtualmin_service.py` ~313-319) saves `account.server` before `create-domain` and keeps it on failure.
  - Stage the target, and commit `account.server` only after a verified create.
  - Test: a failed create leaves `account.server` unchanged.
- **P0.5 Account sync never assigns unknown domains to a random customer.**
  - `virtualmin_views.py` (~1781-1866) imports unknown domains as active services of `Customer.objects.first()`, and the staff form defaults new rows to active (`virtualmin_forms.py` ~513).
  - Unknown domains become unassigned discovery records for staff to attach; nothing is created as active.
  - The full `save()` after a remote call (~1774) uses `update_fields`.
  - Tests: an unknown domain creates no service for any customer; a stale-instance test for the save.
- **P0.6 Recovery restores quotas in the right units.**
  - `virtualmin_disaster_recovery.py` (~394-420) overwrites the create-time quotas (KiB and bytes) with raw MB and passes `-1`.
  - Use the same conversion as `create-domain` (`virtualmin_service.py` ~406-410).
  - Replace the test that locks the bug in (`tests/provisioning/test_disaster_recovery_regressions.py` ~80-82).
- **P0.7 Restrict the legacy rebuild to dry runs.**
  - `rebuild_server_from_praho` recreates *empty* domains. It refuses `dry_run=False` until P2.7's recovery replaces it, and says so in its docstring.
  - Test: a non-dry-run call is refused.
- **P0.8 The customer role list matches the membership roles.**
  - The role check in `apps/common/validators.py` (~55) does not match `CUSTOMER_ROLE_CHOICES`, so `tech` can never be granted (`customer_views.py` ~654).
  - Derive the list from the choices.
  - Test: an owner can grant `tech`.
- **P0.9 The Portal stops exposing node details.**
  - `server_ip` and the node hostname leave every customer payload (`api/services/serializers.py` ~119, ~135: detail, list, summary, auto-renew).
  - Portal `service_detail.html` (~252, ~419-423) stops rendering them.
  - A service with no Virtualmin account no longer 500s (`api/services/views.py` ~208-210).
  - Tests: no payload contains a node IP or hostname; the missing-account case answers normally.
- **P0.10 Harden the DNS gateway** (`apps/infrastructure/dns_gateway.py`).
  - Drift comparison covers TTL and `proxied`, with addresses compared through `ipaddress`.
  - Record listings follow every page.
  - Each reconcile call takes one record name (refused otherwise).
  - 429 and 5xx responses are typed as retriable and honour Retry-After, never ending a deploy or a migration as a hard failure.
  - Tests in `tests/infrastructure/test_dns_gateway_cloudflare.py`: a TTL-only change, a proxied-flag change, a two-page listing, a 429 that is retried, multiple names refused.
- **P0.11 Settings validation runs on the normalised value, under the lock.**
  - `settings/services.py`: the semantic guard (~453) runs after normalisation (strip) and inside `_write_setting_locked`.
  - Test: a padded value is normalised before the guard sees it.

## Phase 1: account names, previews and certificates

**Ownership model.** `AccountHostname.target_server` holds the intended node: the place DNS must point. Only provisioning success, cutover and recovery change it. The reconcile sweep and "Repair DNS" converge DNS to `target_server`, never to `account.server`, so nothing can undo a cutover in flight.

1. **P1.0 Prove the account-name vhost in the lab. Done** (see Status): a sub-server of the customer domain, web root mapped by a relative symlink.
2. **P1.1 Add the models (migration 0005).**
   - `VirtualminServer.ipv4_address` and `ipv6_address`.
   - `AccountHostname`: UUID, `label` (`^[a-z0-9]{8}$`, unique, never reused), `account` (OneToOne, SET_NULL), `target_server`, `zone`, `records` (per-record publication progress: intended content, applied content, provider id, applied TTL), `previous_ttl`, `ttl_lowered_at`, `last_reconciled_at`, `retired_at`, timestamps.
   - `VirtualminAccount.activation_notified_at`.
   - IP backfill from deployments, after P0.3.
   - Audit wiring.
3. **P1.2 Fill server IPs** on registration and in the staff form (`public_address()` validation).
4. **P1.3 Add the settings group `hosting-dns`.**
   - Keys: `dns.account_hostnames_enabled`, `dns.account_hostname_zone`, `dns.account_hostname_zone_id` (`^[0-9a-f]{32}$`, and checked against the zone name through the API as `deployment_service.py` ~1520-1527 does), `dns.account_zone_api_token`, `dns.account_record_ttl_seconds` (300), `dns.cutover_ttl_seconds` (60), `dns.bridge_window_hours` (48).
   - **Token:** its own token with Zone:Read and DNS:Edit on the account zone only. Never the node token.
   - **Registrable-domain guard:** the zone must be a different registrable domain from the brand and Portal domains, using the Public Suffix List with private suffixes (new dependency `publicsuffixlist`). That refuses siblings such as `preview.example.ro` beside `portal.example.ro`, as well as equal names and children.
   - The zone, zone id and token cannot change while live hostnames exist.
   - Tests: sibling, child and equal names are refused; a different registrable domain is accepted; changes are blocked while names are live.
5. **P1.4 The hostname service** (`apps/provisioning/account_hostname_service.py`).
   - `sync_account_hostname(hostname)` converges records to `target_server`, persisting the intent before the call and the progress per record after it.
   - `retire_account_hostname(hostname)`.
   - `ensure_node_account_name(account, server)`: idempotent. Lists the name on `server`; if absent, `create-domain` with `domain=<label>.<zone>`, `parent=<account.domain>`, `dir=`, `web=`, `ssl=`, `desc=`. If present, it must be a `Sub-server` whose `parent_domain` is `account.domain`, else refuse (never adopt another account's row). Then runs the link playbook (P1.15) and installs the current certificate (P1.10). It returns a typed result; an ambiguous gateway answer is not success.
   - `remove_node_account_name(account, server)`: `delete-domain` of the name only, after the same ownership check. Proven safe: it removes the sub-server's own home and never follows the link.
   - The sync acts only on accounts that are active or suspended with `provisioned_at` set.
   - **Archives never carry the account name.** Customer, chain and migration backups keep calling `backup-domain` without `parent`; PRAHO recreates the name from its own record on the node that ends up serving the account. That keeps the name's key out of every archive PRAHO stores or hands out, keeps the differential chain to one domain, and avoids a second `restore-domain` call per restore.
   - Tests: absent → created then linked then certified; present and owned → no create, link re-applied; present under another parent or as a top-level server → refused, nothing deleted; ambiguous create → not success; remove refuses a row it does not own.
6. **P1.5 Cascade suspend and unsuspend to the account name.** Without it the name keeps serving the customer's site while the customer domain shows the disabled page (lab S3).
   - Every `disable-domain` and `enable-domain` PRAHO sends for a customer domain adds `subservers=`: `virtualmin_service.py` ~887 and ~1024 (suspend, activate), their compensating operations (~896, ~1033), the operation table at ~1384, the queued-operation executor (~751, ~762), the migration's source disable and enable and target enable (`virtualmin_migration_service.py` ~430, ~447, ~558), and the pair restore's disable (`virtualmin_pair_restore.py`).
   - One helper builds the parameters (`domain_state_params(domain)`), so a new call site cannot forget the flag; a test greps the provisioning package for a literal `"disable-domain"`/`"enable-domain"` call that bypasses it.
   - Contract suite: record `disable-domain` and `enable-domain` with `subservers=` on a domain with and without a sub-server.
   - Tests: each call site sends the flag; with the flag removed, the lab workflow test sees the account name still serving after suspend.
7. **P1.6 Ignore sub-server rows in every listing.**
   - A row is the customer's domain only when its type is `Top-level server` (text `Type:` or JSON `values.type`). Sub-server and alias rows are skipped. One function decides (`is_account_domain_row(row)`), read from the raw row before `SNAPSHOT_ATTRIBUTES` drops the marker.
   - Callers: `list_migration_domains` (`virtualmin_migration_service.py` ~114), server statistics (`virtualmin_service.py`, which must stop using the name-only listing that cannot tell rows apart), the account sync in `virtualmin_views.py`, and the gateway helpers that list all domains (`virtualmin_gateway.py` ~1298, ~1410).
   - Tests from recorded fixtures with a sub-server row: the sync does not import it as an account, statistics do not count it, a migration listing does not offer it.
8. **P1.7 Lifecycle at one completion boundary.**
   - A single `on_account_ready(account)` runs on every path that finishes a create: `_handle_successful_provisioning_secure` (`virtualmin_tasks.py` ~542), `_retry_create_domain` (`virtualmin_service.py` ~1298) and direct creation. It sets `target_server`, calls `ensure_node_account_name(account, account.server)` and enqueues the sync.
   - **The same ensure runs wherever a customer domain is recreated from nothing:** a migration's target after `restoring` and before `activating` (`_restore`/`_activate`), a recovery or `rebuild_server_from_praho` restore, and a backup restore that recreated the domain. An in-place restore keeps the name (lab S9), so the ensure is a cheap no-op there.
   - **A migration target is created disabled.** The ensure runs while the target is still disabled; `_activate`'s cascading enable (P1.5) turns the name on with the account.
   - **The pair restore's 503 barrier must cover the account name.** It is keyed on the customer vhost's names today; the account name is a separate vhost that serves the same files through the link, so its name joins the barrier's host set, and it is disabled and re-enabled with the customer domain (P1.5).
   - **Retire the name only where an account becomes `terminated`** and on row delete. Deleting the customer domain on the node removes the sub-server with it.
   - **Removing a failed migration target, or any rollback delete,** deletes the customer domain on the target, which removes the target's copy of the name; it never retires the name (`_rollback`, `_execute_rollback`).
   - Tests: every create path ends ready with the name ensured; a migration ends with the name on the target, enabled with the account; a failed migration's cleanup keeps the label and the records; termination retires them; the barrier's host set includes the account name.
9. **P1.8 Reconcile sweep, every 15 minutes.** It converges to `target_server`, with an atomic skip (a row lock and a re-check) for accounts in a migration or recovery.
10. **P1.9 DNS-01 support in the gateway.**
    - TXT records with several values per name.
    - Concurrent challenges, each owned by its order (`praho:acme:<order>`).
    - Owned cleanup, including after a crash (sweep stale owned TXT records).
11. **P1.10 A certificate per account name.**
    - **Per name, not a wildcard.** A sub-server's key sits in its own `/etc/ssl/virtualmin/<id>/` (root-only, lab S4), and any archive that carries the sub-server carries the key (S5). A wildcard there would put one key for every customer's name on every node and into any `parent` backup. A per-name certificate exposes only that customer's own name, which the owner accepted.
    - Issued on Platform with `acme` and `josepy` through DNS-01 on the account zone (P1.9), so it works before the customer's DNS points anywhere. The ACME account key and each certificate key live in the vault, per hostname.
    - **Let's Encrypt budget.** Certificates per registered domain are limited per week (renewals are exempt); new names queue against a budget setting (`dns.account_cert_weekly_budget`, default 40), and an exhausted budget leaves the name on its self-signed certificate and retries the next window. A staff alert fires at 80% of the budget.
    - Renewal runs daily for certificates under 30 days left.
    - Distribution by playbook with the existing temporary-vars-file pattern (`no_log`, never argv): write the PEMs to a root-only temporary directory on the node, `install-cert --domain <name> --cert <path> --key <path>`, delete the files in the same play.
    - `ensure_node_account_name` installs the current certificate before the name's records are published.
    - Tests: issuance through a faked ACME directory and DNS gateway; budget exhaustion leaves the name unpublished-safe; renewal picks only near-expiry names; the playbook leaves no PEM behind (lab).
12. **P1.11 Show the account name and DNS instructions in the Portal.**
    - Builds on P0.9.
    - `ServiceDetailSerializer` adds `hosting` (account name, path, instruction records), read safely when no account exists.
    - Portal: `service_detail.html` plus `partials/dns_instructions.html`.
13. **P1.12 Send the activation email once,** after the first verified sync, guarded by `activation_notified_at` under `select_for_update`.
14. **P1.13 Staff pages.**
    - Hostname card on account detail.
    - "Repair DNS" enqueues a sync and returns at once; no DNS lookup inside a request.
    - Server IPs on the server pages.
15. **P1.14 WordPress preview decision** (owner).
16. **P1.15 The link playbook** (`infrastructure/ansible/playbooks/virtualmin_account_name_link.yml`, allowlisted in `apps/infrastructure/ansible_service.py`).
    - Inputs: the sub-server's home (from the node's own listing, never built from user input), the customer's unix user. Validates that the home is `/home/<user>/domains/<label>.<zone>` and that `<user>` owns it.
    - Replaces `public_html` with the relative symlink `../../public_html`, owned by the customer's user (`chown -h`); idempotent (`ln -sfn` semantics, a real directory is moved aside once as `public_html.own`).
    - Lab test: the name serves the customer's marker and PHP as the customer's user; a second run changes nothing; `validate-domains --all-features` stays clean.
17. **P1.16 A neutral default site on every node.** With several vhosts, a request for an unknown name is answered by the first one Apache loads (lab side finding), and opaque account names sort early. `virtualmin.yml` installs a PRAHO default vhost that loads first and answers 404 with no customer content, on 80 and 443. Lab test: an unknown `Host` gets the default site, never a customer's marker.

## Phase 2: cutover, bridge and recovery

### The cutover contract
1. **Lower the TTL.** Record each record's `previous_ttl`, then lower it. The wait starts only when every owned record confirms the lower TTL. Cancellation or failure restores `previous_ttl`.
2. **Write barrier on the source,** proven in the lab, with **persisted state and verified compensation.**
   - The barrier: `disable-domain`, the account's cron jobs suspended, its processes stopped, and database writes blocked (privileges revoked on its databases).
   - **Before applying it,** PRAHO records the cron state and the database grants on the migration.
   - **A failure before step 5** restores exactly that state and verifies it with a real database write and a cron listing.
   - Mail accounts do not migrate until phase 5 adds queue drain and forwarding.
3. **Back up, restore onto the target, verify it.** The target stays disabled and unreachable: no DNS change and no bridge, so nothing has written to it yet.
4. **Point of no return,** before anything can write to the target.
   - In one fenced transaction, set `account.server` and `AccountHostname.target_server` to the target.
   - From here only "keep target" actions exist: no path may reactivate the source copy or delete the target.
5. **Enable the target** with the intended grants and cron state (the ones recorded in step 2).
6. **Install the bridge on the source** (a reverse proxy to the target) and verify it answers.
7. **Converge DNS** to the target. Progress is persisted per record (A and AAAA separately), retried until the authoritative servers agree. It is never rolled back.
8. **Bridge window,** then verify routing again.
9. **Remove the retained source content, with the bridge vhost still in place.**
10. **Tear down the bridge** and restore the TTL.

- **Before step 4, "keep source"** restores the barrier state (step 2) and removes the target's copy of the customer domain (which removes its account-name sub-server), keeping the label.
- **After step 4, `needs_review`** offers only "keep target" actions: retry convergence, extend the bridge.
- **Tests:**
  - a failure right after the bridge is activated replays forward and never offers "keep source";
  - a failure during backup restores the recorded grants and cron state, and a database write works afterwards.

### Tasks
1. **P2.1 Make migrations able to wait.**
   - A handler can return a *defer* outcome that ends `execute()`'s loop, frees the lease and schedules a delayed run (`virtualmin_migration_service.py` ~594-605).
   - Drains treat a deferred migration as waiting, not failed (`virtualmin_drain_service.py` ~233-237), and resume it.
   - `cancel_drain` handles waiting migrations.
   - Tests: a deferred handler leaves the loop and is re-run later; a drain waits rather than pausing.
2. **P2.2 Add the cutover states (migration 0006)** for the contract's steps. Add `VirtualminMigration.drain` (FK). `RESUME_POLICY` gets a policy for every new state; replay converges forward after step 5.
3. **P2.3 TTL lowering and restore** (contract step 1).
4. **P2.4 Write barrier with persisted state and compensation,** proven in the lab (contract step 2). Tests: a cron write and a database write both fail after the barrier; after a pre-cutover failure, the recorded grants and cron state are back and a database write succeeds.
5. **P2.5 Bridge.**
   - `MigrationBridge` with FSM `pending` → `active` → `removing_source` → `torn_down`, plus `failed` and `ConcurrentTransitionMixin`.
   - Playbook `virtualmin_bridge.yml`.
   - `start_migration` refuses while any bridge for the account is not `torn_down`.
6. **P2.6 Point of no return, target enablement and convergence** (contract steps 4 to 7).
   - `_repoint` becomes verification only.
   - Tests:
     - a crash between steps 4 and 7 replays to convergence;
     - A succeeding while AAAA fails leaves the AAAA progress pending and retried;
     - the sweep never points DNS back at the source.
7. **P2.7 Cleanup** (contract steps 8 to 10), retryable, in that order.
8. **P2.8 Drain finalisation.**
   - Auto-confirm (system actor, audited) only when every migration is past step 10 and no bridge is `pending`, `active` or `failed`.
   - Hostnames of non-live accounts (error, provisioning) left on the drained node are retired, so its IP being reused later cannot be taken over.
9. **P2.9 Recovery onto a new node, with the same contract in "source unavailable" mode.**
   - No barrier and no bridge.
   - Restore from the latest backup, verify, the account name ensured on the target with its certificate (P1.4), the point of no return, DNS convergence; suspension state preserved.
   - New `virtualmin_recovery_service.py` and the `virtualmin_recover_node` command (dry-run by default).
   - It replaces the restricted legacy rebuild (P0.7).
10. **P2.10 Authoritative checks off the request path.**
    - `authoritative_addresses` gets bounded retries and normalised IP comparison.
    - Staff pages show the last result recorded by the task; they never query DNS inside a request.
11. **P2.11 Staff text.** The migration status page shows each contract step, the convergence progress per record and the bridge state. The "PRAHO does not change routing or DNS" text goes.

## Phase 3: watching customer DNS

1. **P3.1 Add the status model.** `HostedDomainDnsStatus`, OneToOne on `VirtualminAccount`:
   - `dns_path`, a results JSON;
   - `healthy`, `first_failed_at`, `notified_at`, `checked_at`;
   - migration 0007.
2. **P3.2 Write probes that follow CNAMEs.**
   - New `apps/infrastructure/dns_probes.py`. Checks: `www` reaching the account name, the apex, MX, stray AAAA, CAA allowing Let's Encrypt, and DNSSEC (DS against DNSKEY).
   - Test: `tests/infrastructure/test_dns_probes.py`.
3. **P3.3 Classify and schedule.** An hourly batched task. Email template `hosting_dns_broken`, sent once per healthy-to-broken change. Test: `tests/provisioning/test_dns_check_task.py`.
4. **P3.4 Add the API and the Portal status card.**
   - `TECH_ROLES = {"owner", "tech"}` in `api/secure_auth.py`.
   - Platform `services/<id>/dns-status/` and `.../recheck/`.
   - Portal `ServicesAPIClient.get_service_dns_status`, view `services/<id>/dns/`, `partials/dns_status_card.html`.
   - Tests:
     - `tests/api/test_service_dns_status_api.py`: another customer gets 404; a viewer cannot recheck;
     - Portal `tests/services/test_service_dns_status_card.py`.
4. **P3.5 Add the staff check results.** A panel on account detail and a list of broken domains.

## Phase 4: our nameservers on Cloudflare

1. **P4.1 Add the zone provider interface and its Cloudflare implementation.**
   - Records: A, AAAA, CNAME, MX, TXT, SRV and CAA.
   - Operations: zone create, read and delete; activation check; record CRUD; DNSSEC status.
   - Settings: `dns.cloudflare_account_id` and an account-level token.
   - Test: `tests/infrastructure/test_dns_zone_provider_cloudflare.py`.
2. **P4.2 Add `HostedZone` and `HostedZoneRecord`** (`apps/domains/dns_zone_models.py`).
   - `HostedZone` has an FSM: `pending_import` → `awaiting_ns` → `active` → `deleting` / `deleted` / `failed`.
   - Each record carries `managed_by` (`praho` / `customer` / `imported`).
   - Audit wiring.
   - Test: `tests/domains/test_hosted_zone_fsm.py`.
3. **P4.3 Import existing records.** Query the current authoritative servers for the apex, `www`, `mail`, `_dmarc`, `autodiscover`, common DKIM selectors and common SRV names. Test with a fixture zone.
4. **P4.4 Copy the account's addresses into customer zones.** `sync_account_hostname` updates the managed apex and `www` records in the customer's zone on every move.
5. **P4.5 Build the nameserver-switch assistant.**
   - An activation poll.
   - A one-click registrar update where a `Domain` row with a capable registrar exists.
   - A warning to remove DS first.
6. **P4.6 Add the Platform API** under `apps/api/dns/`.
   - Writes need tech roles; a managed record answers 409.
   - Per-type validators: no CNAME at the apex, a CAA tag allowlist, MX priority range.
   - Every edit is audited.
   - Test: `tests/api/test_dns_zone_api.py`.
7. **P4.7 Build the Portal pages.**
   - New app `services/portal/apps/dns/`.
   - Pages: zone list, zone detail, the record form and the nameserver-switch assistant; every delete has `hx-confirm`.
   - Test: `services/portal/tests/dns/test_zone_views.py`.
8. **P4.8 Add the staff zone pages:** zone list and detail under the domains app.

## Phase 5: mail on the nodes

1. **P5.1 Do the lab work first.** Postfix and Dovecot in the lab image; confirm the mail and DKIM programs Virtualmin 8 provides.
2. **P5.2 Update the node playbook.**
   - `virtualmin.yml` installs Postfix and Dovecot, adds `mail` to the default features, and sets `myhostname` to the node FQDN.
   - The failing-first test is `test_feature_set_matches_a_minimal_node`, which is replaced.
3. **P5.3 Allowlist the confirmed programs,** with the read-only ones in the read-only set.
4. **P5.4 Publish the mail records (depends on P4.1).**
   - A `_spf.<zone>` TXT record, rebuilt on node register and destroy.
   - DKIM published in our zones, or shown as records to add.
   - MX as a managed record.
   - PTR through a new optional `set_reverse_dns` on the cloud gateway (Hetzner API), and a checked manual step elsewhere.
5. **P5.5 Relay mail during the bridge.** The bridge playbook adds a Postfix transport `<domain> smtp:[B]:25`.
6. **P5.6 Add the mail settings page.** Platform `services/<id>/mail-settings/`; Portal `partials/mail_settings.html` and a tab on the service page.
7. **P5.7 Watch deliverability.** A per-node blocklist check. The server page shows PTR, SPF membership and blocklist status.

## Paths that must keep records in sync

- **Every `account.server` change** goes through the ownership model (`target_server` and the sync), and a structural test enforces it:
  - the migration's point of no return;
  - `reprovision_virtualmin_account` (after P0.4: only on a verified create);
  - the account sync view;
  - `VirtualminAccountForm`;
  - recovery;
  - server deletion (cascade).
- **Only termination retires a name:** the two writers of `terminated`, and row delete.
- **Rollback deletes keep the name.** A migration target removed by "keep source", `_rollback`, or `_execute_rollback`'s delete-domain deletes the customer domain on that node only, which removes that node's account-name sub-server; the label and records stay.
- **Audit actions,** each with a migration and an entry in `BUSINESS_AUDIT_EVENTS.md`:
  - hostname synced, retired and drift repaired;
  - wildcard issued and distributed;
  - cutover verified;
  - bridge started and torn down;
  - zone and record changes;
  - DNS-check state changes.

## Verification per phase

- `make test-platform`, `make test-portal`, `make test-integration`, `make lint`, `make lint-fsm`, `make check-types` and `make check-types-portal` (cold caches), `make check-migrations`, `make lint-templates`.
- `make test-virtualmin-lab` for node-side tasks.
- e2e for the Portal pages.
- A final review of each PR before merge.
