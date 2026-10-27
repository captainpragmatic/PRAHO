# Implementation plan: account hostnames, customer DNS and mail (ADR-0061)

Every task: a test that fails first (quote the failure line), the fix, green, `make lint FILE=` for every changed file, then a sibling check (grep the defect's shape). Node-side steps are proven in the Virtualmin lab. Cloudflare and public DNS are faked in tests through `register_dns_gateway` and a patched `authoritative_addresses`. Each phase is its own PR series.

**Branch base.** This work changes the same provisioning code as #693 and the differential-backup work (provisioning migrations 0003 and 0004). Phase 0 starts on the differential-backup branch's tip once its stage 2 is committed; each phase rebases onto master as #693 and the differential-backup PR land. New provisioning migrations follow the current leaf. That was `0007_legacy_price_labels` when this was written; P1.1 then added `0008_account_hostnames`. Each later task takes the next number after whatever the leaf is when it lands, never a number fixed in this plan.

## Design corrections found in pre-flight

- **The DNS path cannot live on `Domain`.** A `Domain` row needs a registrar and a TLD (PROTECT keys) and exists only for domains we registered (`domains/services.py:622`, `operation_services.py:122`). Per-account DNS state hangs off `VirtualminAccount` instead.
- **Virtualmin parameters reject `--`, CR and LF** (`apps/common/validators.py:42`, `SUSPICIOUS_PATTERNS`) and are capped at 1000 characters. So:
  - a PEM never goes through the API; certificates travel by playbook and `install-cert` receives file paths;
  - labels are `[a-z0-9]` only;
  - punycode domains (`xn--`) are rejected today, which is fixed in P0.1.
- **One vhost serves one certificate,** so the account name cannot be a ServerAlias on the customer's vhost. It is a **Virtualmin sub-server of the customer domain** with its own vhost and certificate, its web root a relative symlink to the customer's (`docs/domain/virtualmin-account-subserver-contract.md`). An alias domain was disproved first (`virtualmin-account-alias-contract.md`).
- **Recovery today recreates empty domains** (`virtualmin_disaster_recovery.py:44`), and restore never changes `account.server`. P2.9 adds a real recover-to-node service.
- **Sub-servers appear in `list-domains`** (`type: Sub-server`, `parent_domain`) and would corrupt the account sync, `update_server_statistics` and `list_migration_domains`. They are filtered in P1.6.
- **There is no ACME client.** Virtualmin GPL's DNS-01 needs BIND, and nodes run without it. Certificates are issued on Platform with the Python `acme` and `josepy` libraries, so the Cloudflare token stays off the nodes.

## Status (2026-10-19)

- **Phase 0 is built** (PR #695, merged).
- **Phase 1 is built, behind `dns.account_hostnames_enabled` (off)** (P1.2 to P1.16, one PR). It stays off until Phase 2: a migration does not move `target_server` before the cutover exists, so a name turned on now would keep pointing at a node a migration left. Departures from the tasks below:
  - **The zone token is proven at use, not at save.** The settings guard checks only what it can offline (the zone's registrable domain, the PSL gate, the completeness of the settings); every sync proves the token reads the configured zone before it publishes anything.
  - **Cutover settings are deferred to Phase 2** (the lowered TTL and the bridge window belong to the cutover that uses them).
  - **P1.14 is built as "no preview offered"**, pending the owner's decision: nothing links to an account name, and the Portal shows it as text.
  - **The review of P1.9 and P1.10 added guarantees** the tasks did not name: one worker per issuance attempt (a lease, and a token on every write of the attempt); keys created once and never overwritten; a certificate put in force and installed only when it matches its key and name; an install recorded only when the node reports serving that certificate's fingerprint; install evidence dropped before a sub-server is created afresh; one node step per name at a time, and a caller that owns no operation changes the node only under the account lock migration admission takes; every account-name task bounded and dispatched one name per task; the sweep rotated so names that cannot be published never starve the others.
- **P1.0 is done: the sub-server design is proven on Virtualmin 8.3** (`docs/domain/virtualmin-account-subserver-contract.md` on `feat/adr61-phase1-account-hostnames`). The alias attempt before it is recorded in `virtualmin-account-alias-contract.md`. What the lab established, and what every task below relies on:
  - the sub-server has its own vhost on 80 and 443 and its own certificate by SNI, key root-only;
  - its `public_html` replaced by the relative symlink `../../public_html` serves the customer's site, with PHP as the customer's user; no Virtualmin program can do this (`modify-web --document-dir` refuses `..`, a `create-redirect` alias answers 403);
  - `disable-domain` and `enable-domain` reach it only with `subservers`;
  - a customer backup carries it only with `parent`, and an in-place restore of the customer domain keeps it;
  - deleting the customer deletes it; deleting it alone never touches the customer's files;
  - its key is in any archive that carries it, which rules out a wildcard on it unless every such archive is excluded (P1.10).

## Review record

### Execution ledger (2026-10-27)

The implementation continues from PR #749 at `66e31447`, on
`codex/adr61-phase2-complete`. The Phase 2 gates below are recorded separately
from the later phases so a passing bridge test cannot be mistaken for a completed plan.

Owner decisions for the remaining phases:

- Finish Phases 2 through 5, keeping each phase in its own PR series.
- Keep website previews off. Use complete zone-file uploads for the first zone import.
- Install mail on all eligible existing and new nodes through Virtualmin's supported setup.
  Existing external mail stays external until the domain's owner enables hosted mail.
- Advertise implicit TLS client ports 993, 995 and 465.
- Investigate native Postfix/Dovecot forwarding in the mail lab before adding a proxy dependency.
  Native proxying may terminate TLS at the source and use a verified encrypted onward connection;
  the invariant is one authoritative writable mailbox copy, with credentials checked at the target.
- Finish a migration after target activation, bridge verification and DNS convergence. The bridge's
  own retryable task owns retention and teardown, so backups and billing reconciliation resume.
- Phase 4 extends the complete TTL/cutover/restore contract to managed customer-zone records.

Phase 4's implementation and focused verification are recorded in
[account-hostnames-phase4-execution.md](account-hostnames-phase4-execution.md).
Its provider and UI workflows are implemented on a separate stack branch; final integration
checks remain. Native mail setup and forwarding have been proven in the isolated lab, while
the all-mailbox held-restore contract and Phase 5 application integration remain in progress.

Review findings to close, each with a failing regression and recorded green result:

| Finding | State / evidence |
|---|---|
| Original barrier record and saved-crontab token survive replay | Regression green; migration review suite: 100 tests + 90 subtests |
| Compensation preserves each child's enabled state | Regression green in the migration review suite |
| Cancellation removes only the owned, idle target copy | Regression green in the migration review suite |
| Compensation resumes safely and parked rows have staff actions | Regression green in the migration review suite |
| Scheduled wakes keep the migration task timeout | Regression green in the migration review suite |
| Wait the old record TTL after all lower TTLs confirm | Seven regressions reproduced; 46 tests + 16 subtests green |
| Every TTL restoration decision uses fresh publication-locked state | Regression green; 81 neighboring tests green, two PostgreSQL-only tests require PostgreSQL |
| Cloudflare cutover TTL minimum is 60 seconds | Settings regression green |
| Web-only accounts do not issue an empty database-union query | Barrier suite: 47 tests + 20 subtests green |
| Bridge runner allowlist and failed-curl verification | Bridge suite: 35 tests + 2 subtests green |
| Encrypted bridge, aliases, full chain and neutral-default ordering | Real two-node contract green, including continued traffic after source deletion |
| Bridge lifecycle audit coverage | Audit/scanner/model suite: 27 tests green |
| Audit scanner respects lexical scopes | Two scope regressions reproduced; scanner tests green |
| New bridge migration checksum matches its file | 0014 digest corrected; 115 checksums and both service schema checks passed |
| Bridge playbook has production-path lab coverage | Full real-node contract: 37 cases passed in 1512.66 seconds, including active and suspended cutovers and recovery |
| A restored target stays held before ownership commits | Real Unix-lock proof, archived application database login and grants, suspension and activation replay passed |
| Native API children count as running operations during cleanup | Remote CGI and argument-free native-child regressions green; CLI commands for other domains remain independent |
| Cancellation arriving during bridge preparation cannot commit | Fresh-row cancellation regression green; compensation runs outside the ownership transaction |
| A fenced, unavailable source cannot trap an already committed cutover | Audited staff-only fencing control; target-only convergence regression green; failed bridge retains separate cleanup exclusion |
| Customer frontend records and old cache lifetimes gate source deletion | Precommit inventory and TTL evidence, fresh authoritative checks, and per-name retention clocks; 39 tests and five subtests green |
| Opaque proxy origins require explicit staff evidence | Expiring attestation binds target, addresses and full inventory; source addresses and failed DNS cannot be overridden |
| Completed or conclusively abandoned moves remove temporary transport data | UUID-scoped archive and private target-data cleanup, retryable per location, permanent replay markers retained |
| Backup recovery keeps current billing quotas | Two regressions reproduced; current quotas reapplied on target before ownership commits; 32 neighboring checks green |
| Recovery refuses a missing account name before changing nodes | Admission regression green; source remains eligible when admission is refused |
| Cancellation and completed releases survive replay and reboot | Source/pair script suites: 59 tests with 38 subtests; additional bridge/pair batch: 59 tests with 17 subtests |
| External webmail/admin aliases do not require a false target-origin statement | Explicit independent-service declarations, fresh route/cache checks and historical source-IP guards; 52 tests green |

The audit CI failures mentioning `virtualmin_migration_apply` and
`virtualmin_migration_verify` are scanner false positives: unrelated barrier loop
variables were mistaken for audit wrapper parameters. Fix the scanner's lexical
scope handling rather than registering events that no operation emits.

Phase 2 now has two signed implementation commits. Its complete two-node native
contract passed all 37 tests, including active and suspended cutovers/recoveries;
the PostgreSQL gate passed 743 tests. The final full-suite and lint runs remain
the publication gates. Earlier "pending" entries above retain the investigation
history; these fresh complete gates supersede the individual lab rerun notes.

Phase 3 is implemented on its own branch. The transport shares a 90-second/96-query
budget, records five independent component results and explicitly limits DNSSEC to
DS/DNSKEY consistency. Offline reads invalidate old results against current ownership,
tenant and bridge maintenance state. Manual rechecks persist intent; a bounded
dispatcher queues probes outside requests. EmailLog creation, incident state and
the observation commit share one transaction, with delivery dispatched after commit.
Per-component definitive history prevents unknown observations from inventing a
healthy baseline or hiding a later healthy-to-broken transition. Customer output
excludes private evidence, while staff see bounded, escaped recorded observations.
Focused tests include real signed API requests, revocation, rollback, slow-render
lease expiry, malformed Portal receipts and concurrent PostgreSQL workers. Final
combined, UI, schema, lint and type gates remain before the Phase 3 draft PR.

Phases 4 and 5 remain in progress. Their implementation is incomplete until the
unit, integration, PostgreSQL and applicable real-node/Portal checks below pass.

The HTTP bridge uses a migration-owned TLS origin on the target's existing port 443,
restricted to its source and admitted hostnames; HTTPS uses the customer's verified
target vhost. No new proxy service, provider firewall rule or listening port is needed.
The retained frontend certificates bound the bridge deadline and any staff extension.

Recovery uses a disabled placeholder and the existing-domain restore path, with Unix
restore excluded and the inherited maintenance barrier retained until ownership commits.
Review against Virtualmin 8.3 established additional gates: restore the archive's Unix
hash through native `modify_unix` so `disabled_oldpass` is correct, use reversible native
cron markers, and persist node activation before exposing the target so replay cannot
overwrite a customer's new cron. These recovery gates passed their real-node checks.

Native existing-domain restore also creates database users from the placeholder's domain
metadata. Before activation, the target therefore needs the archived native credential metadata
as well as its Unix hash. The real-node acceptance checks use the original database login and
grants for both active and suspended accounts; matching table contents alone is insufficient.

- **Phase 1 v3 (sub-server design):** two adversarial plan reviews. Pass 1 REWORK (0 CRITICAL, 5 HIGH, 3 MEDIUM, 1 LOW), all folded in with two extra lab checks (S10, S11); pass 2 APPROVE (0 CRITICAL, 0 HIGH, 1 MEDIUM, 1 LOW), both folded in.

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
  - `rebuild_server_from_praho` recreates *empty* domains. It refuses `dry_run=False` until P2.9's recovery replaces it, and says so in its docstring.
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
2. **P1.1 Add the models (provisioning migration 0008, after `0007_legacy_price_labels`).**
   - `VirtualminServer.ipv4_address` and `ipv6_address`.
   - `AccountHostname`: UUID, `label` (`^[a-z0-9]{8}$`, unique, never reused), `account` (OneToOne, SET_NULL), `target_server`, `zone`, `records` (per-record publication progress: intended content, applied content, provider id, applied TTL), `previous_ttl`, `ttl_lowered_at`, `last_reconciled_at`, `retired_at`, timestamps.
   - `VirtualminAccount.activation_notified_at`.
   - `AccountNameCertificate` (P1.10's durable issuance state): hostname (OneToOne), `status` (`pending`, `ordering`, `issued`, `failed`), ACME order URL, `not_after`, `reserved_at`, `retry_after`, vault references for the certificate and key, timestamps.
   - `AccountNameCertificateBudget`: one row per account zone, locked with `select_for_update` for every reservation.
   - IP backfill from deployments, after P0.3.
   - Audit wiring.
3. **P1.2 Fill server IPs** on registration and in the staff form (`public_address()` validation).
4. **P1.3 Add the settings group `hosting-dns`.**
   - Keys: `dns.account_hostnames_enabled`, `dns.account_hostname_zone`, `dns.account_hostname_zone_id` (`^[0-9a-f]{32}$`, and checked against the zone name through the API as `deployment_service.py` ~1520-1527 does), `dns.account_zone_api_token`, `dns.account_record_ttl_seconds` (300), `dns.cutover_ttl_seconds` (60), `dns.bridge_window_hours` (48).
   - **Token:** its own token with Zone:Read and DNS:Edit on the account zone only. Never the node token.
   - **Registrable-domain guard:** the zone must be a different registrable domain from the brand and Portal domains, using the Public Suffix List with private suffixes (new dependency `publicsuffixlist`). That refuses siblings such as `preview.example.ro` beside `portal.example.ro`, as well as equal names and children.
   - The zone and zone id cannot change while live hostnames exist. The token can be replaced at any time, after the new one is proven to read and edit that same zone id (rotation of an expired or leaked token must not wait for hostnames to retire).
   - Tests: sibling, child and equal names are refused; a different registrable domain is accepted; zone changes are blocked while names are live; a token for the same zone rotates with live names, a token for another zone is refused.
5. **P1.4 The hostname service** (`apps/provisioning/account_hostname_service.py`).
   - `sync_account_hostname(hostname)` converges records to `target_server`, persisting the intent before the call and the progress per record after it.
   - `retire_account_hostname(hostname)`.
   - `ensure_node_account_name(account, server, *, enabled: bool)`: idempotent.
     - **Ownership, read from the node's full listing (P1.6's unfiltered inventory):** the customer domain must be a `Top-level server` owned by `account.virtualmin_username`. If the name is absent, `create-domain` with `domain=<label>.<zone>`, `parent=<account.domain>`, `dir=`, `web=`, `ssl=`, `desc=`. If present, it must be a `Sub-server` whose `parent_domain` is `account.domain` and whose unix owner is the same user; anything else (another parent, a top-level server, another owner) is refused and nothing is changed. The listing is read again after the create and before each later step.
     - **State before content:** a child created under a disabled customer domain starts enabled (lab S10). When `enabled` is false (the account is suspended, or this node's copy is a migration target not yet active) the ensure disables the child and verifies `Disabled` **before** the link step. When true it verifies the child is enabled.
     - Then the link playbook (P1.15), then the current certificate (P1.10).
     - Returns a typed result; an ambiguous gateway answer is not success.
   - `remove_node_account_name(account, server)`: `delete-domain` of the name only, after the same ownership check read immediately before the call. Proven safe: it removes the sub-server's own home and never follows the link (lab S7b).
   - The sync acts only on accounts that are active or suspended with `provisioned_at` set.
   - **PRAHO's own archives do not carry the account name.** Standalone, chain and migration backups keep calling `backup-domain` without `parent`, and PRAHO recreates the name from its record on the node that ends up serving the account. That keeps the name out of the archives PRAHO stores and hands to customers, keeps the differential chain to one domain, and avoids a second `restore-domain` call. **The node's own nightly schedule is different:** it backs up with `--all-domains` (`virtualmin_backup.yml`), so those archives do carry each name's sub-server and its per-name key; that is accepted (the key covers only that customer's own name, lab S5). The legacy `rebuild_server_from_praho` stays dry-run only until P2.9.
   - Tests: absent → created, state set, linked, certified, in that order; present and owned → no create, link re-applied; present under another parent, as a top-level server, or with the right parent name but another owner (a parent recreated under another user) → refused, nothing changed; ambiguous create → not success; created under a disabled parent with `enabled=False` → disabled before the link; remove refuses a row it does not own.
   - Lab test (the recreate-from-PRAHO path, not the archive path): a parent-only archive restored on another node, then `ensure_node_account_name` → the name serves the customer's content with the same certificate fingerprint.
6. **P1.5 Cascade suspend and unsuspend to the account name.** Without it the name keeps serving the customer's site while the customer domain shows the disabled page (lab S3).
   - Every `disable-domain` and `enable-domain` PRAHO sends for a customer domain adds `subservers=`: `virtualmin_service.py` ~887 and ~1024 (suspend, activate), their compensating operations (~896, ~1033), the operation table at ~1384, the queued-operation executor (~751, ~762), the migration's source disable and enable and target enable (`virtualmin_migration_service.py` ~430, ~447, ~558), and the pair-restore node script `infrastructure/ansible/playbooks/files/praho-pair-restore.sh` (its `disable-domain`, the compensating `enable-domain`, and the re-apply step's disable), which must also verify both the customer domain and the name as disabled.
   - One helper builds the parameters (`domain_state_params(domain)`), so a new call site cannot forget the flag; a test greps the provisioning package **and the playbook files** for a `disable-domain`/`enable-domain` call that bypasses it (the shell script must carry `--subservers` on each).
   - Contract suite: record `disable-domain` and `enable-domain` with `subservers=` on a domain with and without a sub-server.
   - Tests: each call site sends the flag; with the flag removed, the lab workflow test sees the account name still serving after suspend.
7. **P1.6 Tell account-name rows apart without hiding them from safety checks.**
   - One parser keeps the full inventory: every row with its type (`Top-level server`, `Sub-server`, alias), `parent_domain` and unix owner, read from the raw row (text `Type:` or JSON `values.type`) before `SNAPSHOT_ATTRIBUTES` drops the marker.
   - **Filtered** (customer domains only): account discovery in the sync (`virtualmin_views.py`), staff display, and server statistics (`virtualmin_service.py`, which stops using the name-only listing that cannot tell rows apart).
   - **Unfiltered** (every row): collision and ownership checks, `list_domains_with_owners` (`virtualmin_gateway.py` ~1408), the restore target gate (`virtualmin_backup_service.py` ~821, `_target_domain_gate`), and migration admission.
   - **Migration admission** (`virtualmin_migration_service.py` ~338, "Source owner must have exactly one domain") exempts exactly one row: the verified account-name child (P1.4's ownership test, label matching the account's `AccountHostname`). Any other sub-server or alias owned by the customer still refuses the migration, because the parent-only archive would drop it.
   - Tests from recorded fixtures: the sync does not import the name as an account; statistics do not count it; migration admits an account with its own name child and refuses one with an extra sub-site; the restore gate and collision checks still see a sub-server named like the customer's domain.
8. **P1.7 Lifecycle at one completion boundary.**
   - A single `on_account_ready(account)` runs on every path that finishes a create: `_handle_successful_provisioning_secure` (`virtualmin_tasks.py` ~542), `_retry_create_domain` (`virtualmin_service.py` ~1298) and direct creation. It sets `target_server`, calls `ensure_node_account_name(account, account.server, enabled=account.status == "active")` and enqueues the sync.
   - **The same ensure runs wherever a customer domain is recreated from nothing:** a migration's target after `restoring` and before `activating` (`_restore`/`_activate`), a recovery or `rebuild_server_from_praho` restore, and a backup restore that recreated the domain. An in-place restore keeps the name (lab S9), so the ensure is a cheap no-op there.
   - **A migration target is created disabled.** The ensure runs on the target with `enabled=False` while it is still disabled; `_activate`'s cascading enable (P1.5) turns the name on with the account, and a suspended account's target keeps both disabled. Recovery and restore paths pass the account's own state (`enabled=account.status == "active"`).
   - **The pair restore's 503 barrier must cover the account name's vhost too.** It matches the customer vhost's `DOCUMENT_ROOT` and its names today. The account name is a separate vhost with its own document root (the link) and its own generated names (`www.`, `mail.`, `webmail.`, `admin.` of the name), so the script collects both vhosts' roots and full name sets into the barrier, and P1.5 disables both domains. Lab test: requests to every name of both vhosts answer 503 throughout both restore steps, after a failure, during compensation, and stop at release.
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
    - **Let's Encrypt budget, durable.** New names are limited per registered domain over a rolling window that refills continuously; renewals of an existing identifier set do not consume it. Each issuance is an `AccountNameCertificate` row (P1.1) moved `pending → ordering → issued|failed` under a row lock; a reservation is taken atomically on the zone's `AccountNameCertificateBudget` row (rolling seven-day count, setting `dns.account_cert_weekly_budget`, default 40). The issuer honours `Retry-After`, resumes an `ordering` row after a crash from its stored order URL instead of ordering twice, and an ensure or a move never orders for a name that already has valid material (it reinstalls the stored certificate); only the scheduled renewal orders while a valid certificate exists. The issued certificate is kept on its own fields, apart from the attempt state, so a renewal in `ordering` or `failed` leaves the current certificate in force. A staff alert fires at 80% of the budget.
    - **Readiness is valid material installed on the intended node,** not the attempt state: every sync entry point (P1.4, P1.8, "Repair DNS", P1.12's email) publishes and announces a name only when an unexpired certificate for it is installed on `target_server`. A first issuance still `pending`, `ordering` or `failed` keeps the name unpublished and unannounced; a failing renewal does not unpublish a name whose certificate is still valid.
    - **Public Suffix gate, enforced.** A setting `dns.account_zone_psl_shipped` (default off) is set by staff only once the zone's Public Suffix List entry is confirmed shipped in current browsers. Until it is on, a published account name serves the node's neutral default site (P1.16) and never customer content: P1.15 does not link the web root, and hiding the preview link alone would not stop direct visits or customer CNAMEs setting a zone-wide cookie. Turning it on links the web roots on the next sync.
    - Renewal runs daily for certificates under 30 days left.
    - Distribution by playbook with the existing temporary-vars-file pattern (`no_log`, never argv): write the PEMs to a root-only temporary directory on the node, `install-cert --domain <name> --cert <path> --key <path>`, delete the files in the same play.
    - `ensure_node_account_name` installs the current certificate before the name's records are published.
    - Tests: issuance through a faked ACME directory and DNS gateway; two workers reserving the last budget slot → one order; a crash in `ordering` resumes the same order; `Retry-After` is honoured; budget exhaustion leaves the name unpublished and unannounced; renewal picks only near-expiry names and consumes no budget; a renewal left `ordering` or `failed` keeps DNS published and the old certificate in use; the playbook leaves no PEM behind (lab).
12. **P1.11 Show the account name and DNS instructions in the Portal.**
    - Builds on P0.9.
    - `ServiceDetailSerializer` adds `hosting` (account name, path, instruction records), read safely when no account exists.
    - Portal: `service_detail.html` plus `partials/dns_instructions.html`.
13. **P1.12 Send the activation email once,** after the first verified sync, guarded by `activation_notified_at` under `select_for_update`.
14. **P1.13 Staff pages.**
    - Hostname card on account detail.
    - "Repair DNS" enqueues a sync and returns at once; no DNS lookup inside a request.
    - Server IPs on the server pages.
15. **P1.14 WordPress preview decision** (owner). Whatever is decided, no preview serves customer content on an account name until the zone's Public Suffix List entry is confirmed shipped in current browsers (ADR-0061 section 1). Until then the preview link is not offered, because a customer site could otherwise set a cookie for the whole zone.

**Build order** (dependencies, not numbering): P1.1 → P1.2, P1.3 → P1.6 (which supplies the shared row and ownership predicates P1.4 uses) → P1.5 → P1.9 → P1.10 → P1.15 → P1.4 → P1.7 → P1.8 → P1.11, P1.12, P1.13 → P1.16 (any time).

16. **P1.15 The link playbook** (`infrastructure/ansible/playbooks/virtualmin_account_name_link.yml`, allowlisted in `apps/infrastructure/ansible_service.py`).
    - Inputs: the sub-server's home as the node's own listing reports it (never built from user input) and the customer's unix user, both re-checked by P1.4 just before the call.
    - **No privileged path-following.** The home and its ancestors are customer-writable, so every filesystem step runs **as the customer's own UID** (`become_user`), never as root: `lstat` each component from `/home/<user>` down and refuse on any symlink or foreign owner; then, inside the sub-server's home only, `ln -s ../../public_html public_html.new` and an atomic rename over `public_html` (a real directory is first renamed `public_html.own`, once). Running as the customer gives the step no more access than the customer already has.
    - Idempotent: a correct link changes nothing.
    - Lab tests: the name serves the customer's marker and PHP as the customer's user; a second run changes nothing; `validate-domains --all-features` stays clean; with the sub-server's home or an ancestor replaced by a link to another account's directory or to `/etc`, the playbook refuses and changes nothing.
    - **Out of scope, an owner decision:** lab S11 shows any customer can already swap their own web root for another customer's files or `/etc` and read them through Apache (which is in every customer's group). The account-name link is one more root of that kind. Closing it (a customer-immutable web-root path, or Apache out of customer groups) is a node-hardening change of its own.
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
2. **P2.2 Add the cutover states (the next provisioning migration after the current leaf)** for the contract's steps. Add `VirtualminMigration.drain` (FK). `RESUME_POLICY` gets a policy for every new state; replay converges forward after step 5.
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
   - Hostnames of non-live accounts (error, provisioning) left on the drained node have their records withdrawn, so no address is published and the node's IP being reused later cannot take them over. The names are not retired: only termination retires a name, so a later retry or recovery keeps the same hostname. Their `target_server` is cleared in the same step (the field is nullable), because it protects the server row and would otherwise block deleting the drained node; a later recovery sets it again.
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
   - the next provisioning migration after the current leaf.
2. **P3.2 Write probes that follow CNAMEs.**
   - New `apps/infrastructure/dns_probes.py`. Checks: `www` reaching the account name, the apex, MX, stray AAAA, CAA allowing Let's Encrypt, and DNSSEC (DS against DNSKEY).
   - Test: `tests/infrastructure/test_dns_probes.py`.
3. **P3.3 Classify and schedule.** Hourly observations, dispatched in bounded batches every five minutes. Email template `hosting_dns_broken`, sent once per healthy-to-broken incident. Tests: `tests/provisioning/test_hosted_domain_dns_status.py`.
4. **P3.4 Add the API and the Portal status card.**
   - `TECH_ROLES = {"owner", "tech"}` in `api/secure_auth.py`.
   - Platform `services/<id>/dns-status/` and `.../recheck/`.
   - Portal `ServicesAPIClient.get_service_dns_status`, view `services/<id>/dns/`, `partials/dns_status_card.html`.
   - Tests:
     - `tests/api/test_service_dns_status_api.py`: another customer gets 404; a viewer cannot recheck;
     - Portal `tests/services/test_service_dns_status_card.py`.
5. **P3.5 Add the staff check results.** A panel on account detail and a list of recorded broken/unknown domains. Tests: `tests/provisioning/test_hosted_domain_dns_views.py`.

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
3. **P4.3 Import the complete zone before activation.** Arbitrary subdomains, verification TXT records, uncommon DKIM selectors and custom service records cannot be found by lookups, so querying common names is not an import.
   - Take the zone from its current provider (a zone-file export or the provider's API), or from a zone file the customer uploads.
   - Probing common names (apex, `www`, `mail`, `_dmarc`, `autodiscover`, common DKIM selectors and SRV names) only cross-checks the import; a probe answer missing from the import blocks activation.
   - The customer confirms the imported record inventory before the nameserver switch is offered.
   - Test with a fixture zone holding records no probe would find.
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
   - `virtualmin.yml` and the existing-node mail-only playbook install Postfix and Dovecot through Virtualmin's supported selective setup, make `mail` available but default-off, and set `myhostname` to the node FQDN. Existing domains retain external mail until an explicit owner opt-in completes.
   - Extend the minimal-node feature test to prove mail capability and default-off enrollment. Preserve web previews, unrelated domains and provider credentials; do not rerun the full installer over an existing node.
3. **P5.3 Allowlist the confirmed programs,** with the read-only ones in the read-only set.
4. **P5.4 Publish the mail records (depends on P4.1).**
   - A `_spf.<zone>` TXT record, rebuilt on node register and destroy.
   - DKIM published in our zones, or shown as records to add.
   - MX as a managed record.
   - PTR through a new optional `set_reverse_dns` on the cloud gateway (Hetzner API), and a checked manual step elsewhere.
5. **P5.5 Relay mail during the bridge.**
   - Inbound delivery uses a dedicated native Postfix transport with verified TLS to the fixed target and no plaintext fallback. Preserve full envelope recipients before Virtualmin's local alias expansion; a domain transport alone is insufficient. Prove the source writer/SMTP generation boundary, queued delivery, all-mailbox held restore and exact compensation before lifting the existing mail-migration refusal.
   - Mail clients: prove native Dovecot proxying and Postfix relay behavior in the lab before choosing a forwarding topology. Advertise implicit TLS ports 993, 995 and 465. A stale-DNS client must authenticate against the destination and use its single authoritative mailbox copy, with verified encryption between nodes. Source TLS termination is acceptable with an independently retained certificate; HAProxy is not a prerequisite.
   - Preserve per-mailbox authentication throttling and source client-IP blocking during forwarding; an abusive login must not ban the whole forwarding node. The source Virtualmin domain is retained until client forwards and owned mail queues have drained, then mail routes are torn down before native source deletion. The web bridge and retained certificates remain until their own cleanup gates pass.
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
