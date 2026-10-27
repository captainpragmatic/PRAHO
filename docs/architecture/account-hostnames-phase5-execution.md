# ADR-0061 Phase 5: native mail implementation and verification plan

Updated 2026-10-27 after real authorized probes on isolated vmlab-a/vmlab-b. This branch starts from the signed Phase 4 checkpoint and keeps the implementation in a separate PR. Native mail transport has lab evidence; the hosted-mail application lifecycle is not implemented yet. The production `mail_feature` migration refusal remains required until every gate below passes. The architecture and service boundaries remain those in ADR-0061 and the existing Platform/Portal design.

## Chosen native topology

Install standard Postfix/Dovecot capability on eligible existing/new nodes. Every domain stays external until owner opt-in; previews stay off. Advertise implicit TLS993/995/465; disable public110/143/587. Postfix25 retains ordinary Internet SMTP compatibility; migration relay specifically requires verified TLS. No HAProxy, stunnel, new global PKI or shared relay credential is needed by the proven topology.

Client993/995/465 → source Dovecot login proxy → target Dovecot same port. Target checks current mailbox password and owns the only writable mailbox. For465, target Dovecot login-proxies the password again to loopback Postfix1465, which authenticates through Dovecot SASL. SASL uses service smtp: its proxy file MUST remain empty, otherwise a nopassword proxy record could count as successful local SMTP authentication.

Per-user route: proxy=y nopassword=y host=<target-node-FQDN> hostip=<fixed-target-IP> port=<993|995|465> ssl=yes proxy_not_trusted=y destuser=<actual-native-login>. No master password, any-cert mode, source fallback or cross-node trusted auth network. Dovecot2.3 proxy trust uses ssl_ca; ssl_client_ca_file alone is insufficient. Lab private CA simulates ordinary verified production node/customer certs, without client certificates/CRL infrastructure. [Dovecot2.3 proxies](https://doc.dovecot.org/2.3/configuration_manual/authentication/proxies/), [extra fields](https://doc.dovecot.org/2.3/configuration_manual/authentication/password_database_extra_fields/)

Postfix1465: loopback only, implicit TLS, Dovecot SASL private/auth, authenticated users only, sender-login ownership check, XCLIENT disabled. Auth socket postfix:postfix0660 inside private queue directory. Actual mailbox UID could not access it, read root-private experimental key, relay without auth or spoof another sender. Chosen topology uses no shared relay key/password. [Postfix SASL](https://www.postfix.org/SASL_README.html)

Postfix25 AUTH must be disabled in main.cf AND smtp/inet overrides; native setup adds a master-specific AUTH=yes override. Preserve smtp/unix when editing smtp/inet: use exact postconf service/type keys. Migration uses dedicated native praho-migration/unix SMTP transport (same Postfix smtp binary) default smtp_tls_security_level=secure; fixed [target-IP]:25 policy adds secure match=<target-FQDN> servername=<target-FQDN>. Missing policy and invalid certificates deferred mail, never plaintext/local fallback. Internet mail keeps opportunistic default. [Postfix TLS](https://www.postfix.org/TLS_README.html)

## Actual environment and bounded evidence

Virtualmin8.3.0-1-gpl; Debian12 ARM64; Postfix3.7.11-0+deb12u1; Dovecot2.3.19.1+dfsg1-2.1+deb12u6; procmail-wrapper1.3-1; native OpenDKIM. Both Exim queues exactly0 before replacement. Snapshots praho-adr61-mail-baseline-a:20261027 and praho-adr61-mail-baseline-b:20261027 allow full rollback. No production/cloud credentials or original dirty checkout changed.

Private controllers: /private/tmp/adr61-mail-proof.py, adr61-mail-queue-proof.py, adr61-mail-auth-policy-proof.py, adr61-mail-dkim-proof.py; supplemental adr61-mail-proof.mk wraps their Python with root Makefile/venv. Sanitized facts: /private/tmp/adr61-native-mail-proof/evidence.jsonl. Generated fake secrets remain in0700/0600 private state, never repository fixtures/logs.

## Existing-node installation findings

Install explicit Postfix, dovecot-imapd/pop3d/submissiond, Procmail/procmail-wrapper and OpenDKIM packages. Native virtualmin config-system --include Postfix Dovecot Procmail --test configures then tests: --test is NOT dry-run. Never rerun full installer/bundle on existing nodes.

Selective setup leaves virtual-server mail_system=99 and mailboxes mail_system=6 (Exim). Narrow native root helper must lock/update BOTH to0. Only changing virtual-server produces backend mismatch; enabling mail before fixing can silently omit aliases. Full setup changes unrelated defaults; narrow setters preserved observed DNS/cloud-prefixed config and old domain features. Rollout must still inventory unmanaged mail/custom configs and preserve nonempty Exim queues explicitly.

set-global-feature --enable-feature mail --default-off mail sets availability2. Real old/new default-feature domains stayed mail-off. However global native PAM accepted a mail-off Unix owner until exact hosted-user PAM username_filter was applied. Maintain that roster through opt-in/CRUD/held activation; empty roster must fail closed. Public ports stay closed until hardened overlay is applied; package autostart/repeated setup otherwise briefly exposes defaults.

Native install-cert plus install-service-cert --domain ... --service dovecot --service postfix --add-domain succeeded. Separate customer-only/node-only certificates proved actual SNI, not accidental global certificate coverage.

## Authentication / brute-force policy, proven

Target Fail2ban banned entire sourceIP after deliberate bad-password tests. Changed password worked target-local while source TCP was refused; actual Ban/Unban timestamps confirmed aggregate rate control, not failed password forwarding. An arbitrary source mailbox UID can originate TCP with sourceIP: never call that authenticated proxy identity.

Replacement uses already-installed native pam_faillock in dedicated praho-dovecot PAM service, selected only by Dovecot PAM driver, with root-private separate tally dir. Original dovecot/common-auth/sshd files stayed byte-identical. Lab deny3/fail300/unlock120 locked attacked mailbox across993/995/465; second mailbox stayed healthy. Mail-locked owner still authenticated through native sshd PAM. Unix hashes unchanged. [Bookworm faillock](https://manpages.debian.org/bookworm/libpam-modules/faillock.conf.5.en.html)

Only after replacement passed, temporary scoped Dovecot-auth-jail rate handoff ignored registered sourceIP aggregate bans; no auth/relay/XCLIENT trust. Actual unprivileged source UID attacked destination owner: owner throttled, reader healthy, no entire-source ban. Actual remote client172.18.0.4 then attacked source frontend: source jail banned that real client after5 attempts, unrelated mailbox still worked. Temporary exception and owned test bans/tallies were reverted afterward.

Implementation: destination account throttle stays on all nodes; only active verified bridge pair IPs enter Dovecot-auth-jail rate handoff, refcounted through last pair teardown. Source retains real-client bans; SSH/other jails and Dovecot trusted networks unchanged. Gate readiness on both controls. Suggested production deny5/fail300/unlock300 bounded policy; test fixture thresholds explicitly. Handoff is a rate-control replacement, never password/process trust.

## Writer / queue / TLS proof

Real IMAP APPEND loop was kicked after29 writes; SMTP transaction already past RCPT could not send DATA after old Postfix generation retirement (~2.31s). Scope450 RCPT gate first, deny all moving login forms, flush cache/kick Dovecot backend+proxy sessions, retire SMTP/local delivery generation, drain previously accepted local queue or refuse precommit. Native disable alone does not do this. Use supervised native systemd lifecycle in implementation to retain logs/jails.

Preserve native aliases for backup/compensation. Prepend owned-domain self-alias identity map so source queues full customer reader/alias addresses instead of old Unix recipients. Wildcard self-alias makes unknown users appear listed: separate exact recipient access map is mandatory (RED250 unknown accepted, corrected550). New target mailbox/alias activation must synchronously update source maps or remain pending; unsynchronized hard550 maps can bounce valid new mail. Canonicalize envelope-only legitimate local UID addresses; real mailbox UID sendmail queued full customer email; headers/DKIM preserved, external quoted-@ spoof remained rejected.

Three accepted messages (reader/alias/local Unix UID) durably held under retry transport; unknown/open relay rejected. Fixed-target verified TLS delivered each once and drained source queue; all266 source message files stayed byte-identical. Bad target cert retained queue with TLS-specific reason; valid recovery delivered once. Missing TLS policy under secure dedicated transport also retained queue, valid recovery delivered once.

Postcommit993 APPEND/995 delete/465 delivery modified only target; rotated target password accepted all3, valid old source password rejected. Wrong backend FQDN/untrusted/expired cert refused all3 while source frontend TLS independently verified. No source PAM fallback. Observed fault-free once-only result does not promise universal SMTP exactly-once: failure after delivery but before250 remains normal SMTP retry ambiguity requiring queue/log evidence, never dropping uncertain accepted mail.

## Native DKIM public API / portability

set-dkim --enable --selector ... --size2048 --no-verify --add-extra <explicit-hosted-domain> supports external DNS. Do not set global dkim_alldns3 blindly: native can_dkim_domain then permits mail-off domains too. get-dns refuses no-local-DNS domains; there is no get-dkim public CLI.

Narrow helper calls get_dkim_config/get_dkim_dns_pubkey(config,owned_domain), projecting selector/name/type/public TXT only. No arbitrary Perl, broad list-users plaintext/hash output, full domain structs or private keys. Native generate_dkim_key/save_domain_dkim_key provides per-domain key; node-global default key would change on migration.

Real external-DNS domain got distinct native2048-bit key unreadable to mailbox UID. Public TXT verified real rsa-sha256 OpenDKIM message (relaxed/simple); changed body/From rejected. Native mail backup included exact custom key in _domdkim; test archive removed. Native feature-mail restore source3241–3250 restores key if target DKIM configured, but external-domain signing selection/selector continuation still needs actual held-restore proof.

## Cleanup and certificate policy

Keep source Virtualmin domain until mail forward/session/accepted-queue/cache retention safely finished. Native certificate cleanup removes matching Dovecot local_name blocks across includes; copied PEM alone does not survive native deletion. No extra deletion registry solely to force mail forwarding after delete.

Order: verify mail teardown/quiescence/zero owned queue work → delete source → remove exact migration mail rules without local fallback → web teardown → TTL restore. Keep protective recipient/routing fences through deletion. Extension cannot outlive actual source client certificate deadline. Renewal/reconcile must preserve bridge overlay or refuse uncertainty.

## Gates still required before mail_feature refusal can be lifted

All-mailbox held restore, not just owner: native mail callback re-creates child users with archived hashes and restores child crons independently of Unix feature. Native enable_mail strips ! from EVERY child password and enables EVERY child cron, so per-child original state must be staged explicitly. The actual mixed-user run is RED: held users were locked and crons inactive, but the originally active child stayed locked after activation and its cron remained frozen. The originally disabled child retained its state. Owner password/cron survived, while owner and active-child aging/expiry were lost. Exact source compensation and fixture teardown passed. The shared owner-aging omission is being fixed in Phase 2; that alone does not prove child restoration. Stage all original per-user states before source freeze, bind them to the actual owned target domain/UIDs, and keep every auth/write surface held until verified activation.

Target private stage must complete before ownership commit; source loss cannot prevent activation. Durable applying/completed marker must preserve customer-modified child password/cron on replay; interrupted applying refuses safely. Secret retirement keeps small replay/deletion/reboot tombstones. Precommit compensation restores exact source per-user state/routing while target stays inaccessible. Active+suspended parents, mixed disabled users, mail-user DB credentials, existing FTP/SSH/app writers, UID/domain conflicts and target-only recovery need real tests.

DKIM key/selector/signed-message continuity through held restore/recovery, mailbox/alias CRUD map synchronization, zero-recipient roster, rate handoff refcounts/revoke/replay, SNI renewals/extension limits, multiple source pairs and provider/firewall deployment require contract coverage. No current P2 unit or owner-only native test substitutes for these gates.

## File/task boundaries after P4 freeze

Node/API: new virtualmin_mail.yml, Dovecot/Postfix/PAM templates + narrow native mail helper; existing virtualmin.yml/bootstrap variables; fixed program/parameter adapters + allowlist; new typed virtualmin_mail_service.py; per-domain opt-in/capability/SNI/public-DKIM readiness.

Migration: new migration_mail_service.py + migration-owned node registry; extend migration_barrier.py/write-barrier record with every mailbox original state; shared held recovery/credentials helper all-user private staging+activation; bridge cleanup ordering/compensation/refcount; lease-fenced checkpoint integration. Keep refusal until native gates pass.

Owner/staff: mail-mode model/migration, explicit owner opt-in, mailbox/alias quota/authorization, useful status/error text, DNS record ownership/outbox/cached checks, explicit SPF merge and existing DMARC retention. Previews remain off.

Tests: new native mail contract, unit service gates, active/suspended/mixed-user restore/recovery/replay, recipient queues/TLS/PAM/Fail2ban tenant boundary, existing+fresh node setup, exact idempotent teardown/pre/post state. Root Makefile commands only; no raw secret fixtures.

## Execution contract

### Current implementation evidence

The first P5.3 persistence boundary is implemented on this branch: an account has no hosted-mail
enrollment by default; explicit configuration starts external. Hosted activation requires fresh native
and DNS receipts bound to the current canonical account, customer, service, node addresses and stable
client name, plus the confirmed consent digest. A committed hosted enrollment receives its own UUID.
Retirement requires fresh native-disabled/accepted-queue proof for that exact enrollment; returning to
external mode retires its readiness. Incomplete partial mode saves refuse before changing the FSM's
concurrency state, and mode writes persist all associated receipt changes together.

`VirtualminMailOperation` preserves immutable owner intent, submission UUID and target generation.
An awaiting-DNS or uncertain attempt retains the one-open-operation exclusion; terminal attempts do
not release submission identity. Model signals audit persisted mode/operation changes using the existing
`configuration_changed` action, without copying native payloads or emitting events for lease heartbeats.
This is persistence evidence; the consent HTTP flow, worker integration and native activation are still
pending, and mail migration admission remains refused.

Verification: 20 focused model/audit regressions pass on SQLite and PostgreSQL, strict typing passes for both new modules, and
Ruff plus import/FSM/audit guards pass. Independent review reproduced two persistence edges before their
fixes: partial-save FSM state and prior-enrollment retirement replay. QuerySet mode writes also refuse a
bypass of the verified transition. The real migration-backed gate passes, 123 migration checksums match,
and neither service has schema drift. The PostgreSQL race proofs are recorded separately below.

The offline enrollment service now stages a bounded, expiring proposal and records only the current
owner's exact confirmed intent. Twenty behavioral cases cover current membership, ownership/generation
changes, service/domain holds, immutable consent, retries and unknown outcomes, with no backend or queue
calls. Four real PostgreSQL contention tests prove same-submission deduplication, one distinct admitted
attempt, and both orderings against public migration admission.

Reverse admission also reserves the account against a later move, deletion, backup or restore. Waiting
mail work still permits name/certificate prerequisites; running or uncertain native work refuses them.
Ordinary billing reconciliation keeps its separate permission. Model/enrollment/exclusion, public
deletion/backup/restore guards, existing operation callers and all four contention cases pass together
on PostgreSQL (77 cases). Final stack gates remain separate.

The repository's automatic deployment currently supports Ubuntu 26.04. The Debian 12/Dovecot 2.3 lab
profile does not establish support for that deployment default. Ubuntu's Dovecot 2.4 configuration and
actual native lifecycle remain required gates before bootstrap wiring can claim successful mail setup.

The following files are proposed additions unless already named as existing. Each task starts with a behavioral RED test, then the smallest implementation, focused GREEN, sibling regression checks and fresh Makefile lint/types. Native proof gates remain separate from mocked application tests. Production/cloud/registrar writes are not part of this implementation session.

| Task | Files and independently verifiable result |
|---|---|
| P5.1 Install supported mail capability | Add `services/platform/infrastructure/ansible/playbooks/virtualmin_mail.yml`, fixed native configuration helpers/templates and call it from `virtualmin.yml`; update lab image/bootstrap where necessary. Inventory the MTA/queue first, preserve operator configuration and provider credentials, prevent package-default public listeners before the hardened overlay, and leave mail default-off for every domain. Refuse unsupported native versions or unmanaged mail state before mutation. Prove fresh/existing setup, repeated setup and exact listener/feature inventories. |
| P5.2 Project native public state safely | Add `apps/provisioning/virtualmin_mail_service.py` and a narrow node-local helper for domain/user identity, public DKIM, certificate and readiness observations. Extend `virtualmin_validators.py` only for programs/flags actually used. Never forward root `list-users` output, password hashes, private key paths/content or arbitrary command parameters. Prove malformed/foreign domain, owner/UID conflicts, mail-off users, public-key signing and sanitized recording behavior. |
| P5.3 Record owner opt-in and progress | Add `virtualmin_mail_models.py`, `virtualmin_mail_tasks.py` and service orchestration, with the next actual migrations/audit catalog entries. Keep current configuration separate from durable per-attempt intent, consent digest, lease, phase, outcome and target generation. Business mail mode uses protected FSM transitions; operational work uses fenced checkpoints. A missing configuration reads as no PRAHO hosted-mail enrollment. Every old/new domain remains external until an explicit authorized opt-in completes. Unknown native/provider outcomes cannot generate a new blind attempt. |
| P5.4 Prepare and confirm DNS safely | Extend the existing account-name/customer-zone publication seams with owned MX/SPF/DKIM slots and a node SPF include writer. Preserve external senders and DMARC; present and confirm an exact single-SPF merge. Native readiness and a stable account name precede publication. Our DNS uses the typed gateway/outbox and authoritative proof; external DNS receives exact manual records and background observations. Add optional provider PTR support where implemented and a truthful manual readiness path elsewhere. No invented record discovery or duplicate SPF. |
| P5.5 Fence all native account users | Add `migration_mail_service.py` and a migration-owned node registry/playbook. Extend the existing barrier/held-restore helpers to include owner, mailbox and other account-owned Unix writers, exact credential/aging/cron state, aliases and per-domain DKIM. Keep private state on nodes/encrypted archives; store bounded identity/digest evidence under the caller's live lease. Prove source/target identity conflicts, disabled users, continuous writers, held credentials, original expiry, target-only recovery and source compensation. |
| P5.6 Activate and forward once | Activate a fully staged target only after ownership commit, apply current billing/domain policy, then enable strict source Dovecot credential forwarding and verified Postfix relay. Completed activation replay never reapplies old credentials/crons. Prove password changes, original disabled users, STARTTLS/implicit-TLS distinctions, unknown/alias/plus/catchall recipients and mailbox/alias changes during retained forwarding. Source local delivery never resumes after commit. |
| P5.7 Retain and clean up mail forwarding | Extend existing bridge cleanup/drain logic with queue/session/route/certificate gates and UUID/refcount ownership. Mail backlog holds source deletion; protective fences survive interruption/reboot. Remove only this migration's rules and restore normal node rate control after the last pair. Prove queued target outage, mixed recipients, source loss, expiry, multiple bridges and repeated teardown. Do not lift mail migration admission until this and P5.5/P5.6 are native GREEN. |
| P5.8 Expose owner/staff mail settings | Add tenant-scoped signed Platform service APIs and Portal mail-setting views/forms/client/templates. Owner consent is explicit; technical management follows existing role boundaries. Show native verified login spelling, account hostname, ports 993/995/465, public DNS records, status and actionable readiness failures. Staff pages show bounded observations and guarded retry. No business models or DNS transports enter Portal; no account previews are enabled. |
| P5.9 Deliverability and final verification | Add bounded background per-node PTR/SPF/blocklist observations; describe their limits without promising inbox placement. Run full Platform/Portal/integration suites, PostgreSQL races, native contracts, setup/rollback/restore/cleanup proofs, lint/types/templates/schema checks. Update the ADR execution ledger and operations documentation around final behavior. Open the separate draft stack PR only with concrete evidence and explicit remaining limitations. |

### Application and authorization boundaries

Platform owns configuration, resource identity, consent and provider/native outcomes. Portal only sends signed customer/user intent and renders bounded public receipts. Reads require an active membership; opt-in requires the owner decision, and delegated technical actions must use the existing hosting/DNS role rules. Missing HTTP identity never becomes an internal system caller.

Mail jobs serialize account changes with existing migration/backup/restore/delete ownership and take the existing account-name publication fence before any managed mail DNS write. A target address or service owner change invalidates old readiness. An operator's unknown outcome stays parked; a retry is not permission to adopt an existing unowned resource. Suspension policy must keep working on a fully activated committed target even when DNS convergence or cleanup is awaiting review.

Node capability is an observation tied to the actual node identity, supported software/configuration, TLS and SMTP reachability. A package installation or open TCP port alone does not establish hosted-mail readiness. The Debian 12/Dovecot 2.3 lab profile does not prove a different distribution/version; fail unsupported profiles explicitly rather than applying guessed syntax.

### Required end-to-end acceptance

1. A standard node gains mail capability without enabling an existing or new external-mail domain.
2. An owner requests enrollment, reviews exact external DNS/SPF changes, and reaches hosted mode only after native identity/TLS and DNS readiness agree. A failed or uncertain attempt preserves evidence and external routing.
3. A hosted account with active and disabled child users moves under continuous IMAP/SMTP/local writers; one mailbox copy remains authoritative. Precommit rollback returns exact source state.
4. After ownership commit, old DNS clients authenticate at the target, queued messages retain envelope identity, and password/mailbox/alias changes remain effective through the bridge.
5. Billing suspension, domain expiry and later release apply the current effective-enabled policy during normal operation, a retained bridge and operator review, without replaying old user state.
6. A source-fenced full/differential recovery preserves per-user identities, DKIM, current quotas and original access policy, or stays held when the archive cannot prove them.
7. Queue/session/certificate/cache evidence gates source removal and drain finalization. Repeated cleanup and worker death preserve the same single authoritative copy.

Operator-facing limitations and any supported-feature refusals must be explicit in receipts/docs. Unit GREEN, a successful raw command, or a single delivered message cannot substitute for these lifecycle proofs.

## Superseded experiments

Initial10025 XCLIENT/shared mTLS/CRL design rejected. Old10025 connection-refusal check is NOT tenant-isolation proof; actual live1465 unprivileged test supersedes it. Initial CA-only failures were listener-start races and later Fail2ban bans, not a need for CRL infrastructure. Final no-client-cert/no-CRL verified profile passed. Setup-selector mismatch, identity-map unknown acceptance and aggregate bans were reproduced/diagnosed/corrected before claiming their respective gates.
