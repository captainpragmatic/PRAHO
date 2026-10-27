# ADR-0061: Account Hostnames, Customer DNS and Mail Follow the Account Across Nodes

- Status: Proposed
- Date: 2026-10-14
- Authors: PRAHO maintainers
- Related: ADR-0044 (placement policy), ADR-0051 (enabled-state ownership), ADR-0058 to ADR-0060 (#689/#498), ADR-0059 (differential backups), ADR-0062 (deployment branding)

## Implementation clarifications (2026-10-27)

This ADR remains Proposed. Implementation is being reviewed in separate phase branches; that does not mean the feature is deployed or every phase is complete. The [execution plan](../architecture/account-hostnames-dns-mail-plan.md) records phase status and verification; [Phase 3](../architecture/account-hostnames-phase3-execution.md), [Phase 4](../architecture/account-hostnames-phase4-execution.md) and [Phase 5](../architecture/account-hostnames-phase5-execution.md) have separate implementation records.

The agreed first release imports a complete customer-uploaded zone file, keeps account-name previews disabled, and makes native mail available on eligible nodes without enabling it for existing or new domains until their owner opts in. Temporary forwarding stays on the account's source node using Apache for web and native Postfix/Dovecot for mail; HAProxy is not a prerequisite. The detailed cutover below distinguishes the ownership commit from later bridge retention and cleanup.

## Context at proposal (2026-10-14)

PRAHO moves hosting accounts between Virtualmin nodes: planned migration, node drain, and recovery when a node is lost. Nodes deliberately sit with different providers (Hetzner, others, AWS), so no IP address can follow an account from one node to another. A floating IP stays inside one provider and region, and a shared edge proxy would put every customer's traffic, latency and uptime behind one layer.

Today PRAHO does nothing about DNS when an account moves:
- Migration and drain change `VirtualminAccount.server` only. The staff forms say "PRAHO does not change routing or DNS", and drain asks the operator to confirm DNS by hand.
- PRAHO manages no customer zones. The domain model stores nameservers only, and nothing records whether a customer uses our DNS.
- `VirtualminServer` has no IP field. The Portal shows "Server IP" from a placeholder server picked at order time, which is wrong from day one.
- Nodes run neither BIND nor mail (minimal install).

Customers may keep DNS anywhere: our nameservers, Cloudflare, their registrar. A bare domain (`example.com`) can never be a CNAME (RFC 1034 §3.6.2; RFC 2181 §10.1). The apex holds SOA and NS records, and a CNAME cannot sit beside other records, whatever it points at.

## Decision

### 1. Every hosting account has a provider-controlled hostname

- **Name.** `<id>.<zone>`, where `<id>` is a short opaque random label (for example `h7k3p2q`), unique and never reused. It is stable through renames and does not encode sequential customer identifiers. The public hostname is not an authentication secret.
- **Zone.** A setting (`dns.account_hostname_zone`), never hard-coded. It must be a separate registered domain from the brand and Portal domains. Customer sites under the brand's registrable domain could set cookies for it and attack Portal sessions. The zone is submitted to the Public Suffix List, as `github.io` and `netlify.app` are. Submission alone protects nothing: until the entry is accepted and shipped in current browsers, a customer site on `<id>.<zone>` could set a cookie for the whole zone and have it sent to other customers' account names. So PRAHO serves no customer content on account names (previews stay off) until that inclusion is confirmed.
- **Records.** PRAHO owns them: `A`, and `AAAA` when the node has IPv6, pointing at the node that currently hosts the account. They are never a CNAME, because MX and SRV targets must not be aliases (RFC 2181 §10.3) and mail uses this name. The records live in our Cloudflare zone through the existing DNS gateway, with an owner tag `praho:account:<id>`. The ordinary TTL is configurable (`dns.account_record_ttl_seconds`, default 300 s); a move records and later restores each record's actual original TTL.
- **Lifecycle.** Created when the account is provisioned; moved by migration, drain and recovery (section 4). Termination withdraws DNS records and permanently retires the name; its label remains reserved. A reconcile sweep compares the records with `VirtualminAccount.server` and repairs drift.

### 2. How a customer's domain reaches the account

External DNS instructions use the account name. Managed customer zones necessarily contain the node's actual A/AAAA values; PRAHO owns those copies and updates them on a move.

1. **Our nameservers (preferred).** The customer's zone lives in our Cloudflare account through the API (section 5). PRAHO writes the apex and `www` (and later MX) as copies of the account name's addresses, and updates them on every move.
2. **External DNS with ALIAS or CNAME flattening.** Cloudflare, DNSimple and similar providers can point the apex at the account name; `www` is a CNAME to it.
3. **External DNS without ALIAS.** `www` is a CNAME to the account name, and the apex is an HTTP redirect to `www` at the registrar ("URL forwarding"). The Portal warns that many registrar forwarders have no certificate, so `https://example.com` may fail before the redirect; `http://` and `www` work.

Customers following the supported external DNS instructions do not need to maintain a node IP manually.

### 3. Certificates

- **Account names and previews.** Each account name is a Virtualmin sub-server of the customer's domain, with its web root linked to the customer's, so it has its own vhost and its own certificate (lab contract: `docs/domain/virtualmin-account-subserver-contract.md`). The certificate is per name, issued by DNS-01 through our Cloudflare zone on Platform. A wildcard is not used: a sub-server's key travels with any archive that carries it, and one key for every customer's name must not. Per-name issuance is bounded by Let's Encrypt's weekly limit per registered domain, which the issuer budgets.
- **Initial setup of the customer's own domain.** Virtualmin requests its certificate by HTTP-01 once the domain points at the account. This first-issuance path can delay HTTPS until validation succeeds; it is separate from a move carrying an existing certificate.
- **Moves.** Reuse the existing certificate and complete served chain instead of issuing a replacement. The customer domain's certificate travels with the account in the backup. The account name's sub-server is kept out of that backup, so its certificate and key are fetched from their vault references and installed on the new node.
- **CAA.** The DNS check (section 6) flags a customer CAA record that excludes Let's Encrypt.

### 4. Moving an account between nodes

Migration gains a **cutover** contract with one point of no return:
1. **Before a planned move,** record every owned-name and managed customer-web record's actual original TTL, lower it to the configured cutover TTL (default 60 s), confirm provider readback, and wait the maximum original TTL. Routine sync preserves the lowered values.
2. **Freeze and restore held.** Fence and verify source write paths before backup. Restore the target behind maintenance with credentials, cron and writes still held; verify archive lineage, account identity, certificates and current quotas. Prepare and verify the encrypted bridge prerequisites before committing ownership.
3. **Commit ownership once.** Move `VirtualminAccount.server` and the account name's `target_server` together under the live operation lease and publication lock. Before this commit, compensation releases exactly the source state recorded by this operation. After it, recovery proceeds toward the committed target and never reopens the source for writes.
4. **Activate, bridge and repoint.** Release the verified target through its activation protocol, verify source-to-target forwarding, and publish the owned name and managed apex/`www` records toward B. Confirm authoritative agreement against the still-current routing generation. Web forwarding uses Apache and verified TLS between nodes. Mail-enabled moves remain refused until the native all-mailbox freeze, held restore, proxy and queue contracts are implemented and proven.
5. **Finish and retain.** Complete the account move after activation, bridge verification and DNS convergence, allowing normal account reconciliation and backups to resume. A separate durable cleanup operation retains the source bridge for its DNS/cache window and certificate lifetime, removes the retained source only after its gates pass, and confirms each original TTL is restored. Failed cleanup retains routing and blocks a subsequent move.

- Drain uses the same cutover, so its manual "routing and DNS confirmed" box goes away for accounts on these paths.
- **Recovery after a lost node:** require explicit source fencing, select a verified full backup or full/differential lineage, restore held, and commit target ownership before activation and authoritative repointing. No source bridge is assumed when the source is unavailable. Missing or ambiguous restore evidence requires review; native archives cannot be assumed to contain every original Unix credential policy. Data loss is bounded by the usable backup schedule and contents.

### 5. Our nameservers: Cloudflare zones through the API

- A customer zone is created in our Cloudflare account after an owner or technical contact confirms a complete zone-file inventory and the exact proposed changes. DNS lookups cross-check that inventory; they cannot discover arbitrary verification names, DKIM selectors or service records and therefore are not a complete import. Unsupported records refuse the whole import rather than disappearing.
- Before offering nameserver instructions, publish and read back the entire confirmed inventory, check the assigned authoritative servers and parent delegation/DS handover, and refresh stale evidence. Registrar changes use the existing durable registrar-operation service. Unknown provider creation or registrar submission outcomes remain fenced for reconciliation.
- The Portal gets a record editor for A, AAAA, CNAME, MX, TXT, SRV and CAA. Records PRAHO manages (apex, `www`, mail, DKIM) are labelled and locked.
- The zone belongs to the customer independently of its hosting service. Hosting termination withdraws managed web records only; unrelated DNS remains. Whole-zone deletion is a separate request requiring a current export and verified move-away/cache-age proof. Provider ownership is recorded per zone and record.
- The DNS provider sits behind an interface, so the zones can move to self-hosted servers later.

### 6. Watching customer DNS

A scheduled check per hosted domain records:
- which path (section 2) is in use;
- whether `www`, the apex and MX resolve to the account;
- stray `AAAA` records pointing elsewhere;
- CAA, and DNSSEC breakage after a nameserver switch.

The Portal shows cached results and the exact records to set. Requests do not run DNS probes or provider calls inline; leased background jobs store bounded observations. A verified healthy-to-broken change creates one notification per incident. Unknown observations and planned maintenance do not produce outage alerts. The DNSSEC observation compares DS/DNSKEY consistency; it does not claim cryptographic signature validation.

### 7. Mail on the nodes

- Eligible existing and new nodes gain Postfix and Dovecot through Virtualmin's selective setup. Mail stays default-off per domain until an explicit owner opt-in; external MX/SPF/DKIM and existing mail routing remain external until that workflow succeeds. Advertised client ports are implicit TLS 993, 995 and 465. A hosted domain's MX and client settings point at the account name, so mail follows its moves.
- **Each node sends outgoing mail from its own IP,** with a PTR record matching the node name. PRAHO keeps one SPF record, `_spf.<zone>`, listing every node's addresses, and customers include it. Moves and new nodes then never break SPF.
- DKIM keys are generated per domain and published by PRAHO in our zones, or shown as records to add elsewhere.
- Native bridge clients authenticate at the destination and use its single writable mailbox copy. Source TLS termination uses independently retained certificates; onward TLS verifies the fixed target's identity. Source SMTP preserves original envelope recipients, queues rather than falling back to local delivery, and verifies target TLS. Mailbox-specific throttling and source client-IP abuse controls remain enforced. Mail queues and live forwarding sessions hold source deletion and node retirement until safely drained.
- **Trade-off.** Sending reputation is per node, and a new node starts cold. Dedicated mail servers (for example mailcow) with stable outbound addresses remain a later option.

## Consequences

- Moves stop needing customer action, and failover becomes "restore and repoint". PRAHO owns more DNS state, which needs reconciliation and monitoring.
- Some caches and long-lived connections outlast DNS TTLs. The configured source bridge window and cleanup evidence determine when the retained copy can be removed.
- Customers whose DNS host offers no ALIAS get a redirect-only apex, with the https caveat.
- Mail adds deliverability work: PTR records, blocklists and abuse handling per node.
- Found while mapping the code: node panels request their Let's Encrypt certificate for the short inventory hostname instead of the node's FQDN, so the panel certificate likely never issues. This is fixed in the first phase.

## Alternatives considered

- **Floating or reserved IPs.** Rejected: they stay within one provider and region.
- **A shared edge proxy or anycast front.** Rejected: one layer for everyone's traffic, latency and uptime; it cannot carry mail; and running anycast needs BGP.
- **Cloudflare for SaaS custom hostnames.** Rejected: apex proxying is an Enterprise add-on, it is HTTP only, and every request depends on a third party.
- **A raw node IP for the apex as a last resort.** Rejected: every move would strand it.
- **Issuing certificates before cutover** through a delegated `_acme-challenge` CNAME. Not needed for now.
