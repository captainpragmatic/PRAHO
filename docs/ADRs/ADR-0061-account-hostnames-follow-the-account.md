# ADR-0061: Account Hostnames, Customer DNS and Mail Follow the Account Across Nodes

- Status: Proposed
- Date: 2026-10-14
- Authors: PRAHO maintainers
- Related: ADR-0044 (placement policy), ADR-0051 (enabled-state ownership), ADR-0058 to ADR-0060 (#689/#498), ADR-0059 (differential backups), ADR-0062 (deployment branding)

## Context

PRAHO moves hosting accounts between Virtualmin nodes: planned migration, node drain, and recovery when a node is lost. Nodes deliberately sit with different providers (Hetzner, others, AWS), so no IP address can follow an account from one node to another. A floating IP stays inside one provider and region, and a shared edge proxy would put every customer's traffic, latency and uptime behind one layer.

Today PRAHO does nothing about DNS when an account moves:
- Migration and drain change `VirtualminAccount.server` only. The staff forms say "PRAHO does not change routing or DNS", and drain asks the operator to confirm DNS by hand.
- PRAHO manages no customer zones. The domain model stores nameservers only, and nothing records whether a customer uses our DNS.
- `VirtualminServer` has no IP field. The Portal shows "Server IP" from a placeholder server picked at order time, which is wrong from day one.
- Nodes run neither BIND nor mail (minimal install).

Customers may keep DNS anywhere: our nameservers, Cloudflare, their registrar. A bare domain (`example.com`) can never be a CNAME (RFC 1034 §3.6.2; RFC 2181 §10.1). The apex holds SOA and NS records, and a CNAME cannot sit beside other records, whatever it points at.

## Decision

### 1. Every hosting account has a provider-controlled hostname

- **Name.** `<id>.<zone>`, where `<id>` is a short opaque random label (for example `h7k3p2q`), unique and never reused. It is stable through renames, reveals nothing about the customer, and cannot be enumerated.
- **Zone.** A setting (`dns.account_hostname_zone`), never hard-coded. It must be a separate registered domain from the brand and Portal domains. Customer sites under the brand's registrable domain could set cookies for it and attack Portal sessions. The zone is submitted to the Public Suffix List, as `github.io` and `netlify.app` are.
- **Records.** PRAHO owns them: `A`, and `AAAA` when the node has IPv6, pointing at the node that currently hosts the account. They are never a CNAME, because MX and SRV targets must not be aliases (RFC 2181 §10.3) and mail uses this name. The records live in our Cloudflare zone through the existing DNS gateway, with an owner tag `praho:account:<id>` and a 300 s TTL.
- **Lifecycle.** Created when the account is provisioned; moved by migration, drain and recovery (section 4); deleted at termination. A reconcile sweep compares the records with `VirtualminAccount.server` and repairs drift.

### 2. How a customer's domain reaches the account

PRAHO never tells a customer to point at a raw node IP. Every supported path follows the account name.

1. **Our nameservers (preferred).** The customer's zone lives in our Cloudflare account through the API (section 5). PRAHO writes the apex and `www` (and later MX) as copies of the account name's addresses, and updates them on every move.
2. **External DNS with ALIAS or CNAME flattening.** Cloudflare, DNSimple and similar providers can point the apex at the account name; `www` is a CNAME to it.
3. **External DNS without ALIAS.** `www` is a CNAME to the account name, and the apex is an HTTP redirect to `www` at the registrar ("URL forwarding"). The Portal warns that many registrar forwarders have no certificate, so `https://example.com` may fail before the redirect; `http://` and `www` work.

A raw node IP is not offered, so no customer ever holds an address that a move makes stale.

### 3. Certificates

- **Account names and previews.** Each account name is a Virtualmin sub-server of the customer's domain, with its web root linked to the customer's, so it has its own vhost and its own certificate (lab contract: `docs/domain/virtualmin-account-subserver-contract.md`). The certificate is per name, issued by DNS-01 through our Cloudflare zone on Platform. A wildcard is not used: a sub-server's key travels with any archive that carries it, and one key for every customer's name must not. Per-name issuance is bounded by Let's Encrypt's weekly limit per registered domain, which the issuer budgets.
- **The customer's own domain.** Virtualmin requests it by HTTP-01 once the domain points at the account. No certificate is issued before the switch, so HTTPS starts a few minutes after cutover. That trade-off was accepted.
- **Moves.** Certificates travel with the account in the backup and are installed on the new node, not reissued (the Let's Encrypt duplicate-certificate limit is 5 per week).
- **CAA.** The DNS check (section 6) flags a customer CAA record that excludes Let's Encrypt.

### 4. Moving an account between nodes

Migration gains a **cutover** phase after restore and verification on the new node:
1. **Before a planned move,** lower the account records' TTL to 60 s at least one old TTL ahead.
2. **Repoint** the account name, and the apex and `www` copies for customers on our nameservers, to node B. Verify through the zone's authoritative servers.
3. **Bridge the tail.** Some resolvers hold old answers past their TTL. Node A keeps serving the domain as a reverse proxy to B for web traffic, and relays the domain's mail to B, until the bridge window ends. There are never two live copies accepting writes.
4. **Then** the retained copy on A is removed (the existing migration step), and the TTL returns to 300 s.

- Drain uses the same cutover, so its manual "routing and DNS confirmed" box goes away for accounts on these paths.
- **Recovery after a lost node:** restore the account from its latest backup onto a new node, then run the cutover. Data loss is bounded by the backup schedule.

### 5. Our nameservers: Cloudflare zones through the API

- A customer zone is created in our Cloudflare account. Before the customer switches nameservers, PRAHO imports their existing records (read from their current authoritative servers) so mail and verification TXT records survive the switch.
- The Portal gets a record editor for A, AAAA, CNAME, MX, TXT, SRV and CAA. Records PRAHO manages (apex, `www`, mail, DKIM) are labelled and locked.
- The DNS provider sits behind an interface, so the zones can move to self-hosted servers later.

### 6. Watching customer DNS

A scheduled check per hosted domain records:
- which path (section 2) is in use;
- whether `www`, the apex and MX resolve to the account;
- stray `AAAA` records pointing elsewhere;
- CAA, and DNSSEC breakage after a nameserver switch.

The Portal shows the result with the exact records to set. The customer is notified when something that worked breaks.

### 7. Mail on the nodes

- Nodes gain Postfix and Dovecot. A domain's MX and the mail client settings point at the account name, so mail follows every move.
- **Each node sends outgoing mail from its own IP,** with a PTR record matching the node name. PRAHO keeps one SPF record, `_spf.<zone>`, listing every node's addresses, and customers include it. Moves and new nodes then never break SPF.
- DKIM keys are generated per domain and published by PRAHO in our zones, or shown as records to add elsewhere.
- **Trade-off.** Sending reputation is per node, and a new node starts cold. Dedicated mail servers (for example mailcow) with stable outbound addresses remain a later option.

## Consequences

- Moves stop needing customer action, and failover becomes "restore and repoint". PRAHO owns more DNS state, which needs reconciliation and monitoring.
- About 9% of resolvers keep answers past their TTL. The bridge on the old node covers that tail, which costs an extra window of time before the retained copy can be removed.
- Customers whose DNS host offers no ALIAS get a redirect-only apex, with the https caveat.
- Mail adds deliverability work: PTR records, blocklists and abuse handling per node.
- Found while mapping the code: node panels request their Let's Encrypt certificate for the short inventory hostname instead of the node's FQDN, so the panel certificate likely never issues. This is fixed in the first phase.

## Alternatives considered

- **Floating or reserved IPs.** Rejected: they stay within one provider and region.
- **A shared edge proxy or anycast front.** Rejected: one layer for everyone's traffic, latency and uptime; it cannot carry mail; and running anycast needs BGP.
- **Cloudflare for SaaS custom hostnames.** Rejected: apex proxying is an Enterprise add-on, it is HTTP only, and every request depends on a third party.
- **A raw node IP for the apex as a last resort.** Rejected: every move would strand it.
- **Issuing certificates before cutover** through a delegated `_acme-challenge` CNAME. Not needed for now.
