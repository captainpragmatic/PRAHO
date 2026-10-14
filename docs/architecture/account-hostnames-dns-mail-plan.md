# Plan: account hostnames, customer DNS and mail (ADR-0061)

Five phases, each its own PR series after #693. Every phase ships behind tests that fail without it, and the Virtualmin lab proves the node-side steps.

## Phase 1: account hostnames and previews

- **Data.**
  - `VirtualminServer` gains `ipv4_address` and `ipv6_address`, filled from `NodeDeployment` and editable for hand-registered servers.
  - `VirtualminAccount` gains `hostname_label`: opaque, unique, generated at provisioning, never reused.
  - New settings: `dns.account_hostname_zone` and the Cloudflare zone id for it, validated at the settings write chokepoint.
- **Gateway.** Account-owned A/AAAA records in the existing Cloudflare gateway, with owner tag `praho:account:<label>` and a 300 s TTL. Create, update and delete calls; a reconcile sweep compares the records with `VirtualminAccount.server`.
- **Lifecycle hooks.** Create the record after provisioning succeeds, delete it at termination, and audit both.
- **The node answers to the name.** Add the account name as a web server alias of the domain (Virtualmin `modify-web --add-alias`, or the documented equivalent; to be proven in the lab).
- **Wildcard certificate.**
  - `*.<zone>` is issued by DNS-01, using a Cloudflare token scoped to that zone only.
  - Issuance runs on Platform as a scheduled task, and a playbook distributes the certificate to every node.
  - Renewal works the same way.
- **Portal.** Show the account name and the DNS instructions for the customer's path (ADR-0061 section 2) instead of the placeholder "Server IP". Send the activation email that exists but is never sent.
- **Fix.** Node panels request their Let's Encrypt certificate for the FQDN, not the short inventory hostname.
- **Preview of CMS sites.** WordPress redirects to its stored site URL. Decide between a PRAHO must-use plugin, which overrides home and siteurl when the request's Host is the account name, and documenting the limitation.

## Phase 2: cutover on move, drain and recovery

- A `cutover` phase in the migration service between verification and the existing repoint, with an entry in `RESUME_POLICY`. Steps:
  1. TTL lowered ahead of planned moves;
  2. records repointed;
  3. the change verified with `authoritative_addresses`;
  4. a bridge on the old node: a reverse proxy for the domain's web traffic and a mail relay to the new node, held for the bridge window;
  5. TTL restored.
- Drain finalisation no longer needs the manual "routing and DNS confirmed" box for accounts on supported paths.
- Recovery: restore from the latest backup onto a replacement node, then cutover. A real management command replaces the dry-run-only entry point.
- Lab proofs: a migration A to B with the account name resolving to B, the old node proxying during the bridge, and no writes accepted on A after cutover.

## Phase 3: watching customer DNS

- `Domain` gains `dns_path` (`our_nameservers`, `external_alias`, `external_redirect` or `unknown`) and the last check's results.
- A scheduled check covers: `www` and the apex resolving to the account; MX pointing at the account name; stray AAAA records; CAA allowing Let's Encrypt; and DNSSEC after a nameserver switch.
- The Portal status card shows the exact records to set. Customers are notified when something that worked breaks.

## Phase 4: our nameservers on Cloudflare

- Zone creation through the API; an import of existing records read from the current authoritative servers before the switch; and an assistant that guides the nameserver change at the registrar.
- A Portal record editor (A, AAAA, CNAME, MX, TXT, SRV, CAA). Records PRAHO manages are locked and labelled. Edits go through Platform's HMAC API and are audited.
- The DNS provider sits behind an interface, so self-hosted servers stay possible later.

## Phase 5: mail on the nodes

- **Node install.** Postfix and Dovecot, with Virtualmin's mail feature enabled. The default features in the node playbook and the lab image change to match.
- **Records.** MX points at the account name. One `_spf.<zone>` record lists every node's addresses and is updated on node deploy and removal. DKIM keys are generated per domain and published, or shown to add. A PTR record is set per node through the provider API where one exists, and as a checked manual step otherwise.
- **Moves.** Mail data travels in the account backup, and the bridge relays mail during the bridge window.
- **Deliverability.** Blocklist monitoring per node IP, rate limits and abuse handling.

## Open items

- Register the hosting zone domain and submit it to the Public Suffix List.
- Confirm Cloudflare's zone-count and API rate limits for the expected number of customer zones.
- Settle the preview behaviour for WordPress in phase 1.
- Decide whether mail moves to dedicated servers (for example mailcow), once per-node sending reputation proves a problem.
