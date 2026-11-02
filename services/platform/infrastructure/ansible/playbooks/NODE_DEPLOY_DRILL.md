# Node deploy → customer-ready acceptance drill (#347)

The credential seam and node policy are qualified against native Virtualmin in
disposable Docker nodes, including denied-peer checks during installation and
actual API/SSH authentication. This drill adds the isolated Hetzner, public DNS
and panel-certificate evidence that local qualification cannot supply. Complete
it before claiming production auto-deploy is customer-ready.

## Prerequisites

- Follow [customer maintenance windows](../../../../../docs/deployment/NODE_MAINTENANCE.md)
  before customer-visible work. Its isolated Platform/Portal HTTP acceptance uses local mail and a scoped
  worker; it does not call providers, qualify this paid node-deploy drill, or turn reboot acknowledgment
  into recovery proof. Imported/manual outcomes require explicit operator attestation.
- For #782, install `virtualmin_usage.yml` on the isolated node, verify the root timer
  and HTTP/HTTPS logging, grow files and a database separately and run the hourly
  usage publisher. Check both account and Service byte projections plus the portal
  breakdown/source time. Generate traffic before/after an injected month boundary;
  incomplete first-month coverage must stay partial. The full lab's `test_sync.py`
  covers real collection without relying on filesystem quota support.
  `provisioning.usage_sync_enabled` is on by default; turn it off in Advanced settings
  to stop polling while this acceptance is pending.
- A Hetzner Cloud API token (project-scoped) configured in PRAHO (provider token / vault).
- PRAHO platform running with node-deployment settings configured.
- `infrastructure.node_admin_allowed_cidrs` set to Platform's egress addresses plus your admin network
  (ADR-0060). `virtualmin.yml` and `virtualmin_harden.yml` refuse to run while it is empty, and the harden
  play refuses when its own SSH connection comes from outside it.
- Enroll the operator public-key bundle and retain the provider console recovery path. The final SSH
  port is 9876, with key authentication only. The `praho-tunnel` account permits only a local forward
  to `127.0.0.1:10000`; root Webmin access uses that tunnel. The durable API credential must authenticate
  before root access is restricted. Inspect the detailed changes before hardening an imported node.
- Use the checksum-pinned installer and matching local `slib.sh` in `virtualmin.yml`. The early
  `virtualmin_firewall.yml` play must precede the installer; its minimal profile excludes Nftables,
  Firewalld and Fail2ban integrations that could replace the reviewed policy.
- Configure the Cloudflare API token, zone ID and deployment DNS zone. The deployment pipeline now creates and owns its public A/AAAA records. Run `panel_cert_preflight --provider-id <id>` before the paid drill.
- Follow the canonical [panel-certificate drill guide](../../../../../docs/deployment/DEPLOYMENT.md#panel-certificate-preflight-and-activation-gate-436-drill-gated) for #436. This credential-seam checklist does not prove certificate issuance or authorize enabling fatal issuance. The current installer can make a production ACME request; prepare and verify the isolated staging path first.

## Existing nodes and imported websites

Use the server's security review page before changing an existing node. Inspection
is read-only. A source-only acknowledgment retains its mail, DNS and access policy;
it does not grant destination capability. Conversion requires the reviewed admin
CIDRs and operator keys, explicit impact acceptance and a fresh native inspection.
Resolve any interrupted execution before another lifecycle operation.

For a website on an acknowledged source, use **Move website components** on its
account page. Select independent application paths and MySQL schemas and inspect
the destination. The preview explains which writers stop, which services remain,
the website address changes and the independent source backup responsibility.
Shared SQL principals, mail/administration aliases, retained TLS files inside
selected roots and unclassified writers require preparation and another preview.
Source Apache programs and logrotate hooks are excluded; the target uses the
qualified safe rotation policy. Root SSH identity and exact host trust must already
be enrolled; inspection does not bootstrap access or harden the source.

Acceptance starts asynchronous work. The restored target remains held until both
native copies refuse rollback and the database commits ownership. After that,
recovery keeps the target and moves forward. The source bridge remains until
authoritative routing and old cache lifetimes are proven. External/proxy DNS may
need operator changes; MX, mail authorization and unrelated records stay at the
source. Current billing policy can suspend the committed target during a DNS wait
without replaying its original credentials or jobs.

Retiring the selected source website does not release its mail/DNS/Unix obligation.
The migration status page retains that responsibility. Release requires live native
domain and owner-domain absence plus a named independent backup/service handoff;
moving the account or confirming a drain cannot substitute for that proof.

## Provider resources when destroying a node

Review the destroy page's exact resource inventory and choose whether cloud-provider
backups and snapshots should remain. Shared, foreign and unproven resources are
preserved with an explanation. Keeping an ephemeral provider backup requires a
verified durable snapshot before VM deletion; a provider without conversion support
needs an explicit verified mapping. Cleanup verifies each resource's absence and
resumes from its immutable decision after an interrupted response. This decision
does not configure or delete PRAHO backups.

## What it proves
Given a Hetzner key, `deploy_node` produces an **active, credentialed** `VirtualminServer` with **zero manual steps**, onto which a customer domain can be provisioned.

## Steps
1. Trigger a deployment (`queue_deploy_node` / staff UI / management command). Record the deployment id.
2. Watch the FSM (per-stage `NodeDeploymentLog`): pending → provisioning_node → configuring_dns → installing_panel → configuring_backups → validating → registering → completed.
3. **Validate the API user.** `virtualmin.yml` creates it with `/usr/local/sbin/praho-webmin-api-user`
   (`playbooks/files/praho-webmin-api-user.pl`): a Webmin user whose only module is virtual-server, with
   Virtualmin master rights, because remote.cgi runs most programs only for the master administrator.
   (`virtualmin create-admin` makes per-domain extra administrators and cannot serve PRAHO.) SSH to the node:
   - The lab runs these node-side checks on every nightly run: `make test-virtualmin-node-deploy` deploys
     `virtualmin.yml` and `virtualmin_harden.yml` onto the bare `praho-debian-node` image, and reads the API
     user's ACL (`praho-api: virtual-server`), its per-user IP lock (`allow <your allowlist>`, ADR-0060), the
     UFW rules (9876/tcp and 10000/tcp `ALLOW IN` only from the allowlist) and that a host outside the allowlist
     cannot reach port 10000 throughout installation. On a real node, read the same four things by hand:
     `grep '^praho-api:' /etc/webmin/webmin.acl`, `grep '^praho-api:' /etc/webmin/miniserv.users | cut -d: -f5`,
     `ufw status`, and port 10000 from outside.
   - Let PRAHO's own diagnostic prove auth — do NOT hand-auth with `curl -k`. Step 4 below
     (`status=active`) is the real auth proof: `verify_and_activate` authenticates over the pinned-cert TLS
     with the vault credential, the exact production path.
   - The lab already proves the helper: `make test-virtualmin-lab` (check 5) on Virtualmin 8.3.0, and
     `make test-virtualmin-node-deploy` from scratch on `praho-debian-node` (deploy/virtualmin-lab/README.md).
4. **Confirm PRAHO activated the node.** The `VirtualminServer` row should be `status=active`
   (i.e. `verify_and_activate` succeeded). If still `disabled`, the deployment log carries the
   "Node registered but left disabled: …" reason — that reason IS the handshake failure from step 3.
   New nodes also require a `verified_web` review bound to their current credential, transport and policy.
   Authentication alone cannot activate one. Inspect both address families' effective input policy,
   canonical SSH/startup policy, Webmin principals and live listeners. Only 80/443 are public; 2222 is
   closed, SMTP/MySQL bind to loopback and UDP Webmin discovery is closed. Loopback 11000 is Virtualmin's
   domain lookup service. Repeat convergence and verify no changes, then exercise rollback and reboot.
5. **Provision a test customer — this is the ACL CAPABILITY gate, not just auth.** `info`/`list-domains`
   prove the credential authenticates; they do NOT prove `--can-create`/`--can-edit` actually grant
   domain provisioning. Creating a real domain does:
   - `create_virtualmin_account` should succeed (a `VirtualminAccount`, status active) — this exercises
     `create-domain`, proving the ACL user has the create capability the flags are meant to grant.
   - The customer domain should resolve publicly and serve; provision its DNS separately from the node hostname records.
   Record the tested playbook SHA and installed versions. Repeat the capability drill when that contract changes.
6. Record RTO (deploy start → active) and note any manual step you had to take — the goal is **zero**.

## Debugging aids
- Hidden API-user error → do NOT flip `no_log: false` (it logs the plaintext password). Re-run the helper
  on the node with a dummy login and password on stdin to read its error.
- Credential transport: the API password reaches the ansible CONTROLLER via a `0600` temp vars file
  (`-e @file`, never the `ansible-playbook` argv), cleaned up after the run. On the TARGET node the helper
  reads it from stdin, so it never appears in the node's process list either.
- `verify_and_activate` calls `gateway.test_connection()`; check its `{"healthy": …}` response.

## Definition of done for #347
A deploy from a Hetzner key yields an `active` + credentialed node with no manual step, and a real customer domain provisions and serves on it. Until this drill passes, the code is "structurally complete, unproven."
