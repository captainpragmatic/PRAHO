# Node deploy → customer-ready acceptance drill (#347)

The credential-seam code (PR #348) is unit-tested with mocks and the playbook
passes `ansible-playbook --syntax-check`, but it has **never run against a real
Virtualmin node**. This drill is the acceptance gate that turns "code that should
work" into "provably works". Run it against ONE real Hetzner node before claiming
auto-deploy is customer-ready.

## Prerequisites
- A Hetzner Cloud API token (project-scoped) configured in PRAHO (provider token / vault).
- PRAHO platform running with node-deployment settings configured.
- `infrastructure.node_admin_allowed_cidrs` set to Platform's egress addresses plus your admin network
  (ADR-0060). `virtualmin.yml` and `virtualmin_harden.yml` refuse to run while it is empty, and the harden
  play refuses when its own SSH connection comes from outside it.
- Configure the Cloudflare API token, zone ID and deployment DNS zone. The deployment pipeline now creates and owns its public A/AAAA records. Run `panel_cert_preflight --provider-id <id>` before the paid drill.
- Follow the canonical [panel-certificate drill guide](../../../../../docs/deployment/DEPLOYMENT.md#panel-certificate-preflight-and-activation-gate-436-drill-gated) for #436. This credential-seam checklist does not prove certificate issuance or authorize enabling fatal issuance. The current installer can make a production ACME request; prepare and verify the isolated staging path first.

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
     UFW rules (22/tcp and 10000/tcp `ALLOW IN` only from the allowlist) and that a host outside the allowlist
     cannot reach port 10000. On a real node, read the same four things by hand:
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
