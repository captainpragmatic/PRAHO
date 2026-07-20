# Node deploy → customer-ready acceptance drill (#347)

The credential-seam code (PR #348) is unit-tested with mocks and the playbook
passes `ansible-playbook --syntax-check`, but it has **never run against a real
Virtualmin node**. This drill is the acceptance gate that turns "code that should
work" into "provably works". Run it against ONE real Hetzner node before claiming
auto-deploy is customer-ready.

## Prerequisites
- A Hetzner Cloud API token (project-scoped) configured in PRAHO (provider token / vault).
- PRAHO platform running with node-deployment settings configured.
- (For public hostname resolution + Let's Encrypt) a Cloudflare API token + zone — note GAP 3 (imperative-pipeline DNS) is NOT implemented yet, so the node hostname will not auto-resolve; the LE cert step may skip. Not required to prove the credential seam.

## What it proves
Given a Hetzner key, `deploy_node` produces an **active, credentialed** `VirtualminServer` with **zero manual steps**, onto which a customer domain can be provisioned.

## Steps
1. Trigger a deployment (`queue_deploy_node` / staff UI / management command). Record the deployment id.
2. Watch the FSM (per-stage `NodeDeploymentLog`): pending → provisioning_node → configuring_dns → installing_panel → configuring_backups → validating → registering → completed.
3. **CRITICAL — validate the `create-admin` flags (the biggest unknown).** SSH to the node:
   - `virtualmin list-admins` → confirm the `praho-api` admin exists.
   - Test API auth directly:
     `curl -k -u 'praho-api:<password>' 'https://<node-ip>:10000/virtual-server/remote.cgi?program=list-domains'`
     → expect a valid response, **not** HTTP 401.
   - If auth fails, the capability flags in `virtualmin.yml`'s create-admin task are wrong:
     temporarily set `no_log: false` on that task, re-run the playbook, read the real error,
     run `virtualmin create-admin --help` on the node for the exact flag names, and correct them.
4. **Confirm PRAHO activated the node.** The `VirtualminServer` row should be `status=active`
   (i.e. `verify_and_activate` succeeded). If still `disabled`, the deployment log carries the
   "Node registered but left disabled: …" reason — that reason IS the handshake failure from step 3.
5. **Provision a test customer.** Create a service that provisions a domain onto the node:
   - `create_virtualmin_account` should succeed (a `VirtualminAccount`, status active).
   - The domain should resolve (GAP 3 / DNS) and serve. Without GAP 3, resolve DNS manually to test.
6. Record RTO (deploy start → active) and note any manual step you had to take — the goal is **zero**.

## Debugging aids
- Hidden create-admin error → flip `no_log: true` to `false` on that task for one run.
- The API password is passed via a `0600` temp vars file under the PRAHO host's tempdir (never argv), cleaned up after the run — inspect it mid-run only if debugging.
- `verify_and_activate` calls `gateway.test_connection()`; check its `{"healthy": …}` response.

## Definition of done for #347
A deploy from a Hetzner key yields an `active` + credentialed node with no manual step, and a real customer domain provisions and serves on it. Until this drill passes, the code is "structurally complete, unproven."
