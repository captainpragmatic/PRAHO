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
   - **Let PRAHO's own diagnostic prove auth — do NOT hand-auth with `curl -k`.** `-k` disables the
     certificate validation the platform enforces (pinned-cert TLS), so a `curl -k` success would
     "prove" a path PRAHO never uses. Step 4 below (`status=active`) IS the real auth proof:
     `verify_and_activate` authenticates over the pinned-cert TLS with the vault credential — the exact
     production path. If you must probe the API by hand, do it securely: read the password from the
     vault into a shell variable (never type it on the command line / into shell history), validate the
     node cert (`--cacert` / pinned fingerprint, not `-k`), and pass credentials via a `--netrc`/config
     file rather than `-u user:pass` on argv.
   - If auth fails, the capability flags in `virtualmin.yml`'s create-admin task are likely wrong. Do
     NOT flip `no_log: false` — that logs the plaintext password. Diagnose safely: run
     `virtualmin create-admin --help` on the node for the exact flag names, and/or re-create a THROWAWAY
     admin manually with a DUMMY password to read the real CLI error — never with the real credential.
4. **Confirm PRAHO activated the node.** The `VirtualminServer` row should be `status=active`
   (i.e. `verify_and_activate` succeeded). If still `disabled`, the deployment log carries the
   "Node registered but left disabled: …" reason — that reason IS the handshake failure from step 3.
5. **Provision a test customer — this is the ACL CAPABILITY gate, not just auth.** `info`/`list-domains`
   prove the credential authenticates; they do NOT prove `--can-create`/`--can-edit` actually grant
   domain provisioning. Creating a real domain does:
   - `create_virtualmin_account` should succeed (a `VirtualminAccount`, status active) — this exercises
     `create-domain`, proving the ACL user has the create capability the flags are meant to grant.
   - The domain should resolve (GAP 3 / DNS) and serve. Without GAP 3, resolve DNS manually to test.
   Every auto-deploy runs the IDENTICAL `virtualmin.yml`, so proving the capability flags once here
   proves them for all future deployments — this drill is the one-time capability acceptance.
6. Record RTO (deploy start → active) and note any manual step you had to take — the goal is **zero**.

## Debugging aids
- Hidden create-admin error → do NOT flip `no_log: false` (it logs the plaintext password). Read the
  flag names with `virtualmin create-admin --help`, or reproduce with a throwaway admin + dummy password.
- Credential transport: the API password reaches the ansible CONTROLLER via a `0600` temp vars file
  (`-e @file`, never the `ansible-playbook` argv), cleaned up after the run. **Residual risk:** on the
  TARGET node the password is briefly visible in the process list during the `create-admin` command
  itself (`--pass` on argv) — inherent to the Virtualmin CLI; `no_log` only hides the CONTROLLER's
  output. Mitigated by the node being freshly-provisioned + PRAHO-controlled and the command being
  short-lived; a stdin/password-file facility on the node is a hardening follow-up to investigate.
- `verify_and_activate` calls `gateway.test_connection()`; check its `{"healthy": …}` response.

## Definition of done for #347
A deploy from a Hetzner key yields an `active` + credentialed node with no manual step, and a real customer domain provisions and serves on it. Until this drill passes, the code is "structurally complete, unproven."
