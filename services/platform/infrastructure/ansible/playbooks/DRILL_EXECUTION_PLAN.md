# #347 end-to-end drill — execution plan (CLI + Web UI)

Operational plan for running the live Hetzner → Virtualmin → order → provisioning
drill. Companion to `NODE_DEPLOY_DRILL.md` (which is the acceptance checklist).
Run on the `agent/347-credential-seam` branch — it has the fixed deploy path
(#341) + the credential seam (#347 GAP 1/2) + idempotent destroy.

## 0. Secrets & safety
- The Hetzner API token was provided by the operator in chat. Store it via
  `store_provider_token()` into the CredentialVault — **never echo it, never
  commit it**. The operator will **rotate it after the drill** (it lived in a
  chat transcript).
- This creates a **real, billable** Hetzner server. **Destroy it at the end.**
- If anything wedges, the server can also be killed directly in the Hetzner
  console; then reconcile PRAHO state.

## 1. Stand up PRAHO
- `make dev-platform` — runs migrations, seeds data, starts the **django-q
  workers** (the async deploy runs there — essential) + runserver on `:8700`,
  SQLite DB. `make dev-all` also brings up the portal on `:8701`.
- Confirm the qcluster is alive (`django_q.log`) before triggering a deploy.

## 2. Configure the Hetzner provider (django shell or a mgmt command)
- Create `CloudProvider(provider_type="hetzner", code="hetzner", credential_identifier=...)`.
- `store_provider_token(provider, "<token>")` → vault (keyed by credential_identifier).
- Seed real Hetzner-valid `NodeRegion` (e.g. `fsn1`/`nbg1`), `NodeSize`
  (e.g. `cx22`), and a virtualmin `PanelType(panel_type="virtualmin",
  ansible_playbook="virtualmin.yml")`.

## 3. fqdn resolution (the dev hack)
- PRAHO reaches the node's API by **hostname** (`https://<fqdn>:10000`), not IP
  (`virtualmin_models.py:api_url`). So the fqdn must resolve to the node IP for
  the credential handshake / activation to work.
- Use `/etc/hosts` on the PRAHO host: `<node-ipv4>  <node-fqdn>`. The IP only
  exists after `create_server`, and activation happens later in the same async
  task — so either add the entry mid-deploy (after IP is known, before
  `verify_and_activate`) or run the deploy in two stages. (`resolv.conf` is for
  nameservers, not per-host maps — wrong tool.)

## 4. CLI drill
1. Trigger a deploy (`queue_deploy_node(...)` from a shell, or the mgmt path).
2. Watch the FSM via `NodeDeploymentLog`: provisioning_node → configuring_dns →
   installing_panel → configuring_backups → validating → registering → completed.
   (virtualmin-install is ~40 min.)
3. **Validate the `create-admin` flags** (biggest unknown): SSH to the node,
   `virtualmin list-admins`, then test API auth:
   `curl -k -u 'praho-api:<pw>' 'https://<ip>:10000/virtual-server/remote.cgi?program=list-domains'`.
   If it 401s, set `no_log:false` on the create-admin task, re-run, read the real
   error, `virtualmin create-admin --help` for the exact capability flags, fix.
4. Confirm `verify_and_activate` flipped the `VirtualminServer` to `active`
   (else the deployment log carries the "left disabled: …" reason = the handshake
   failure = step 3).
5. **SSH host-key trust for a brand-new node** — the fail-closed RejectPolicy +
   known_hosts path needs the node's key trusted; watch how this behaves and
   sort a TOFU/known-hosts step if it blocks.

## 5. Web-UI drill (Claude-in-Chrome)
- Load Chrome MCP tools; open `http://localhost:8700`, log in as a staff user
  (seed one if needed).
- Fill the **node deployment form** (provider / region / size / panel) → submit
  → watch it spin up a real server through the same pipeline.
- Create an **order** for a hosting service → confirm → watch **provisioning**
  land on the node (`create_virtualmin_account`) — the full order→provisioning
  path end-to-end.
- Confirm the customer domain provisions and serves.

## 6. Teardown
- Destroy the node (`destroy_node` / the UI destroy action). Confirm the Hetzner
  server + firewall are actually deleted (validates the idempotent-delete fix
  against real Hetzner).
- Remove the `/etc/hosts` entry. **Rotate the Hetzner key.**

## Known unknowns this drill will settle
1. The `virtualmin create-admin` capability flags (guessed; will likely need fixing).
2. SSH host-key trust for a freshly created node (fail-closed policy).
3. Hostname resolution on the PRAHO→node API path (the /etc/hosts hack; GAP 3 automates it later).
4. `destroy_node` against real Hetzner (idempotent-delete fix, unproven live).
