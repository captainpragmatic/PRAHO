# Node deployment drill — execution entry point (#347 / #436)

Use a reviewed branch based on current `master`. The canonical
[panel-certificate preflight and live drill guide](../../../../../docs/deployment/DEPLOYMENT.md#panel-certificate-preflight-and-activation-gate-436)
defines the certificate prerequisites, how issuance and the trust gate work,
the rate budget, and cleanup for #436.
The [credential-seam acceptance checklist](NODE_DEPLOY_DRILL.md) covers API ACLs
and customer provisioning after the node is ready.

The preparation command is read-only:

```bash
# From services/platform with the platform environment configured:
python manage.py panel_cert_preflight --provider-id <provider-id> --json
python manage.py panel_cert_preflight --deployment-id <deployment-id> --json
```

A green report establishes only scoped prerequisites. It does not prove ACME
issuance, renewal or activation, and does not start a deployment. The installer
issues the panel certificate from the production CA, and no staging path exists
(see the canonical guide), so a live drill spends real certificates. Use a node
name with budget left: the name includes the region.

For a separately scheduled live run:

1. Set a disposable-node budget and cleanup deadline. Configure project-scoped
   provider credentials through the vault and valid Cloudflare token/zone
   settings. Do not reuse secrets copied into chat or print them for debugging.
2. Start the platform and its django-q workers (`make dev-platform`, or
   `make dev-all` for the portal too). Confirm the worker is processing tasks.
3. Check the node name's certificate budget before triggering the CLI or staff
   UI deployment. Record the deployment ID and watch `NodeDeploymentLog` through
   provisioning, DNS, panel installation, backups, validation and registration.
   Public node DNS is implemented; a controller `/etc/hosts` entry is not ACME
   evidence and should not replace public DNS checks.
4. Follow the certificate guide, then the credential checklist. Keep Ansible
   `no_log` enabled. Inspect installed command help or reproduce errors with a
   throwaway admin and dummy password. Use the platform's verified/pinned TLS
   handshake to test real API credentials; never disable certificate validation
   or put a password in a command argument.
5. Exercise customer provisioning through the normal order flow, record timing
   and any manual steps, and retain redacted evidence tied to the tested SHA.
6. Destroy the disposable deployment using the normal teardown path. Confirm
   owned server, firewall and DNS resources are gone through read APIs, reconcile
   any partial teardown and remove local temporary files. Rotate exposed secrets.

#436 remains open until the live certificate evidence and reviewed fatal-issuance
rollout are complete. Passing the credential drill alone does not close it.
