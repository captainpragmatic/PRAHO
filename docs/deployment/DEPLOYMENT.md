# PRAHO Deployment Guide

For Platform database/media recovery, see [Restore a Platform backup](PLATFORM_RESTORE.md).

This guide covers all deployment scenarios for PRAHO, from native single-server setups to multi-server distributed deployments.

## Table of Contents

- [Choosing a Deployment Method](#choosing-a-deployment-method)
- [Managed-node SSH Trust](#managed-node-ssh-trust)
- [Deployment Options](#deployment-options)
  - [Option 1: Native Single Server](#option-1-native-single-server)
  - [Option 2: Docker Single Server](#option-2-docker-single-server)
  - [Option 3: Container Service](#option-3-container-service)
  - [Option 4: Docker Platform Only](#option-4-docker-platform-only)
  - [Option 5: Docker Portal Only](#option-5-docker-portal-only)
  - [Option 6: Two Servers (Docker Compose split)](#option-6-two-servers-docker-compose-split)
- [Database Operations](#database-operations)
- [Rollback Procedures](#rollback-procedures)
- [Makefile Commands](#makefile-commands)
- [Environment Variables](#environment-variables)
- [Troubleshooting](#troubleshooting)

---

## Queued email across the durable-envelope upgrade

Upgrade all Platform writers and Django-Q workers together. The new publishers queue only an email id;
old workers cannot execute those tasks. Old publishers still create rows without a durable envelope,
so a mixed-version rollout is not supported. This patch adds no schema or status migration.

1. Take the normal restricted database backup before the upgrade. Keep the original ORM queue,
   Schedule and Task rows. Do not purge jobs or delete their kwargs to make worker errors disappear.
2. Stop incoming writes and let any in-flight email sends finish before stopping workers. For native
   hosts the units are `praho-platform`, `praho-portal`, and `praho-qcluster`; the Compose service names
   are `platform`, `portal`, and `qcluster` (Portal is on its own host for split deployments). Confirm
   the topology in this guide before operating it. An old `sending` row, even without a lease, has an
   uncertain provider outcome and needs review, not an automatic resend.
3. With those processes stopped, install the same build for every Platform writer and worker. Use
   the normal migration/deploy procedure. Do not restart workers until the checks below are safe.
4. In the Platform runtime, from `services/platform`, run the read-only inventory below with its
   normal production settings and credentials. It prints ids and counts only. An unsafe global
   setting, per-task acknowledgement override, or unreadable package is a rollout blocker: keep the
   original signed packages in the restricted backup and reconcile them before starting workers.

```python
# Run in `python manage.py shell` in the configured Platform runtime.
import ast
from collections import Counter
from django.db.models import Q
from django_q.conf import Conf
from django_q.models import OrmQ, Schedule
from django_q.signing import SignedPackage
from apps.notifications.models import EmailLog

send_task = "apps.notifications.tasks.send_email_task"
counts = Counter()
counts["unsafe_global_retention"] = int(bool(Conf.ACK_FAILURES) or Conf.MAX_ATTEMPTS != 0)
for job in OrmQ.objects.iterator():
    try:
        task = SignedPackage.loads(job.payload)
        if task.get("func") == send_task:
            counts["email_packages"] += 1
            counts["unsafe_ack_override"] += int(bool(task.get("ack_failure")))
    except Exception:
        counts["unreadable_packages"] += 1
for entry in Schedule.objects.filter(func=send_task).iterator():
    try:
        kwargs = ast.literal_eval(entry.kwargs or "{}")
        options = kwargs.get("q_options", {})
        counts["unsafe_schedule_ack_override"] += int(bool(kwargs.get("ack_failure") or options.get("ack_failure")))
    except Exception:
        counts["unreadable_schedule_kwargs"] += 1
print(dict(counts))
for row in EmailLog.objects.filter(Q(envelope__isnull=True) | Q(envelope=""), status__in=["queued", "failed", "sending"]).values("id", "status").iterator():
    print(row)
```

The required retention settings are `ack_failures=False` and `max_attempts=0` (the Django-Q defaults).
A held invocation raises `LegacyEmailRecoveryRequiredError` outside the provider error handler; under
those settings the worker/monitor retains its original signed ORM package. A per-task
`ack_failure=True` overrides that protection. Never interpret a returned `{"success": False}` as a
broker failure: Django-Q acknowledges a normally returned function as successful execution.

5. Resume the new writers and workers. All new sends and retries still carry only their email id.
   The compatibility path imports only complete original calls with no explicitly supplied
   `retry_count`, addressed solely to a bare primary mailbox already on the row. Historical display-name
   primaries are held too: erasure before recipient digests existed may have missed them. It checks the stored
   identity and bodies, seals the envelope, then claims the row under the same lock. Stored envelopes
   remain authoritative over stale task arguments. Old lossy sweep payloads, their retries (including
   full-shaped retries), additional To/CC/BCC recipients, and unresolved `sending` rows are held.
   A hidden recipient's earlier erasure may have missed the old row, so importing that address is not
   safe merely because the package survived. Staff must reconstruct these messages from their source.
6. Confirm recoverable messages reach the provider and review held ids with staff. A missing-key
   failure before preparation commits preserves the original package for redelivery after keys are
   fixed. Raw legacy attachment bytes are available only to that claiming invocation; if it fails or
   dies, an id-only retry refuses instead of sending without the attachment. Reconstruct the source
   document explicitly. Never bulk resend `sent` or `delivered` messages, or assume a timeout proves
   that the provider accepted nothing.

A held package can be redelivered on the existing broker retry interval until it is reconciled.
There is no new retry loop. Empty-envelope rows are excluded before drain batch limits, so they do
not block newer complete messages. Malformed decoded envelopes fail permanently at the sending
boundary; historical log displays can still show their first recorded recipient.

Django-Q already copies old args/kwargs into Task results, and old one-off schedules with `repeats=1`
may remain with `repeats=0` and their original kwargs. This fix adds no attachment blob store and does
not claim to erase those historical copies. Keep unresolved payloads restricted and recoverable.
Review their existing retention/erasure separately; clean up resolved originals only after approved
reconciliation. Do not expose a queue export or Task kwargs in logs or support replies.

A version rollback to an old worker is unsafe while id-only tasks remain. Follow the full database
and release rollback procedure rather than restarting old workers against the new queue.

## Managed-node SSH Trust

Platform and its task worker include `ansible-core` from the locked Platform dependency group and
OpenSSH client tools. Docker builds and native deployment install the pinned collections in
`services/platform/infrastructure/ansible/requirements.yml` into `/opt/praho-ansible/collections`.
The service processes read that directory. Docker uses a private controller home under `/tmp`; native
units use separate mode-0700 runtime directories under `/run`. Native `ProtectHome` and `ProtectSystem`
remain enabled. Portal does not need these
tools. Installing Ansible only on the deployment laptop does not supply the application runtime.
Native Make targets decode `.env.prod`, `.env.staging` or `.env.dev` as data, without sourcing shell
code. Use one `KEY=value` assignment per line; quote values containing spaces. Single quotes preserve
literal dollars and backticks. Multiline values, interpolation, `export` declarations and inline
comments are refused with key/line diagnostics. The last declaration wins. The native role uses the
same decoder and writes an escaped runtime EnvironmentFile, so quoted credentials mean the same thing
to deployment commands and systemd. For a remote dev host, start with the staging example and select
`config.settings.dev`; the local-only `.env.example.dev` is not a remote-server configuration.

Database credentials for unattended native backup/restore live in the mode-0600
`/opt/praho/credentials/postgresql.pgpass`, inside a mode-0700 directory. The generated executables
are mode 0700 and contain only its path. Do not copy credential files or verbose historical deployment
logs to shared storage. Existing-host credential rotation, if exposure occurred, is an operator rollout
step; deployment does not silently rotate the database password.

PRAHO rejects unknown SSH host keys for node validation, Virtualmin fallback access, pooled SSH connections, and Ansible maintenance. Before enabling infrastructure automation, provision a `known_hosts` file for the operating-system account that runs Platform and its Django-Q workers.

Obtain each host key or fingerprint through a trusted out-of-band channel, such as the cloud-provider console. Do not trust an unverified `ssh-keyscan` result by itself. Add entries for every address PRAHO uses to connect (normally both the node hostname and its public IP), then set:

```dotenv
PRAHO_SSH_KNOWN_HOSTS_PATH=/etc/praho/known_hosts
```

The file must be readable by the Platform and worker processes. Container deployments must mount the same file read-only into the container at the configured path. A missing file, unknown host, or changed key intentionally blocks the operation; verify rotations out of band and update the trust file before retrying.

Newly deployed self-signed Virtualmin nodes have the certificate actually served on port 10000 measured through this trusted SSH channel and pinned automatically. Before enabling provisioning after upgrading an installation with existing unpinned self-signed nodes, run:

```bash
python manage.py pin_virtualmin_certificates --dry-run
python manage.py pin_virtualmin_certificates
```

The command fails closed for records without a linked deployment or without verified SSH host-key trust. Do not obtain their initial certificate pin over an unverified network connection.

The `--dry-run` output lists every record that cannot be remediated by a normal run, in two classes:

**1. Servers with no linked node deployment.** The SSH path needs a `NodeDeployment` for the node IP and the host-key trust anchor, so servers registered through the admin form rather than a deployment cannot be pinned automatically. Either link a deployment, or read the digest on the node itself and supply it explicitly:

```bash
# ON THE NODE, over an already-trusted session (console or verified SSH).
# `-servername` matters: PRAHO's request sends SNI, so a vhost-based setup can otherwise
# serve you a DIFFERENT certificate than the one PRAHO will validate. Use the node's real
# api_port if it is not the default 10000. The `cut` strips OpenSSL's "sha256 Fingerprint="
# label — the command takes the bare digest.
openssl s_client -connect 127.0.0.1:10000 -servername <node-fqdn> </dev/null 2>/dev/null \
  | openssl x509 -noout -fingerprint -sha256 \
  | cut -d= -f2

# On the Platform host, with the value from above:
python manage.py pin_virtualmin_certificates \
  --server-id <virtualmin-server-uuid> --fingerprint <sha256>
```

The digest is accepted with or without colons, in either case, and with an optional `sha256:` prefix. It is *not* read over the network by PRAHO — you are vouching for it, which is why it must come from the node itself rather than from an `openssl s_client` run against the node from elsewhere.

Replacing an existing pin is refused unless you add `--force`, so a mis-pasted UUID cannot silently retarget a healthy node's trust anchor. Every manual pin is recorded as a `virtualmin_cert_pin_set_manually` security event including the previous digest, which is what you need to recover from a wrong one.

**2. Servers still using plain HTTP (`use_ssl=false`).** No pin makes these reachable — the HTTPS guard rejects them before pinning is even considered — and `--fingerprint` refuses them rather than let a pin imply the record is remediated. Migrating one is a node-side change *and* a database-side change; doing only the first leaves the row unreachable:

1. **On the node**, enable SSL for Webmin/Virtualmin so the API listens on HTTPS
   (Webmin → Webmin Configuration → SSL Encryption), and confirm it answers:
   `openssl s_client -connect 127.0.0.1:10000 -servername <node-fqdn> </dev/null`
2. **In PRAHO**, open the server (Infrastructure → Virtualmin servers → the row → Edit) and
   tick **Use SSL**, adjusting the port if it changed. The form *requires* HTTPS, so a save
   that succeeds is itself the confirmation that the record is no longer plain-HTTP.
3. **Then pin**, if the node uses a self-signed certificate: re-run
   `pin_virtualmin_certificates` (it becomes a candidate once `use_ssl=true`), or use the
   `--fingerprint` path above when it has no linked deployment. A node with a CA-issued
   certificate needs no pin — leave `ssl_verify` on.
4. **Verify** the row is no longer listed by `pin_virtualmin_certificates --dry-run`, and
   that a provisioning action against the node succeeds.

To size the work before deploying (JSON report of plain-HTTP rows, stranded
unpinnable rows, and SSH-pinnable candidates):

```bash
python manage.py pin_virtualmin_certificates --report
```

### Panel-certificate preflight and activation gate (#436, drill-gated)

The read-only preflight prepares the **Hetzner / Virtualmin** drill. It does not
issue certificates, provision servers, edit DNS, pin certificates, or change
activation settings. Credential reads retain the vault's normal access audit.
Run from `services/platform` with the platform environment and database settings:

```bash
python manage.py panel_cert_preflight --provider-id 1
python manage.py panel_cert_preflight --deployment-id 42 --json > panel-cert-preflight.json
```

Choose exactly one existing database ID. Provider mode checks the controller's
`ansible-playbook`, `ssh`, `ssh-keygen`, and `ssh-keyscan`, the provider credential,
Cloudflare zone access, and `node_deployment.dns_default_zone` containment before
spending money. The provider vault entry takes precedence; `HCLOUD_TOKEN` is used
only when no vault identifier is configured. Cloudflare uses
`node_deployment.dns_cloudflare_api_token` and
`node_deployment.dns_cloudflare_zone_id`. Successful API reads establish neither
write permissions nor available cloud capacity. Other providers are reported as
unsupported for this drill.

Deployment mode additionally checks the recorded server, the deployment's own
DNS zone and FQDN, and authoritative A/AAAA answers against its recorded addresses.
Nameservers are discovered through the controller resolver; each authority is
queried directly over TCP port 53. A lookup failure remains unknown, including
when another authority answers successfully. Empty AAAA is acceptable only when
the deployment has no IPv6 address. Missing A, conflicting answers, stale AAAA,
non-public addresses, and aliases require correction. DNS changes or resolver
caches may require an operator to wait and rerun; the command does not poll.

Every published address receives one port-80 GET with the node's `Host` header.
The probe uses `/.well-known/acme-challenge/praho-preflight`, creates no file,
reads no response body, and never follows redirects. An HTTP 200, redirect, 404,
or error response establishes only that an HTTP listener answered. **It does
not establish that an actual HTTP-01 nonce reaches the correct webroot.** A
controller unable to reach a published IPv6 address reports an indeterminate
check; do not discard the AAAA result to obtain a green report.

JSON includes a schema version, stable check IDs, `pass`, `fail`, `unknown`, or
`not_run`, and the individual authoritative answers. Any scoped prerequisite
that is not `pass` produces a nonzero exit; JSON remains on stdout and the exit
explanation goes to stderr. A zero exit means only the selected mode's observed
prerequisites passed. Provider mode has no node DNS, HTTP, or TLS observations.
API and socket operations use ten-second timeouts; the command adds no retry
loops, disables Hetzner HTTP retries, and bounds DNS discovery lookups. Total
runtime can exceed ten seconds because checks and authorities are independent.
Tokens, authenticated request payloads, and raw API errors are omitted.

The separate certificate observation connects to the **recorded IPv4 on port
10000**, using the FQDN for SNI and ordinary CA/hostname verification. It reports
`trusted`, `untrusted`, or `indeterminate`, plus observed SHA-256 and expiry when
available. An observed fingerprint is not a trust anchor. A self-signed or
staging certificate before issuance is expected and does not fail the scoped
prerequisites. Probe failure does not mean the certificate was rejected.

`letsencrypt_fatal` remains **false** by default. The
`infrastructure.require_trusted_panel_certificate` setting remains **off** by
default; when enabled it already refuses both untrusted and indeterminate
certificates and leaves the server disabled. The preflight does not enable either
control. **#436 stays open until the live evidence and rollout below are complete.**

#### Future live drill: evidence required before fatal issuance rollout

1. **Prepare one disposable node and a cost limit.** Validate provider and DNS
   credentials, confirm a public domain under operator control, select available
   capacity, name the cleanup owner and deadline, and record a maximum spend.
   Capture the Git SHA, provider/deployment IDs and preflight JSON. Public DNS
   provisioning is implemented; `/etc/hosts` cannot prove public ACME readiness.
   Keep real credentials in the vault and the existing mode-0600 Ansible vars
   file; never put them on argv, in a transcript, or in unredacted logs.
2. **Establish the installed CLI contract before any ACME attempt.** Record the
   installer artifact checksum, OS, Webmin/Virtualmin versions, installed help,
   and relevant source/paths. The [Virtualmin command documentation](https://www.virtualmin.com/docs/development/api-programs/generate-letsencrypt-cert/)
   requires `--domain` to identify a virtual server; `--host` alone is not that
   argument. `--renew` configures renewal, and `--staging` selects the test CA.
   Prove whether the panel hostname should use a Virtualmin virtual server or
   Webmin's hostname-certificate workflow on the installed version. Do not ship
   guessed replacement flags into the active playbook.
3. **Prevent the installer's own production request.** The [automated installer](https://www.virtualmin.com/docs/installation/automated/)
   requests a hostname certificate unless `--no-hostname-ssl` is used. Verify that
   option in the selected installer and build an isolated staging drill path
   before starting installation. The current deployment playbook is not a
   staging-safe harness: setting `letsencrypt_fatal=true` alone does not select
   staging or suppress installer issuance. Stop if production ACME calls cannot
   be excluded. Record the staging directory actually used:
   `https://acme-staging-v02.api.letsencrypt.org/directory`.
4. **Prove challenge routing.** Run deployment preflight after DNS provisioning.
   Compare all authorities, then serve an actual random HTTP-01 test nonce at the
   chosen challenge webroot. Fetch and compare its exact content from an external
   vantage point at every published A and AAAA address with the hostname `Host`
   header. Inspect any redirects explicitly; neither an open port nor a generic
   response is proof. Remove the test nonce afterward. Resolve DNS/firewall/webroot
   failures before contacting ACME.
5. **Exercise staging success and failure.** Prove staging issuance, installation
   into the running panel, and the certificate served on :10000. Induce a failed
   issuance and a separate installation failure; with the drill's fatal flag they
   must abort before activation and produce useful redacted errors. Interrupt
   between issuance and installation, recover without another unnecessary order,
   and rerun successfully without replacing a usable certificate. Verify the
   marker is written only after both steps succeed and reconciles with the
   installed certificate; a marker alone must not conceal an interrupted install.
   Demonstrate the configured renewal mechanism and a staging renewal, including
   panel reload and a changed served certificate. Preserve order/attempt counts.
6. **Prove ordinary trust once.** After staging passes and the rate budget permits,
   make one deliberate production issuance. Verify FQDN/SAN, chain, expiry and
   fingerprint from the platform, then exercise strict activation: a trusted
   certificate permits the ordinary credential handshake; untrusted and
   indeterminate probes refuse. [Staging roots](https://letsencrypt.org/docs/staging-environment/)
   belong only in an isolated test client's trust store, never the controller's
   ordinary trust store. Staging success cannot satisfy production CA trust.
7. **Review rollout and clean up.** Ship the proven hostname workflow, recovery
   behavior and fatal failure handling in a follow-up PR; then enable fatal
   issuance and strict activation in the reviewed rollout. Destroy the disposable
   server and owned firewall, DNS records and temporary challenge files. Verify
   absence through provider/DNS read APIs and reconcile PRAHO state. Retain
   redacted logs, timings, costs, DNS/HTTP evidence, certificate identities,
   interruption/renewal results, attempt counts and cleanup receipts on #436.

Before the paid drill, record a capacity model per registered domain: planned new
nodes plus replacements and recovery headroom in each seven-day window. Current
[Let's Encrypt rate limits](https://letsencrypt.org/docs/rate-limits/) include 50
new certificates per registered domain per seven days, five per exact identifier
set per seven days, and five failed authorizations per identifier/account/hour.
Check current limits again at execution time and distinguish renewals from new
orders. Keep all iteration on staging. Honor `Retry-After` and the reported
cooldown; a failure must not trigger an automatic deploy retry or a replacement
hostname to bypass the limit. If forecast demand exceeds the budget, obtain an
approved limit override before rollout; creating subdomains does not provide a
new registered-domain allowance.

---

## Choosing a Deployment Method

| Method | Stack | RAM | Complexity | Management |
|--------|-------|-----|------------|------------|
| **Native** | Gunicorn + systemd + Caddy | 2 GB+ (e.g. Hetzner `cpx11`) | Low | `systemctl`, `journalctl` |
| **Docker** | Docker Compose + Caddy | 4 GB+ | Medium | `docker compose`, `docker logs` |
| **Container Service** | ECS / Cloud Run / App Platform | Varies | High | Platform-specific CLI |

**Native** is the simplest option for a single VPS — no Docker overhead, direct systemd control, and easy debugging with `journalctl`. Start here if you have a single Ubuntu server.

**Docker** provides reproducible builds and easier horizontal scaling. Use this if you already run Docker infrastructure or want identical dev/prod environments.

**Container Service** is for managed cloud platforms with auto-scaling, built-in load balancing, and managed databases.

---

## Two-Domain Security Architecture

PRAHO requires **two separate FQDNs** — one for Portal (customer-facing) and one for Platform (staff/admin). This is a security requirement, not optional.

**Why two domains?** Portal and Platform have completely different threat models. Portal is public-facing and stateless; Platform has full database access and admin capabilities. Separating them by domain means:
- Caddy routes traffic by hostname — no URL-path-based routing mistakes can leak admin endpoints
- Platform can be IP-whitelisted at the reverse proxy level
- Cookie scoping is isolated (no cross-service cookie leakage)
- Each service has its own TLS certificate

| Component | Domain | Access |
|-----------|--------|--------|
| **Portal** (customer-facing) | `portal.example.com` | Public |
| **Platform** (staff/admin) | `platform.example.com` | IP-restricted (optional) |
| **Bare IP** | Server's public IP | 301 redirect to portal domain |

**Security layers (all deployment modes):**

1. **UFW firewall** — default deny incoming, only allows SSH (22), HTTP (80), HTTPS (443). Gunicorn ports 8700/8701 are **never** reachable from outside.
2. **Caddy reverse proxy** — routes by domain name (not URL path). Platform domain can be IP-whitelisted via `platform_allowed_ips`. Non-whitelisted IPs get HTTP 403.
3. **Django `ALLOWED_HOSTS`** — fails hard at startup if not set or contains wildcards. No fallback defaults in production.

**IP whitelisting (optional, all modes):**
```yaml
# Pass as extra-var or add to inventory vars
platform_allowed_ips:
  - 203.0.113.10        # Office IP
  - 198.51.100.0/24     # VPN range
```
When `platform_allowed_ips` is empty (default), Platform is accessible from any IP on its domain.

---

## Deployment Options

### Option 1: Native Single Server

Deploy PRAHO directly on the host with PostgreSQL + Gunicorn + systemd + Caddy. No Docker required. Fully automated via Ansible. One inventory, one playbook — works for staging and production.

**Architecture:**
```
┌────────────────────────────────────────────────────────┐
│  Ubuntu Server — UFW: deny all except 22/80/443        │
│                                                        │
│  ┌──────────────┐                                      │
│  │    Caddy      │  portal.example.com  → Portal       │
│  │   :80/:443    │  platform.example.com → Platform    │
│  │               │  bare IP → 301 to portal            │
│  └───┬──────┬───┘                                      │
│      │      │                                          │
│  ┌───▼───┐  ┌───▼─────┐  ┌──────────┐                 │
│  │Portal │  │Platform │──│PostgreSQL│                 │
│  │ :8701 │  │ :8700   │  │  :5432   │                 │
│  └───────┘  └─────────┘  └──────────┘                 │
│             ┌─────────┐                                │
│             │qcluster │                                │
│             │(Django-Q)│                                │
│             └─────────┘                                │
└────────────────────────────────────────────────────────┘
```

**What it installs:**
- PostgreSQL 16 (from official APT repo)
- Python 3.13 (managed by uv under `/opt/praho-python`, readable by both service users)
- uv (Python package manager)
- Caddy (automatic HTTPS via Let's Encrypt)
- 3 systemd services: `praho-platform`, `praho-portal`, `praho-qcluster`
- Backup cron job (daily at 2:00 AM)

#### Prerequisites

1. **Ubuntu 26.04 LTS** server (24.04 remains supported for existing hosts)
2. **Ansible** installed on your local machine
3. **Two DNS A records** pointing to the server IP — both must resolve before deploying (Caddy ACME will fail without them)
4. **Root SSH key access**, approved operator public keys and a pinned server host key

```bash
# Install Ansible and required collections
pip install ansible
ansible-galaxy collection install -r deploy/ansible/requirements.yml
```

#### Deploy

The `.env` file is the **single source of truth** for all configuration. Ansible validates it, copies it to the server, and uses its values for every template and service.

> **Why `praho_env` and not `environment`?** Ansible reserves the keyword `environment` for setting task-level environment variables. Using it as a custom variable causes silent failures.

**Step 1: Create your environment file** (once per deployment target):
```bash
# For staging:
cp .env.example.staging .env.staging
# Edit .env.staging — fill in all [REQUIRED] values

# For production:
cp .env.example.prod .env.prod
# Edit .env.prod — fill in all [REQUIRED] values
```

The `.env.example.*` files list every variable Django reads, organized with `[REQUIRED]`, `[RECOMMENDED]`, and `[OPTIONAL]` tags. You only need to fill in the `[REQUIRED]` ones to get started.

**Step 2: Deploy:**
```bash
make deploy-staging
# or
make deploy-prod
```

That's it. The Makefile validates the file exists, passes it to Ansible, and Ansible copies it to `/opt/praho/.env` on the server.

**Manual Ansible command** (if you prefer not to use Make):
```bash
cd deploy/ansible && ansible-playbook -i inventory/native-single-server.yml \
  playbooks/native-single-server.yml \
  -e praho_env=staging -e env_file_path=$(pwd)/../../.env.staging -v
```

#### Staging vs Production Django Settings

The Ansible infrastructure is fully unified — one inventory, one playbook, one set of variables. The **only** thing that differs is the Django settings module (`-e praho_env=staging` selects `config.settings.staging`).

Staging settings exist to prevent real-world side effects during testing:
- **Email**: console backend (prevents sending real emails)
- **e-Factura**: test mode (prevents submitting invoices to Romanian ANAF)
- **HSTS**: 1 hour instead of 1 year (allows rolling back to HTTP), via `HSTS_POLICY=max-age=3600` at the Caddy edge
- **Sessions**: longer lifetime, no browser-close expiry (more lenient for testing)
- **Logging**: DEBUG level with smaller log files

See the docstrings in `services/platform/config/settings/staging.py` and `services/portal/config/settings/staging.py` for the full list.

#### Required Environment Variables

These are the `[REQUIRED]` variables in the `.env.example.*` files — PRAHO won't deploy without them:

| Variable | Description | Example |
|----------|-------------|---------|
| `PRAHO_SERVER_IP` | Server public IP address | `203.0.113.10` |
| `PORTAL_DOMAIN` | Customer-facing FQDN; customer email links point at `https://` and this domain unless staff set Settings → Customer portal URL | `portal.example.com` |
| `PLATFORM_DOMAIN` | Staff/admin FQDN | `platform.example.com` |
| `ACME_EMAIL` | Let's Encrypt notification email | `admin@example.com` |
| `DJANGO_SECRET_KEY` | Django secret key | `openssl rand -base64 50` |
| `DJANGO_ENCRYPTION_KEY` | AES-256-GCM key for 2FA secrets and sensitive fields; production refuses to start without it | `python -c "import secrets, base64; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())"` |
| `CREDENTIAL_VAULT_MASTER_KEY` | Credential vault key; production refuses to start without it | same command, a different key |
| `DB_PASSWORD` | PostgreSQL password | `openssl rand -base64 32` |
| `HMAC_SECRET` | Portal-to-Platform auth secret | `openssl rand -base64 32` |
| `PLATFORM_TO_PORTAL_WEBHOOK_SECRET` | Platform→Portal webhook HMAC secret | `python -c "import secrets; print(secrets.token_urlsafe(32))"` |

`HMAC_SECRET` is **critical** — Portal authenticates every API request to Platform using HMAC-SHA256 signatures. Without it, Portal cannot communicate with Platform.

`PLATFORM_TO_PORTAL_WEBHOOK_SECRET` is required for Platform→Portal payment webhooks. Both services validate this secret at startup in production — missing it causes a startup error.

The `.env.example.*` files also list `[RECOMMENDED]` variables (email, Stripe, e-Factura) and `[OPTIONAL]` variables with sensible defaults. See the file comments for details.

#### What the Playbook Validates

Before deploying, the playbook checks:
1. `praho_env` is defined and one of `dev`, `staging`, `prod`
2. Ubuntu >= 24.04
3. The `.env.{praho_env}` file exists and contains all required variables (`DJANGO_SECRET_KEY`, `DB_PASSWORD`, `HMAC_SECRET`, `PORTAL_DOMAIN`, `PLATFORM_DOMAIN`, and for `prod` also `PLATFORM_TO_PORTAL_WEBHOOK_SECRET`, `DJANGO_ENCRYPTION_KEY` and `CREDENTIAL_VAULT_MASTER_KEY`)
4. Both FQDNs resolve to the server IP (DNS pre-flight)

The shared SSH role requires a verified server key in `PRAHO_DEPLOY_KNOWN_HOSTS_FILE`
and approved operator public keys in `PRAHO_SSH_PUBLIC_KEYS_FILE`. Leave
`PRAHO_SSH_KEY` empty to use the SSH agent, or provide an explicit identity file.
For a first bootstrap set `PRAHO_SSH_PORT=22`; normal access uses 9876. Run
`make ssh-harden ENV=staging` to establish SSH access independently of application
configuration. It installs keys additively, disables password and keyboard-interactive
authentication for everyone, allows root with keys, and verifies a fresh connection
before removing the old listener. Timed rollback protects an incomplete handoff.
A retry detects a completed cutover using the same pinned server identity.

The common role prepares 2 GB of swap (`swap_size_mb: 2048`), verifies kernel
activation, then records it in fstab. Existing files must already be valid swap
with the requested size and root-only permissions; they are never reformatted or
resized. New files require ext4/XFS and at least 1 GiB of free disk after allocation.
Failed creation retains one protected, bounded candidate for retry. Staging uses
one web worker per service; production defaults to two. Swap helps memory spikes
but does not establish production load capacity.

### Promoting a release to staging

Staging receives only release candidates, and the `staging` branch always names the
commit staging runs. Nothing is merged into `staging`; commits flow one way:
pull request → `master` → release candidate → staging → (later) production.

1. **Run the release candidate.** Actions → *Release candidate* → *Run workflow*, or
   `gh workflow run release-candidate.yml [-f candidate_sha=<sha>]`. A blank SHA means
   the current `master` commit; the run title names it. The run checks that the
   commit's pull request passed every required check on exactly the commit's tree,
   then runs the whole platform suite on PostgreSQL and the full Virtualmin lab on that
   SHA. Expect an hour or more. On success the commit shows the status
   `release-candidate`.
2. **If it is red,** staging is untouched: fix it through a pull request into `master`
   and start a new candidate.
3. **If it is green,** from an approved operator IP:
   `make promote-staging SHA=<sha>` (add `DRY_RUN=1` to see the checks only). It
   refuses a commit that is not on `master` or has no successful release-candidate run
   from `master`'s copy of the workflow (the run is the proof, not the status, which
   anyone who can push could post). It deploys from a clean detached checkout of that
   commit, so the playbooks and templates are the reviewed ones (environment/DNS and
   HTTP/HTTPS checks included), refuses any `DEPLOY_METHOD` but git, and only after a
   successful deploy fast-forwards `staging`. Promote from one machine at a time.
   `scripts/promote_staging.sh --rollback <sha>` deploys an older approved release
   and moves the branch back.
4. **Accept it on staging,** then record the deployed SHA.

A release candidate is not a GitHub Release; a `v*` tag publishes one. For production
the order will be: release candidate → staging accepted → tag that same commit →
deploy the tag.

`make deploy-staging VERSION=<commit-or-tag>` still deploys any revision without
moving a branch, for emergencies. Deploys stay manual: staging admits only the
operator IPs and the deploy inputs live on the operator's machine. A "Promote to
staging" button (a `workflow_dispatch` behind a protected `staging` environment that
joins the tailnet and calls the same script) is future work and needs its own
security review first. The production service split is a separate rollout
requirement.

Native staging restricts **both entire sites** to `PLATFORM_ALLOWED_CIDRS`, including
API, health, webhook and static routes. Supply space-separated canonical CIDRs in
the ignored `.env.staging`; include loopback for local callers. Empty/unset defaults
to loopback only. Internet-wide `/0` ranges are refused. Caddy checks the connection
address, so forwarded headers cannot grant access. Automatic ACME challenges remain
managed by Caddy. Keep staging DNS records DNS-only so Caddy sees the caller's IP.

Apply an allowlist or Caddy configuration change with `make deploy-caddy ENV=staging`.
This reads local configuration, validates and installs the Caddyfile, restarts Caddy
only if changed, and checks both HTTPS endpoints from the controller. Run it from
an approved source address. It skips SSH changes, packages, migrations and application
restarts. The full deployment uses the same controller-side HTTPS checks.

Production Portal remains public. Production Platform retains the staff restriction
and its existing API/webhook routes; service-to-service and provider access must be
configured separately before the production rollout. Staging's all-route guard is
not automatically applied to production.

#### Post-Deploy

After deployment completes, the playbook verifies all services over HTTP and HTTPS.

**Step 3: Create the first admin user:**

The database starts empty — no users exist. Create a superuser on the server:

```bash
# SSH to the server and create the admin user interactively
ssh -p 9876 root@<server-ip>
cd /opt/praho/src
sudo -u praho bash -c 'set -a && source /opt/praho/.env && set +a && \
  source /opt/praho/.venv-linux/bin/activate && \
  python services/platform/manage.py createsuperuser --email admin@example.com'
```

You will be prompted for a password. This is the only time credentials need to be entered manually — they are **not** stored in `.env` files or Ansible logs.

Access Platform at `https://<platform-domain>/` (redirects to login).

> **Why not automate this?** Storing admin passwords in `.env` files or Ansible logs is a security risk. The interactive `createsuperuser` method ensures the password is entered once and never written to disk in plaintext.

#### Post-Deploy Configuration (Optional Integrations)

A fresh deployment works with only the `[REQUIRED]` variables filled in. The `[RECOMMENDED]` features can be enabled by adding their env vars to your `.env.{env}` file and redeploying, or by editing `/opt/praho/.env` on the server directly:

| Feature | Env Vars Needed | Impact if Missing |
|---------|----------------|-------------------|
| **Email sending** | `EMAIL_HOST`, `EMAIL_HOST_USER`, `EMAIL_HOST_PASSWORD` | Emails silently fail — no notifications, password resets, or invoices |
| **Stripe payments** | `STRIPE_SECRET_KEY`, `STRIPE_PUBLISHABLE_KEY`, `STRIPE_WEBHOOK_SECRET` | Payment processing disabled |
| **e-Factura (ANAF)** | `EFACTURA_API_URL`, `EFACTURA_API_KEY` | Romanian e-invoicing disabled |
| **2FA encryption** | `DJANGO_ENCRYPTION_KEY` | App fails to start in production. Generate: `python -c "import secrets, base64; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())"` |
| **Credential vault** | `CREDENTIAL_VAULT_MASTER_KEY` | App fails to start in production. Generate: `python -c "import secrets, base64; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())"` |
| **Sentry** | `SENTRY_DSN` | No error tracking — errors only in log files |
| **Company info** | `COMPANY_NAME`, `COMPANY_CUI`, etc. | Placeholder data on invoices |

**To add vars after deployment:**
```bash
# Option A: Edit the local .env file and redeploy
nano .env.prod
make deploy-prod

# Option B: Edit directly on the server (takes effect after restart)
ssh root@your-server
sudo nano /opt/praho/.env
sudo systemctl restart praho-platform praho-portal praho-qcluster
```

**System Status Dashboard:** The staff dashboard displays the latest check snapshot (green/amber/red/grey), its actual check time, and a warning after 26 hours. Refresh runs bounded read-only checks; ordinary page loads only recompute date-sensitive FX freshness. Checks follow the effective runtime configuration in every environment. A local email backend or explicitly disabled integration is grey. See [System Status checks](SYSTEM_STATUS.md) for what each result proves and how to interpret warnings.

> **Note about `.env.example.dev`:** That file is a **developer reference** for local `make dev` usage. For deployment, use `.env.example.prod` or `.env.example.staging`.

#### Management Commands

```bash
# Service status
systemctl status praho-platform praho-portal praho-qcluster

# View logs (live)
journalctl -u praho-platform -f
journalctl -u praho-portal -f
journalctl -u praho-qcluster -f

# Restart a service
sudo systemctl restart praho-platform

# Health check
/opt/praho/scripts/health-check.sh

# Manual backup
/opt/praho/scripts/backup.sh

# Restore from backup
/opt/praho/scripts/restore-platform.sh --latest
```

#### Redeployment

To redeploy (e.g., after code changes), run the same Make command again. The playbook is idempotent — it will rsync code, run migrations, collect static files, and restart services.

```bash
make deploy-staging   # or: make deploy-prod
```

To rebuild a server from scratch (e.g., after an OS upgrade):
```bash
# Hetzner example: rebuild the server image
hcloud server rebuild praho-staging --image ubuntu-26.04

# Wait for server to come up, then deploy
make deploy-staging
```

#### Tuning (Ansible Extra Variables)

Override defaults with `-e` flags:

| Variable | Default | Description |
|----------|---------|-------------|
| `gunicorn_workers_platform` | 2 | Platform Gunicorn workers |
| `gunicorn_workers_portal` | 2 | Portal Gunicorn workers |
| `gunicorn_worker_class_portal` | gthread | Portal worker class: `gthread`, or `sync` to roll back (ADR-0056) |
| `gunicorn_threads_portal` | 4 | Portal threads per worker (`gthread` only; `sync` always has one) |
| `platform_memory_max` | 1G | systemd memory limit (platform) |
| `portal_memory_max` | 512M | systemd memory limit (portal) |
| `deploy_method` | git | `git` (always for prod), or `DEPLOY_METHOD=rsync` in a dev/staging env file |
| `platform_allowed_ips` | `[]` | IP whitelist for Platform access |

Example: deploy production with 4 Gunicorn workers:
```bash
ansible-playbook -i inventory/native-single-server.yml \
  playbooks/native-single-server.yml \
  -e praho_env=prod \
  -e gunicorn_workers_platform=4 \
  -e gunicorn_workers_portal=3
```

#### Portal server settings

`services/portal/gunicorn.conf.py` owns the portal's gunicorn settings. The launchers pass only the bind address, because a command-line flag would override the config. Both launchers first run `python -m config.server_settings`, so a bad value stops startup before any migration runs. Set these environment variables:

| Variable | Default | Allowed |
|----------|---------|---------|
| `PORTAL_GUNICORN_WORKER_CLASS` | `gthread` | `gthread`, or `sync` to roll back |
| `PORTAL_GUNICORN_WORKERS` | 2 (native: `gunicorn_workers_portal`, 2) | 1-16 |
| `PORTAL_GUNICORN_THREADS` | 4 for `gthread` (native: `gunicorn_threads_portal`, 4); always 1 for `sync` | 1-32 |

Neither timeout is configurable:
- **Request timeout, 60 s, under `sync` only.** Under `gthread` the worker checks in with gunicorn while its requests run, so gunicorn never ends a slow request. Each Platform call is bounded by its budget (at most 45 s). A slow client is held by Caddy instead: the portal's `reverse_proxy` blocks read the whole request (a 6 MB buffer, above the 5 MB body cap) and up to 10 MiB of the response before passing them on (`request_buffers`, `response_buffers`), and a request body must arrive within 120 s (`read_body`, a server-wide setting, so it covers Platform's sites on the same Caddy too). Only a response larger than 10 MiB still streams to a slow reader through a portal thread.
  - **A body cut off at that limit** (or by a client that gave up) reaches the application short. Both services refuse it rather than process a partial request. The client sees 499 (HTTP/1.1, logged by Caddy at debug level) or 502 with an `i/o timeout` naming the upstream port (HTTP/2). That is a slow client, not a failing application.
- **Graceful shutdown, 50 s** (gunicorn's own default was 30 s). gunicorn stops accepting connections before it drains, so on a single portal container a restart refuses new requests until it is back, for up to 50 s while slow requests finish. Docker allows 55 s before it kills the container.

Access lines go to stdout on every deploy path. Each line is gunicorn's default line plus the request duration, the worker pid and the request id; the id is `-` on a response refused before the portal's request-id middleware ran, such as an early 429.

- **Bad values stop the portal.** A worker class or worker count outside those ranges stops the portal from starting. So does a thread count outside 1-32 under `gthread`; under `sync` the thread count is not read, so a rollback can leave it set.
- **No inline comments.** In a `.env` read by systemd, `#` comments are kept as part of the value, so `PORTAL_GUNICORN_WORKERS=2 # two` is refused.
- **`GUNICORN_CMD_ARGS` is refused.** gunicorn applies it over the config, and on native installs the `.env` is shared with the platform, so the platform's tuning would become the portal's. Use the variables above.
- **Precedence on native installs.** The unit sets these from the Ansible variables above, and the `.env` (`EnvironmentFile=`) overrides them. An empty value in the `.env` (`PORTAL_GUNICORN_WORKERS=`) still overrides, and means the code's default (2 workers), not the Ansible value.
- **Docker.** The compose files take them from `--env-file` (or the shell running `docker compose`); unset means the default.

**Upgrading from a release where the launchers passed these flags:**
- **Docker:** the portal no longer reads `GUNICORN_WORKERS`, which is the platform's setting. If you set it for the portal, set `PORTAL_GUNICORN_WORKERS` instead.
- **Native:** the Ansible variable `gunicorn_timeout_portal` is gone. If you had raised it, note that the portal now stops a request after 60 s under `sync` workers.

**Rollback to sync workers**, on any deploy path:
1. Set `PORTAL_GUNICORN_WORKER_CLASS=sync`. Threads then become 1 automatically: gunicorn would otherwise quietly keep `gthread` whenever threads > 1. Optionally raise `PORTAL_GUNICORN_WORKERS`.
   - native: in the `.env`. Re-running the playbook with `-e gunicorn_worker_class_portal=sync` works only when the `.env` does not set `PORTAL_GUNICORN_WORKER_CLASS`, since the `.env` wins;
   - Docker: in the env file passed with `--env-file`.
2. Restart:
   - native: `sudo systemctl restart praho-portal`;
   - Docker, from the repository root, with your stack file (`single-server`, `container-service` or `portal-only`):
     `PRAHO_ENV_FILE=$PWD/.env.prod docker compose --env-file .env.prod -f deploy/docker-compose.single-server.yml up -d portal`
3. Confirm the startup log line `Using worker: sync`:
   - native: `journalctl -u praho-portal | grep "Using worker"`;
   - Docker: `PRAHO_ENV_FILE=$PWD/.env.prod docker compose --env-file .env.prod -f deploy/docker-compose.single-server.yml logs portal | grep "Using worker"`.

**Caveats:**
- Ubuntu 26.04 LTS is the new-server baseline; existing Ubuntu 24.04 hosts remain supported
- Single-server only — no built-in horizontal scaling

---

### Option 2: Docker Single Server

Deploy Platform, its task worker, Portal, PostgreSQL, and Caddy in Docker containers on a single server. Best for teams already using Docker.

The task worker (`qcluster`, Django-Q) runs from the Platform image with Platform's environment and volumes, and starts once Platform is healthy, because Platform's container runs the migrations. It sends queued mail (password resets among them) and runs invoice, provisioning and scheduled jobs. Every Docker stack that includes Platform runs it: single-server, platform-only and container-service.

**Architecture:**
```
┌─────────────────────────────────────────────┐
│                  Server                      │
│  ┌─────────┐  ┌──────────┐  ┌──────────┐   │
│  │  Caddy  │──│ Platform │──│ Postgres │   │
│  │  :80    │  │  :8700   │  │  :5432   │   │
│  │  :443   │  └──────────┘  └──────────┘   │
│  │         │  ┌──────────┐                  │
│  │         │──│  Portal  │                  │
│  │         │  │  :8701   │                  │
│  └─────────┘  └──────────┘                  │
└─────────────────────────────────────────────┘
```

**Using the deploy script:**

The Docker deployments read the same env files as the native one: `.env.prod`, or `.env.staging` with `--env staging`. Never the repo-root `.env`, which is the development file; the script refuses it.

```bash
cp .env.example.prod .env.prod
# Fill in every [REQUIRED] value: DJANGO_SECRET_KEY, DB_PASSWORD, HMAC_SECRET and
# PLATFORM_API_SECRET (same value), PLATFORM_TO_PORTAL_WEBHOOK_SECRET, DJANGO_ENCRYPTION_KEY,
# CREDENTIAL_VAULT_MASTER_KEY, PORTAL_DOMAIN, PLATFORM_DOMAIN, ACME_EMAIL

./deploy/scripts/deploy.sh single-server --build      # or: make deploy-single-server
./deploy/scripts/deploy.sh single-server --env staging --build   # reads .env.staging
./deploy/scripts/deploy.sh single-server --stop       # or: make deploy-stop
```

The script passes the file to every Compose call and waits until the platform, portal and database report healthy and Caddy and the task worker, which have no healthcheck, are running (`up --wait`; Docker Compose v2 is required). A first boot migrates a fresh database before the platform reports healthy, which can take a few minutes. Health is read from the containers: the stack publishes only Caddy's ports 80 and 443.

To run Compose directly, pass the file twice: `--env-file` for `${VAR}` substitution, and `PRAHO_ENV_FILE` for the platform, which receives the whole file:

```bash
PRAHO_ENV_FILE=$PWD/.env.prod docker compose --env-file .env.prod -f deploy/docker-compose.single-server.yml up -d --wait
```

Export nothing else in that shell: a shell variable beats the env file in Compose's substitution.

> **Note:** Both native and Docker deployments use a two-domain architecture. Platform is never exposed on the portal domain.

---

### Option 3: Container Service

For managed container platforms like DigitalOcean App Platform, AWS ECS, or Google Cloud Run.

**Key Differences:**
- No database container (use managed PostgreSQL)
- No Caddy (platform handles SSL/routing)
- Images pushed to container registry

**Build and Push:**
```bash
# REGISTRY and VERSION name the images; set them in .env.prod (or export them)
./deploy/scripts/deploy.sh container-service --build

docker push ${REGISTRY}praho-platform:${VERSION}
docker push ${REGISTRY}praho-portal:${VERSION}
```

**Environment Variables for Container Service** (set them in the provider's settings; `deploy/docker-compose.container-service.yml` lists the same set):
```
DB_HOST, DB_NAME, DB_USER, DB_PASSWORD     # managed PostgreSQL
DJANGO_SECRET_KEY
PLATFORM_API_SECRET, PLATFORM_TO_PORTAL_WEBHOOK_SECRET
DJANGO_ENCRYPTION_KEY, CREDENTIAL_VAULT_MASTER_KEY   # platform, production settings
PLATFORM_DOMAIN, PORTAL_DOMAIN
PORTAL_TRUSTED_PROXY_CIDRS                 # the provider's load balancer range
PLATFORM_API_BASE_URL=https://platform.praho.example.com/api
PLATFORM_API_AUTH_MIN_DURATION_SECONDS     # optional, portal: login timing floor, default 1.0 (1 <= s <= 10)
MEDIA_STORAGE=s3, MEDIA_S3_BUCKET, MEDIA_S3_ACCESS_KEY_ID, MEDIA_S3_SECRET_ACCESS_KEY   # platform media
MEDIA_S3_ENDPOINT_URL, MEDIA_S3_REGION, MEDIA_S3_SERVER_SIDE_ENCRYPTION                # optional
```

**Media in a private bucket.** The platform and task-worker containers share no volume, and a
container's disk is lost when it is replaced, so media (invoice PDFs, e-Factura archives, ticket
attachments, GDPR exports) goes to an S3-compatible bucket with `MEDIA_STORAGE=s3` (ADR-0057). The
other deployment options keep the filesystem default. Django reads every file and returns it
itself; nothing links to the bucket. Set the bucket up as follows:

- **Private:** Block Public Access on, object ownership "bucket owner enforced" (ACLs disabled), no
  public bucket policy. PRAHO sends no ACLs.
- **Its own key:** an access key allowed only `s3:GetObject`, `s3:PutObject` and `s3:DeleteObject`
  on `<bucket>/media/*`, and `s3:ListBucket` on the bucket, limited to the `media/` prefix. Don't
  reuse the SES key.
- **Backup:** versioning on, with a lifecycle rule that expires noncurrent versions (30 days, like
  the dump retention). That rule also bounds how long a deleted file survives: GDPR erasure and
  export cleanup delete the current version only.
- **Encryption at rest:** the provider's default encryption, or `MEDIA_S3_SERVER_SIDE_ENCRYPTION`.
  GDPR exports are encrypted by PRAHO before upload as well.
  - `aws:kms` uses the account's AWS-managed `aws/s3` key; this setting cannot name a
    customer-managed key. The access key also needs `kms:GenerateDataKey` (uploads) and
    `kms:Decrypt` (reads) on that key unless its key policy already allows use through S3 for the
    account, as the `aws/s3` default policy does. Without them every media operation is `AccessDenied`.
- **TLS:** `MEDIA_S3_ENDPOINT_URL` must be `https://`. Leave it unset for AWS itself.

The platform refuses to start with `MEDIA_STORAGE=s3` and a missing bucket or key, rather than
falling back to the container's disk.

`PLATFORM_API_AUTH_MIN_DURATION_SECONDS` makes every portal login take at least that long, so the
time a failed login takes gives no sign of whether the email has an account. Production and
staging default to 1.0 s, which is also the lowest value accepted: the floor can be raised, not
lowered. The portal refuses to start on anything below 1, above 10, `nan` or `inf`. If the portal logs "A login took … longer than the … timing floor", raise it.

---

### Option 4: Docker Platform Only

Deploy just the Platform service (admin, API, business logic) and its task worker.

**Use Cases:**
- Portal runs on separate infrastructure
- API-only deployment
- Development/staging environments

```bash
# With the bundled database (the script sets DB_HOST=db and DB_SSLMODE=disable for it)
./deploy/scripts/deploy.sh platform-only --with-db --build

# With an external database: set DB_HOST, DB_NAME, DB_USER and DB_PASSWORD in .env.prod
# (DB_SSLMODE defaults to require)
./deploy/scripts/deploy.sh platform-only --build

# Full stack (DB + Caddy)
./deploy/scripts/deploy.sh platform-only --full --build
```

The platform-only and portal-only stacks publish the application port (8700, 8701) on `127.0.0.1` only.
Their Caddy reaches the app over the Docker network, and a proxy on the same host can use the loopback
port; publishing it wider would bypass Caddy's TLS and, for the platform, the `PLATFORM_ALLOWED_CIDRS`
allowlist. For an external load balancer, set `PLATFORM_BIND` / `PORTAL_BIND` (e.g. to a private
interface's address) in the env file.

---

### Option 5: Docker Portal Only

Deploy just the Portal service (customer-facing).

**Prerequisites:**
- Platform must be running and reachable at its public URL
- A portal host holds only what the portal stack uses. Never copy the full `.env.prod` there: it holds the
  platform's database password, encryption keys, payment and mail credentials and its Django secret key.
  `deploy.sh portal-only` refuses a file with anything else, naming the extra keys (never their values).

```bash
# On the machine that holds the full .env.prod: set the portal's own key and its public settings
#   PORTAL_DJANGO_SECRET_KEY=...   (openssl rand -base64 50; must differ from DJANGO_SECRET_KEY)
#   PLATFORM_API_BASE_URL=https://platform.praho.example.com/api
#   PORTAL_DOMAIN, PLATFORM_DOMAIN
#   PORTAL_TRUSTED_PROXY_CIDRS=10.200.250.0/24 (the stack's own network, where its Caddy or a proxy on
#   the host reaches the portal; PRAHO_WEB_SUBNET changes it, an external load balancer adds its range)
# then write the portal's file (mode 600; only the variables the portal stack uses)
./deploy/scripts/portal-env.sh --env prod          # writes .env.prod.portal
scp -p .env.prod.portal portal-host:/opt/praho/.env.prod

# On the portal host (one that already ran the portal stack: run --stop once first, so Compose
# recreates its network with the pinned subnet)
./deploy/scripts/deploy.sh portal-only --build
./deploy/scripts/deploy.sh portal-only --with-caddy --build   # with Caddy
```

---

### Option 6: Two Servers (Docker Compose split)

Platform + DB on primary server, Portal on secondary server. This is the layout Terraform provisions for
staging and production. Until the native role deploys two hosts, it is deployed by hand with the Compose
stacks of Options 4 and 5 (ADR-0054).

**Architecture:**
```
┌─────────────────────────┐     ┌─────────────────────────┐
│    Primary Server       │     │   Secondary Server      │
│  ┌─────────┐           │     │  ┌─────────┐           │
│  │  Caddy  │           │     │  │  Caddy  │           │
│  │  :443   │           │     │  │  :443   │           │
│  └────┬────┘           │     │  └────┬────┘           │
│       │                │     │       │                │
│  ┌────▼────┐           │     │  ┌────▼────┐           │
│  │Platform │           │     │  │ Portal  │───────────┼──▶ Platform API
│  │ :8700   │           │     │  │ :8701   │           │
│  └────┬────┘           │     │  └─────────┘           │
│       │                │     │                         │
│  ┌────▼────┐           │     │                         │
│  │Postgres │           │     │                         │
│  │ :5432   │           │     │                         │
│  └─────────┘           │     │                         │
└─────────────────────────┘     └─────────────────────────┘
```

**Deploying it:**
```bash
# Where the full .env.prod lives, with PORTAL_DJANGO_SECRET_KEY, PORTAL_DOMAIN, PLATFORM_DOMAIN,
# PLATFORM_API_BASE_URL=https://<platform domain>/api and PORTAL_TRUSTED_PROXY_CIDRS=10.200.250.0/24
# (the portal stack's own network, where its Caddy runs; PRAHO_WEB_SUBNET changes it) set:
./deploy/scripts/portal-env.sh --env prod        # writes .env.prod.portal: only what the portal uses

# Platform server: the full file (its checkout's .env.prod), then
./deploy/scripts/deploy.sh platform-only --full --build

# Portal server: only .env.prod.portal, copied as its checkout's .env.prod, then
./deploy/scripts/deploy.sh portal-only --with-caddy --build
```

The portal reaches the platform at `https://<platform domain>/api` through the platform server's Caddy,
where `/api/*` is public and Django's HMAC check guards it. Database restore supports the local bundled
`praho_db` on a single-server or platform-only host and restarts only its existing local application
containers. It does not operate the remote portal or an external database. `rollback.sh` still assumes
the single-server stack: on a split deployment, redeploy an earlier `VERSION` on each server.

---

## Database Operations

### Creating Backups

```bash
# Using script
./deploy/scripts/backup.sh

# Using make
make backup

# List existing backups
./deploy/scripts/backup.sh --list

# Native deployment (on the server)
/opt/praho/scripts/backup.sh

# Native deployment, from your machine: back up, then download that dump to ~/praho-backups
make ansible-backup ENV=prod FETCH=true    # reads .env.prod, like make deploy-prod
# or, directly, with that file's PRAHO_SERVER_IP and SSH settings exported
cd deploy/ansible && ansible-playbook -i inventory/native-single-server.yml playbooks/backup.yml \
  -e fetch_backup=true    # -e backup_fetch_dir=PATH to choose another directory
```

Docker backups are stored in `./backups/` as `praho_backup_YYYYMMDD_HHMMSS_<pid>.sql.gz`; native ones
in `/opt/praho/backups/` as `praho_backup_YYYYMMDD_HHMMSS_<pid>.dump` (`pg_dump` custom format). The
process id keeps two backups started in the same second apart. Both scripts write the dump under a
`.partial` name and rename it once it is complete, so a failed backup never becomes the one
`restore --latest` picks; each backup first removes a partial a killed run left once it has been
untouched for a day. A downloaded dump gets mode `0600` in a `0700` directory, and git ignores
`praho_backup_*` anywhere in the checkout.

Each backup also archives the media directory (`MEDIA_ROOT`) next to its dump, as
`praho_backup_YYYYMMDD_HHMMSS_<pid>.media.tar.gz`.
- **What it holds:** what the database cannot rebuild, including ANAF's e-Factura response archives, issued invoice PDFs, ticket attachments and GDPR exports.
- **Where it comes from:** in Docker, the `media_files` volume (`MEDIA_ROOT=/app/media`); natively, `/opt/praho/media`.
- **Restoring:** a restore unpacks the archive with the same name as its dump into the media directory, keeping files the archive does not hold. A dump with no archive (one made before this change) restores the database only.
- **Retention:** expires an archive with its dump.
- **A failed archive** fails the backup run, but keeps the complete dump.
- **Downloads:** `make ansible-backup FETCH=true` downloads the dump only; copy the media archive from the server's backup directory when you need it.
- **With `MEDIA_STORAGE=s3`** the media directory is empty, and the bucket's versioning is the media backup (Option 3).
- **Not encrypted:** backups are plain files; see "Known gap — backups are not encrypted" in `docs/security/SECURITY_COMPLIANCE_ASSESSMENT.md` before storing them anywhere shared.

### Restoring from Backup

```bash
# Interactive (choose from list)
./deploy/scripts/restore-platform.sh

# Restore specific file
./deploy/scripts/restore-platform.sh ./backups/praho_backup_20240115_120000_4242.sql.gz

# Restore latest backup
./deploy/scripts/restore-platform.sh --latest

# Docker staging: the scripts read .env.prod unless told otherwise
./deploy/scripts/restore-platform.sh --latest --env staging

# Using make (DEPLOY_ENV=staging for staging)
make restore

# Native deployment
/opt/praho/scripts/restore-platform.sh --latest
```

Docker restore privately stages the selected dump and companion media archive before creating its
safety backup, so retention cannot remove the input during the restore. It checks compression, the
plain `pg_dump` envelope and tar integrity before stopping services; these checks do not prove SQL
compatibility with the target database. A failed safety backup aborts before downtime. SQL errors stop
the restore and leave applications offline for recovery using the safety backup. Restart failures are
reported without creating containers from a different deployment topology.

Every restore pauses the daily orphaned-media sweep for seven days, before any worker starts. Files
written since the backup (ticket attachments, GDPR exports) have no row in the restored database,
and the sweep would otherwise delete them a day later. Reconcile them within the seven days, or move
`media_sweep.paused_until` in Settings further out. A backup taken before the sweep existed has no
such setting; the restore creates it. If the pause cannot be written, the restore stops with the
applications offline.

Run the offline recovery contracts with `make test-deploy`. `make test-deploy-docker` runs the
disposable Caddy acceptance tests and requires a working Docker daemon.

### Backup Retention

Backups older than 30 days are automatically deleted. Configure with:

```bash
export RETENTION_DAYS=60
./deploy/scripts/backup.sh
```

### Scheduled Backups

Ansible automatically sets up a cron job for daily backups at 2:00 AM. Manual setup:

```bash
# Add to crontab
0 2 * * * /opt/praho/scripts/backup.sh >> /opt/praho/logs/backup.log 2>&1
```

---

## Rollback Procedures

### Version Rollback

Roll back to a specific image version. The tag applies to that run only (the env file is not edited), so a later `deploy.sh` run goes back to the `VERSION` in the env file:

```bash
# Using script (add --env staging for a staging host)
./deploy/scripts/rollback.sh version v1.2.3

# Using make
make rollback VERSION=v1.2.3
```

**Native installs rolling back past the log rotation change** (releases before Platform and the portal stopped rotating their own log files): remove `/etc/logrotate.d/praho-platform` and `/etc/logrotate.d/praho-portal` first. The older release rotates those files in process again, and logrotate moving them as well would race it. The next deploy of a current release installs them again.

### PostgreSQL version and existing data

Fresh bundled/native installations use PostgreSQL 16. Existing 15 data requires an explicit
[migration procedure](POSTGRESQL_16_UPGRADE.md); preflight refuses an implicit image or cluster-major
replacement before startup. Docker preflight uses Python 3.9+ and a read-only volume inspection.

### Backup recovery metadata

Docker `backup.sh` also writes a mode-0600 `.metadata.json` beside each completed database/media
pair. It records SHA-256 checksums, PostgreSQL major version and immutable source application image
IDs/references, without environment secrets. Keep all three files together. The operator host needs
Python 3.9+ for this stdlib-only metadata helper. A metadata failure is reported as a failed backup
run while retaining the completed dump/media for manual recovery. Existing legacy pairs remain
restorable; metadata does not change their format or prove cross-release schema compatibility.

### Database Rollback

Restore the latest database backup:

```bash
# Using script
./deploy/scripts/rollback.sh database

# Using make
make rollback-db
```

### Full Rollback

Use `make rollback-full VERSION=v1.2.3 BACKUP=/private/backups/praho_backup_SELECTED.sql.gz`
(`DEPLOY_TYPE=platform-only` on a platform-only host, `DEPLOY_ENV=staging` for staging).
The matching media archive and metadata must accompany that explicit dump. The command verifies
both checksums, PostgreSQL major and immutable target application image IDs before downtime.
Missing targets are pulled and checked first. A newest timestamp or tag name alone never establishes
compatibility. Legacy backups remain usable with standalone restore and manual operator planning.

After confirmation, restore takes a mandatory safety backup and leaves all local writers stopped.
Only then does Compose start the selected old images with the same local topology. The current
application entrypoint never runs against the restored old database. SQL/media or target readiness
failures require operator recovery; no automatic data rollback runs. A platform-only host creates
no Portal; coordinate any remote Portal release separately. Reserve disk space for private staging
and the safety backup. The env file is not edited, so a later deploy still uses its configured version.

### Rollback on a native server

```bash
# Redeploy an earlier tag
make deploy-prod VERSION=v1.2.3

# Restore the latest database backup (on the server)
/opt/praho/scripts/restore-platform.sh --latest
```

---

## Terraform validation and state recovery

`make infra-validate` checks formatting and validates with the committed provider lock, a temporary
plugin cache and backend initialization disabled. It makes no plan/apply or backend migration.
Keep environment workspaces and private state backups according to the
[state recovery runbook](TERRAFORM_STATE_RECOVERY.md) before operating infrastructure.

## Makefile Commands

| Command | Description |
|---------|-------------|
| `make deploy-staging` | Deploy to staging (reads `.env.staging`) |
| `make deploy-prod` | Deploy to production (reads `.env.prod`) |
| `make deploy-dev-native` | Deploy to dev (native) |
| `make deploy-single-server` | Docker single server (reads `.env.prod`; `DEPLOY_ENV=staging` reads `.env.staging`) |
| `make deploy-stop` | Stop a Docker deployment (`DEPLOY_TYPE=single-server` by default) |
| `make deploy-status` | Show deployment status |
| `make deploy-logs` | Follow a Docker deployment's logs (`DEPLOY_TYPE`, `DEPLOY_ENV` as above) |
| `make backup` | Create database backup |
| `make restore` | Restore from backup (interactive) |
| `make rollback VERSION=X` | Roll back to version X |
| `make rollback-db` | Restore latest database backup |
| `make health-check` | Check service health |

---

## Environment Variables

### Native Deployment (Ansible)

The native inventory deploys the complete single-server stack. The common role controls firewall
ports, and Django controls worker configuration; inventory flags and role defaults do not disable
individual services or tune qcluster. Worker startup is separate from proving queued work executes.

All variables live in your `.env.{env}` file. See `.env.example.prod` for the full list with descriptions. Key required variables:

| Variable | Description | Example |
|----------|-------------|---------|
| `PRAHO_SERVER_IP` | Server public IP | `203.0.113.10` |
| `PORTAL_DOMAIN` | Customer-facing FQDN; customer email links point at `https://` and this domain unless staff set Settings → Customer portal URL | `portal.example.com` |
| `PLATFORM_DOMAIN` | Staff/admin FQDN | `platform.example.com` |
| `DJANGO_SECRET_KEY` | Django secret key | `openssl rand -base64 50` |
| `DJANGO_ENCRYPTION_KEY` | AES-256-GCM key for 2FA secrets and sensitive fields; production refuses to start without it | `python -c "import secrets, base64; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())"` |
| `CREDENTIAL_VAULT_MASTER_KEY` | Credential vault key; production refuses to start without it | same command, a different key |
| `DB_PASSWORD` | PostgreSQL password | `openssl rand -base64 32` |
| `HMAC_SECRET` | Portal ↔ Platform HMAC auth | `openssl rand -base64 32` |
| `PLATFORM_TO_PORTAL_WEBHOOK_SECRET` | Platform→Portal webhook HMAC | `python -c "import secrets; print(secrets.token_urlsafe(32))"` |
| `COMPANY_NAME`, `COMPANY_CUI` | The seller on every invoice; production refuses to start without them | `Example Hosting SRL`, `RO12345674` |
| `COMPANY_COUNTRY_CODE` | ISO code of the EU country the seller is established in. It decides which Romanian features apply (ADR-0047) and the home currency (ADR-0041); production refuses to start without it | `RO`, `DE` |
| `TIME_ZONE` | The operator's clock for billing periods, document dates and reports. Empty means `Europe/Bucharest`, the only zone allowed in Romania; any other operator must set it | `Europe/Berlin` |
| `BRAND_DIR` | Optional folder with `logo.svg`, `favicon.svg`, `brand.css` replacing PRAHO's marks (ADR-0062) | `/opt/praho/brand` |
| `ACME_EMAIL` | Let's Encrypt email | `admin@example.com` |

### Docker Deployment (Compose)

The same `.env.prod` / `.env.staging` file, passed by `deploy/scripts/deploy.sh`. Each compose file's header lists every variable it requires; for `single-server`:

| Variable | Required | Description | Example |
|----------|----------|-------------|---------|
| `PORTAL_DOMAIN` | Yes | Customer-facing domain | `portal.example.com` |
| `PLATFORM_DOMAIN` | Yes | Staff/admin domain | `platform.example.com` |
| `DB_PASSWORD` | Yes | PostgreSQL password | `openssl rand -base64 32` |
| `DJANGO_SECRET_KEY` | Yes | Django secret key | `openssl rand -base64 50` |
| `PLATFORM_API_SECRET` | Yes | Portal ↔ Platform HMAC (same value as `HMAC_SECRET`) | `openssl rand -base64 32` |
| `PLATFORM_TO_PORTAL_WEBHOOK_SECRET` | Yes | Platform→Portal webhook HMAC | `python -c "import secrets; print(secrets.token_urlsafe(32))"` |
| `PORTAL_DJANGO_SECRET_KEY` | portal-only | The portal's own Django key (single-server uses it when set, else `DJANGO_SECRET_KEY`) | `openssl rand -base64 50` |
| `DJANGO_ENCRYPTION_KEY`, `CREDENTIAL_VAULT_MASTER_KEY`, `COMPANY_NAME`, `COMPANY_CUI`, `COMPANY_COUNTRY_CODE` | Production | Checked by `deploy.sh` before Compose runs | see the native table |
| `TIME_ZONE` | Outside Romania | Passed to both services; production settings enforce it | see the native table |
| `BRAND_DIR` | No | Host folder mounted read-only at `/app/brand` for the platform and portal (`deploy/brand/`, empty, when unset) | `/srv/praho-brand` |
| `ACME_EMAIL` | Yes | Let's Encrypt email | `admin@example.com` |
| `VERSION` | No | Image tag (default `latest`) | `v1.2.3` |

### Brand folder

`BRAND_DIR` names a folder holding any of `logo.svg` (drawn for PRAHO's dark screens), `favicon.svg`, `favicon.ico`, `apple-touch-icon.png` and `brand.css`; each file present replaces PRAHO's own (ADR-0062). In `brand.css`, `--color-primary-50` to `--color-primary-950` recolour the portal's accent and `--color-slate-*` its neutrals. Native installs read it from the env file. The Compose stacks mount it read-only at `/app/brand` (an empty `deploy/brand/` when unset). On a container platform without bind mounts, build a derived image: `COPY brand /app/brand` and `ENV BRAND_DIR=/app/brand`; collectstatic runs in the entrypoint, so the files are published at start.

### Legal documents

PRAHO ships no legal text. After the first deploy, an administrator publishes the Terms of Service, Privacy Policy and Cookie Policy under Settings → Legal documents; until Terms of Service are in force, nobody can register. See [LEGAL_DOCUMENTS.md](LEGAL_DOCUMENTS.md).

### Security Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `platform_allowed_ips` | IP whitelist for Platform access (Ansible extra-var) | loopback only; an empty list also means loopback only, never unrestricted |
| `HMAC_SECRET` | HMAC shared secret for Portal ↔ Platform auth | (required in `.env`) |
| `PLATFORM_TO_PORTAL_WEBHOOK_SECRET` | HMAC secret for Platform→Portal webhooks | (required in `.env`) |

### Portal-Specific Variables

Native Portal identity upgrade (planned maintenance, existing hosts):

1. Take and verify a private backup of the Portal SQLite session/counter store and logs. Record the
   configured `SESSION_DB_PATH`; the previous default was `/opt/praho/src/services/portal/portal.sqlite3`.
2. Stop `praho-portal` and disable its counter-cull cron job while moving state. Ensure no Portal
   process is writing; checkpoint SQLite WAL with the matching SQLite tool before moving the database,
   and retain any WAL/SHM sidecars with the safety copy. Do not start with an empty database by accident.
3. Create the system account/group `praho-portal` (nologin, no shared supplementary groups). Create
   `/var/lib/praho-portal` and `/var/log/praho/portal` owned by that account with mode 0700. Move the
   existing database to `/var/lib/praho-portal/portal.sqlite3`, set ownership to `praho-portal:praho-portal`
   and mode 0600, and migrate existing Portal log ownership while stopped. Inspect symlinks before
   changing individual files; do not recursively chown the application tree or Platform credentials.
4. Set `SESSION_DB_PATH=/var/lib/praho-portal/portal.sqlite3` and a distinct
   `PORTAL_DJANGO_SECRET_KEY` in the operator configuration. The key change invalidates old sessions;
   preserving the counter database retains replay/idempotency history. Deploy normally. Preflight
   refuses a legacy session path or log/database files still owned by the shared identity.
5. Verify Portal can create sessions/counters and write its logs, and that it cannot read Platform's
   `.env`, credential passfile or media, or write the source/venv. Verify Platform, worker and Caddy
   health separately. Retain the safety copy privately until the maintenance is accepted.

Fresh hosts use the private directories automatically. Portal's source and collected static files
remain readable and owned by the deployment account, and systemd permits Portal writes only in its
state/log directories. No live account, ownership or session migration is performed by this change.

Native Portal uses `/opt/praho/.portal.env`, generated from the same filtered values used for
its migrations and static collection. It contains Portal API credentials and its own
`PORTAL_DJANGO_SECRET_KEY` (mapped to Django's `DJANGO_SECRET_KEY`), but excludes the Platform
DB password, encryption key and vault key. Set a nonempty Portal key distinct from the Platform
key before upgrading; replacing the previously shared key invalidates existing Portal sessions.
Keep `STATIC_ROOT=/opt/praho/static` for Platform: Portal always uses `/opt/praho/portal-static`,
which is also Caddy's Portal static root. Both staging and production use this contract.
The existing shared OS identity still allows access to Platform-owned files; the separate Portal
identity migration must be completed before treating this as filesystem isolation.

These are set in the `.env` file and used by the Portal service:

| Variable | Description | Required When |
|----------|-------------|---------------|
| `PLATFORM_API_BASE_URL` | Platform API URL | Portal-only deployment |
| `PLATFORM_API_SECRET` | HMAC secret for portal auth | Always (defaults to `HMAC_SECRET`) |
| `PLATFORM_API_ALLOW_INSECURE_HTTP` | Allow HTTP for internal comms | Docker/native (HTTP internal) |

---

## Troubleshooting

### Check Service Health

`make docker-dev` starts the development task worker only after Platform migrations, setup and its
HTTP health check finish. It shares Platform's dev image, database, source and media; it has no HTTP
health probe. A running worker is not evidence that a queued task executed.

For Docker hosts, run `deploy/scripts/health-check.sh single-server`, `platform-only`, `portal-only`
or `container-service` for the local topology. Split hosts omit remote services. Use `--with-db`
when a platform-only host includes the bundled database and `--with-caddy` when its optional Caddy
must be present; `--without-caddy` selects an external edge. An optional Caddy that exists is still
checked. Missing/unknown/starting/unhealthy state or Docker inspection errors fail the check.
Set `PLATFORM_URL` and/or `PORTAL_URL` to additionally test public routes with bounded HTTP probes.

```bash
# Using script
./deploy/scripts/health-check.sh

# Using make
make health-check

# Docker: single-server publishes only Caddy's 80/443, and the split stacks publish the app on
# 127.0.0.1 only, so read container health or probe the public routes
docker inspect --format '{{.State.Health.Status}}' praho_platform praho_portal
PLATFORM_URL=https://platform.example.com PORTAL_URL=https://portal.example.com ./deploy/scripts/health-check.sh

# Native deployment
curl http://localhost:8700/api/users/health/
curl http://localhost:8701/
/opt/praho/scripts/health-check.sh
systemctl status praho-platform praho-portal praho-qcluster
```

### View Logs

```bash
# Docker: all services (add --env staging for a staging host)
./deploy/scripts/deploy.sh single-server --logs

# Docker: specific service
docker logs praho_platform -f
docker logs praho_portal -f
docker logs praho_db -f

# Native: systemd journal
journalctl -u praho-platform -f
journalctl -u praho-portal -f
journalctl -u praho-qcluster -f

# Native: the portal's JSON log files (rotated daily by /etc/logrotate.d/praho-portal)
tail -F /var/log/praho/portal/app.log /var/log/praho/portal/error.log

# Native: Platform's JSON log files (rotated by /etc/logrotate.d/praho-platform)
tail -F /var/log/praho/app.log /var/log/praho/security.log /var/log/praho/audit.log /var/log/praho/error.log

# Using make
make deploy-logs
```

**Portal log files.** The portal always logs to the console (journald, `docker logs`). When `PORTAL_LOG_DIR` names a directory (native default: `/var/log/praho/portal`), it also writes `app.log` and `error.log` there. Several portal processes write those files, so the portal never rotates them itself: it reopens a file once logrotate has moved it. The native role installs the policy (daily, 14 kept, sooner once past 50 MB) and runs logrotate hourly. On native installs keep the default directory: the unit's writable paths and the rotation policy cover only `/var/log/praho/portal`. The Docker image sets `PORTAL_LOG_DIR` empty, so containers log to the console only (`docker logs`). If you set it in Docker, rotate the files yourself.

**Platform log files** work the same way. The gunicorn workers and the qcluster workers all write `app.log`, `security.log`, `audit.log` and `error.log` in `PLATFORM_LOG_DIR` (native default `/var/log/praho`), and Platform never rotates them itself. The native role's policy keeps 10 rotated files of `app.log`, 30 of `security.log` and `error.log`, and 90 of `audit.log`, the counts the in-process rotation kept. Each is rotated daily, or within the hour once past 50 MB (100 MB for the audit log), so a busy file's history can be shorter than that many days; the audit trail itself is in the database, and this file is its copy. On native installs keep the default directory: the units' writable paths and the rotation policy cover only `/var/log/praho`. On the first deploy, backups left by the old in-process rotation are compressed and handed over to logrotate, and the portal's beyond its 14 are removed. The Docker image sets `PLATFORM_LOG_DIR` empty, so the container logs to the console only.

### Common Issues

**1. Database connection failed**
```bash
# Docker
docker ps | grep praho_db
docker logs praho_db

# Native
systemctl status postgresql
journalctl -u postgresql -n 50

# Verify DB_HOST, DB_NAME, DB_USER and DB_PASSWORD in the env file
```

**2. SSL/HTTPS not working**
```bash
# Docker
docker logs praho_caddy

# Native
journalctl -u caddy -f

# Verify domain DNS is correct
dig portal.example.com
dig platform.example.com

# Check if ports 80/443 are open
sudo ufw status
```

**3. Portal can't connect to Platform**

This usually means `HMAC_SECRET` or `PLATFORM_TO_PORTAL_WEBHOOK_SECRET` is missing or mismatched between services.

```bash
# Check HMAC secrets are set in the .env
grep HMAC_SECRET /opt/praho/.env
grep PLATFORM_TO_PORTAL_WEBHOOK_SECRET /opt/praho/.env

# Verify Platform is responding
curl http://localhost:8700/api/users/health/

# Check Portal logs for auth errors
journalctl -u praho-portal --since "5 minutes ago" | grep -i hmac
```

**4. Health checks failing**
```bash
# Docker
docker ps -a
docker restart praho_platform

# Native
systemctl restart praho-platform
journalctl -u praho-platform --since "5 minutes ago"
```

### Emergency Procedures

**Quick rollback to last known good state:**
```bash
# 1. Stop current services
make deploy-stop                    # Docker
sudo systemctl stop praho-platform praho-portal praho-qcluster  # Native

# 2. Restore database
make rollback-db

# 3. Deploy previous version
make rollback VERSION=v1.0.0        # Docker
# Native: re-run Ansible with previous git tag
```

**Complete reset (Docker):**
```bash
# Stop and remove all containers and volumes (the database too)
PRAHO_ENV_FILE=$PWD/.env.prod docker compose --env-file .env.prod -f deploy/docker-compose.single-server.yml down -v

# Redeploy fresh
make deploy-single-server
```

---

## File Structure

```
# Environment files (project root — single source of truth)
.env.example.dev          # Developer reference for local make dev
.env.example.staging      # Staging deployment template
.env.example.prod         # Production deployment template
.env.staging              # Your staging secrets (git-ignored)
.env.prod                 # Your production secrets (git-ignored)

deploy/
├── docker-compose.single-server.yml   # Docker: all services on one server
├── docker-compose.container-service.yml # For managed platforms
├── docker-compose.platform-only.yml   # Platform service only
├── docker-compose.portal-only.yml     # Portal service only
├── docker-compose.dev.yml             # Development environment
├── caddy/
│   ├── Caddyfile                      # Full stack configuration
│   ├── Caddyfile.platform             # Platform-only config
│   └── Caddyfile.portal               # Portal-only config
├── platform/
│   └── Dockerfile                     # Platform Docker image
├── portal/
│   └── Dockerfile                     # Portal Docker image
├── scripts/
│   ├── deploy.sh                      # Main deployment script
│   ├── backup.sh                      # Database backup
│   ├── restore-platform.sh                     # Database restore
│   ├── rollback.sh                    # Version/DB rollback
│   ├── health-check.sh               # Health check script
│   ├── portal-env.sh                  # Writes a portal host's env file from the full one
│   └── lib/compose.sh                 # Passes the env file to every Compose call
└── ansible/
    ├── inventory/
    │   ├── native-single-server.yml   # Unified native inventory (staging + prod)
    │   └── dev.yml                    # Remote dev box (make deploy-dev-native)
    ├── group_vars/
    │   └── all.yml                    # Ansible-only vars (ports, paths, tuning)
    ├── playbooks/
    │   ├── native-single-server.yml   # Native deploy (no Docker) — the main playbook
    │   └── backup.yml                 # Backup playbook
    └── roles/
        ├── common/                    # Base server setup (UFW, swap, users)
        └── praho-native/              # Native deployment (systemd + Gunicorn)
            ├── defaults/main.yml      # Tunable variables
            ├── handlers/main.yml      # Service restart handlers
            ├── tasks/main.yml         # 11-step deployment (validates + copies .env)
            └── templates/             # systemd units, Caddyfile, backup/restore scripts
```

Native recovery stages the selected custom dump and optional companion media privately before the
safety backup can apply retention. It reads the TOC and renders every dump data block to a discarded
SQL stream without connecting; corrupt/truncated/empty inputs stop before downtime. This is an
integrity check, not proof of application-schema compatibility. Use trusted backup pairs selected
for the intended application release. Recovery supports the bundled local PostgreSQL on port 5432.
The pre-restore backup and stopping all writers are mandatory. SQL errors leave services stopped;
failed starts or bounded readiness checks stop them again. Inspect the failure and safety backup
before explicitly restarting. A running worker service still requires a separate queue execution
check. The script does not roll back a partially restored database automatically.
