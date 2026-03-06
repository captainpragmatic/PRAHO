# PRAHO Deployment Guide

This guide covers all deployment scenarios for PRAHO, from native single-server setups to multi-server distributed deployments.

## Table of Contents

- [Choosing a Deployment Method](#choosing-a-deployment-method)
- [Deployment Options](#deployment-options)
  - [Option 1: Native Single Server](#option-1-native-single-server)
  - [Option 2: Docker Single Server](#option-2-docker-single-server)
  - [Option 3: Container Service](#option-3-container-service)
  - [Option 4: Docker Platform Only](#option-4-docker-platform-only)
  - [Option 5: Docker Portal Only](#option-5-docker-portal-only)
  - [Option 6: Two Servers (Distributed)](#option-6-two-servers-distributed)
- [Database Operations](#database-operations)
- [Rollback Procedures](#rollback-procedures)
- [Makefile Commands](#makefile-commands)
- [Environment Variables](#environment-variables)
- [Troubleshooting](#troubleshooting)

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
| **Portal** (customer-facing) | `portal.pragmatichost.com` | Public |
| **Platform** (staff/admin) | `platform.pragmatichost.com` | IP-restricted (optional) |
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
- PostgreSQL 15 (from official APT repo)
- Python 3.13 (from deadsnakes PPA)
- uv (Python package manager)
- Caddy (automatic HTTPS via Let's Encrypt)
- 3 systemd services: `praho-platform`, `praho-portal`, `praho-qcluster`
- Backup cron job (daily at 2:00 AM)

#### Prerequisites

1. **Ubuntu 24.04 LTS** server
2. **Ansible** installed on your local machine
3. **Two DNS A records** pointing to the server IP — both must resolve before deploying (Caddy ACME will fail without them)
4. **SSH access** to the server as root (or a user with passwordless sudo)

```bash
# Install Ansible and required collections
pip install ansible
ansible-galaxy collection install community.postgresql community.general ansible.posix
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
- **HSTS**: 1 hour instead of 1 year (allows rolling back to HTTP)
- **Sessions**: longer lifetime, no browser-close expiry (more lenient for testing)
- **Logging**: DEBUG level with smaller log files

See the docstrings in `services/platform/config/settings/staging.py` and `services/portal/config/settings/staging.py` for the full list.

#### Required Environment Variables

These are the `[REQUIRED]` variables in the `.env.example.*` files — PRAHO won't deploy without them:

| Variable | Description | Example |
|----------|-------------|---------|
| `PRAHO_SERVER_IP` | Server public IP address | `203.0.113.10` |
| `PORTAL_DOMAIN` | Customer-facing FQDN | `portal.pragmatichost.com` |
| `PLATFORM_DOMAIN` | Staff/admin FQDN | `platform.pragmatichost.com` |
| `ACME_EMAIL` | Let's Encrypt notification email | `admin@pragmatichost.com` |
| `SECRET_KEY` | Django secret key | `openssl rand -base64 50` |
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
3. The `.env.{praho_env}` file exists and contains all required variables (`SECRET_KEY`, `DB_PASSWORD`, `HMAC_SECRET`, `PLATFORM_TO_PORTAL_WEBHOOK_SECRET`, `PORTAL_DOMAIN`, `PLATFORM_DOMAIN`)
4. Both FQDNs resolve to the server IP (DNS pre-flight)

#### Post-Deploy

After deployment completes, the playbook verifies all services over HTTP and HTTPS.

**Step 3: Create the first admin user:**

The database starts empty — no users exist. Create a superuser on the server:

```bash
# SSH to the server and create the admin user interactively
ssh root@<server-ip>
cd /opt/praho/src
sudo -u praho bash -c 'set -a && source /opt/praho/.env && set +a && \
  source /opt/praho/.venv/bin/activate && \
  python services/platform/manage.py createsuperuser --email admin@pragmatichost.com'
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

**System Status Dashboard:** After deployment, the Platform dashboard shows real-time status of all integrations (green/amber/red/grey). Staging automatically shows "Not required" (grey) for features that staging settings override (email, Stripe, e-Factura).

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
/opt/praho/scripts/restore.sh --latest
```

#### Redeployment

To redeploy (e.g., after code changes), run the same Make command again. The playbook is idempotent — it will rsync code, run migrations, collect static files, and restart services.

```bash
make deploy-staging   # or: make deploy-prod
```

To rebuild a server from scratch (e.g., after an OS upgrade):
```bash
# Hetzner example: rebuild the server image
hcloud server rebuild praho-staging --image ubuntu-24.04

# Wait for server to come up, then deploy
make deploy-staging
```

#### Tuning (Ansible Extra Variables)

Override defaults with `-e` flags:

| Variable | Default | Description |
|----------|---------|-------------|
| `gunicorn_workers_platform` | 2 | Platform Gunicorn workers |
| `gunicorn_workers_portal` | 1 | Portal Gunicorn workers |
| `qcluster_workers` | 2 | Django-Q2 background workers |
| `platform_memory_max` | 1G | systemd memory limit (platform) |
| `portal_memory_max` | 512M | systemd memory limit (portal) |
| `deploy_method` | rsync | `rsync` (dev/staging) or `git` (prod) |
| `platform_allowed_ips` | `[]` | IP whitelist for Platform access |

Example: deploy production with 4 Gunicorn workers:
```bash
ansible-playbook -i inventory/native-single-server.yml \
  playbooks/native-single-server.yml \
  -e praho_env=prod \
  -e gunicorn_workers_platform=4 \
  -e gunicorn_workers_portal=2
```

**Caveats:**
- Ubuntu 24.04 LTS only (relies on deadsnakes PPA for Python 3.13)
- Single-server only — no built-in horizontal scaling

---

### Option 2: Docker Single Server

Deploy Platform, Portal, PostgreSQL, and Caddy in Docker containers on a single server. Best for teams already using Docker.

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

**Using Docker Compose:**
```bash
# Set environment variables
export PRAHO_PORTAL_DOMAIN=portal.pragmatichost.com
export PRAHO_PLATFORM_DOMAIN=platform.pragmatichost.com
export DB_PASSWORD=your-secure-password
export SECRET_KEY=your-django-secret-key
export ACME_EMAIL=admin@example.com

# Deploy
docker compose -f deploy/docker-compose.single-server.yml up -d

# Or use the deploy script
./deploy/scripts/deploy.sh single-server --build --migrate
```

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
# Set registry
export REGISTRY=registry.digitalocean.com/your-registry/
export VERSION=v1.0.0

# Build images
docker compose -f deploy/docker-compose.container-service.yml build

# Push to registry
docker push ${REGISTRY}praho-platform:${VERSION}
docker push ${REGISTRY}praho-portal:${VERSION}
```

**Environment Variables for Container Service:**
```
DATABASE_URL=postgresql://user:pass@db-host:5432/praho
SECRET_KEY=your-secret-key
DOMAIN=praho.example.com
PLATFORM_API_BASE_URL=https://platform.praho.example.com/api
```

---

### Option 4: Docker Platform Only

Deploy just the Platform service (admin, API, business logic).

**Use Cases:**
- Portal runs on separate infrastructure
- API-only deployment
- Development/staging environments

```bash
# With local database
docker compose -f deploy/docker-compose.platform-only.yml --profile with-db up -d

# With external database
export DATABASE_URL=postgresql://user:pass@db-host:5432/praho
docker compose -f deploy/docker-compose.platform-only.yml up -d

# Full stack (DB + Caddy)
docker compose -f deploy/docker-compose.platform-only.yml --profile full up -d
```

---

### Option 5: Docker Portal Only

Deploy just the Portal service (customer-facing).

**Prerequisites:**
- Platform must be running and accessible
- PLATFORM_API_BASE_URL must be set

```bash
# Set Platform API URL
export PLATFORM_API_BASE_URL=https://platform.praho.example.com/api
export SECRET_KEY=your-secret-key
export DOMAIN=portal.praho.example.com

# Deploy
docker compose -f deploy/docker-compose.portal-only.yml up -d

# With Caddy
docker compose -f deploy/docker-compose.portal-only.yml --profile with-caddy up -d
```

---

### Option 6: Two Servers (Distributed)

Platform + DB on primary server, Portal on secondary server.

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

**Using Ansible:**
```bash
# Set environment variables
export PRAHO_PLATFORM_IP=10.0.0.1
export PRAHO_PORTAL_IP=10.0.0.2
export PRAHO_PORTAL_DOMAIN=portal.pragmatichost.com
export PRAHO_PLATFORM_DOMAIN=platform.pragmatichost.com
export PRAHO_DB_PASSWORD=secure-password
export PRAHO_SECRET_KEY=django-secret-key

# Deploy
cd deploy/ansible
ansible-playbook -i inventory/two-servers.yml playbooks/two-servers.yml
```

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

# Native deployment
/opt/praho/scripts/backup.sh
```

Backups are stored in `./backups/` with format: `praho_backup_YYYYMMDD_HHMMSS.sql.gz`

### Restoring from Backup

```bash
# Interactive (choose from list)
./deploy/scripts/restore.sh

# Restore specific file
./deploy/scripts/restore.sh ./backups/praho_backup_20240115_120000.sql.gz

# Restore latest backup
./deploy/scripts/restore.sh --latest

# Using make
make restore

# Native deployment
/opt/praho/scripts/restore.sh --latest
```

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

Roll back to a specific image version:

```bash
# Using script
./deploy/scripts/rollback.sh version v1.2.3

# Using make
make rollback VERSION=v1.2.3
```

### Database Rollback

Restore the latest database backup:

```bash
# Using script
./deploy/scripts/rollback.sh database

# Using make
make rollback-db
```

### Full Rollback

Roll back both version and database:

```bash
./deploy/scripts/rollback.sh full v1.2.3
```

### Rollback via Ansible

```bash
# Rollback to version
ansible-playbook -i inventory/native-single-server.yml playbooks/rollback.yml -e version=v1.2.3

# Restore database
ansible-playbook -i inventory/native-single-server.yml playbooks/rollback.yml -e restore_backup=true
```

---

## Makefile Commands

| Command | Description |
|---------|-------------|
| `make deploy-staging` | Deploy to staging (reads `.env.staging`) |
| `make deploy-prod` | Deploy to production (reads `.env.prod`) |
| `make deploy-dev-native` | Deploy to dev (native) |
| `make deploy-stop` | Stop all deployment services |
| `make deploy-status` | Show deployment status |
| `make deploy-logs` | Show service logs |
| `make backup` | Create database backup |
| `make restore` | Restore from backup (interactive) |
| `make rollback VERSION=X` | Roll back to version X |
| `make rollback-db` | Restore latest database backup |
| `make health-check` | Check service health |

---

## Environment Variables

### Native Deployment (Ansible)

All variables live in your `.env.{env}` file. See `.env.example.prod` for the full list with descriptions. Key required variables:

| Variable | Description | Example |
|----------|-------------|---------|
| `PRAHO_SERVER_IP` | Server public IP | `203.0.113.10` |
| `PORTAL_DOMAIN` | Customer-facing FQDN | `portal.pragmatichost.com` |
| `PLATFORM_DOMAIN` | Staff/admin FQDN | `platform.pragmatichost.com` |
| `SECRET_KEY` | Django secret key | `openssl rand -base64 50` |
| `DB_PASSWORD` | PostgreSQL password | `openssl rand -base64 32` |
| `HMAC_SECRET` | Portal ↔ Platform HMAC auth | `openssl rand -base64 32` |
| `PLATFORM_TO_PORTAL_WEBHOOK_SECRET` | Platform→Portal webhook HMAC | `python -c "import secrets; print(secrets.token_urlsafe(32))"` |
| `ACME_EMAIL` | Let's Encrypt email | `admin@pragmatichost.com` |

### Docker Deployment

| Variable | Required | Description | Example |
|----------|----------|-------------|---------|
| `PRAHO_PORTAL_DOMAIN` | Yes | Customer-facing domain | `portal.pragmatichost.com` |
| `PRAHO_PLATFORM_DOMAIN` | Yes | Staff/admin domain | `platform.pragmatichost.com` |
| `DB_PASSWORD` | Yes | PostgreSQL password | `secure-password` |
| `SECRET_KEY` | Yes | Django secret key | `django-insecure-...` |
| `ACME_EMAIL` | Yes | Let's Encrypt email | `admin@example.com` |

### Security Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `platform_allowed_ips` | IP whitelist for Platform access (Ansible extra-var) | `[]` (unrestricted) |
| `HMAC_SECRET` | HMAC shared secret for Portal ↔ Platform auth | (required in `.env`) |
| `PLATFORM_TO_PORTAL_WEBHOOK_SECRET` | HMAC secret for Platform→Portal webhooks | (required in `.env`) |

### Portal-Specific Variables

These are set in the `.env` file and used by the Portal service:

| Variable | Description | Required When |
|----------|-------------|---------------|
| `PLATFORM_API_BASE_URL` | Platform API URL | Portal-only deployment |
| `PLATFORM_API_SECRET` | HMAC secret for portal auth | Always (defaults to `HMAC_SECRET`) |
| `PLATFORM_API_ALLOW_INSECURE_HTTP` | Allow HTTP for internal comms | Docker/native (HTTP internal) |

---

## Troubleshooting

### Check Service Health

```bash
# Using script
./deploy/scripts/health-check.sh

# Using make
make health-check

# Manual checks
curl http://localhost:8700/api/users/health/
curl http://localhost:8701/

# Native deployment
/opt/praho/scripts/health-check.sh
systemctl status praho-platform praho-portal praho-qcluster
```

### View Logs

```bash
# Docker: all services
docker compose -f deploy/docker-compose.single-server.yml logs -f

# Docker: specific service
docker logs praho_platform -f
docker logs praho_portal -f
docker logs praho_db -f

# Native: systemd journal
journalctl -u praho-platform -f
journalctl -u praho-portal -f
journalctl -u praho-qcluster -f

# Using make
make deploy-logs
```

### Common Issues

**1. Database connection failed**
```bash
# Docker
docker ps | grep praho_db
docker logs praho_db

# Native
systemctl status postgresql
journalctl -u postgresql -n 50

# Verify DATABASE_URL is correct
```

**2. SSL/HTTPS not working**
```bash
# Docker
docker logs praho_caddy

# Native
journalctl -u caddy -f

# Verify domain DNS is correct
dig portal.pragmatichost.com
dig platform.pragmatichost.com

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
# Stop and remove all containers
docker compose -f deploy/docker-compose.single-server.yml down -v

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
├── docker-compose.services.yml        # Legacy production config
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
│   ├── restore.sh                     # Database restore
│   ├── rollback.sh                    # Version/DB rollback
│   └── health-check.sh               # Health check script
└── ansible/
    ├── inventory/
    │   ├── native-single-server.yml   # Unified native inventory (staging + prod)
    │   ├── dev.yml                    # Dev environment inventory
    │   └── two-servers.yml            # Multi-server hosts (Docker)
    ├── group_vars/
    │   └── all.yml                    # Ansible-only vars (ports, paths, tuning)
    ├── playbooks/
    │   ├── native-single-server.yml   # Native deploy (no Docker) — the main playbook
    │   ├── single-server.yml          # Docker single server deploy
    │   ├── two-servers.yml            # Multi-server deploy (Docker)
    │   ├── backup.yml                 # Backup playbook
    │   └── rollback.yml               # Rollback playbook
    └── roles/
        ├── common/                    # Base server setup (UFW, swap, users)
        ├── docker/                    # Docker installation
        ├── praho/                     # Docker-based deployment
        └── praho-native/              # Native deployment (systemd + Gunicorn)
            ├── defaults/main.yml      # Tunable variables
            ├── handlers/main.yml      # Service restart handlers
            ├── tasks/main.yml         # 11-step deployment (validates + copies .env)
            └── templates/             # systemd units, Caddyfile, backup/restore scripts
```
