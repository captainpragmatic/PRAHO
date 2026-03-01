# PRAHO Deployment Guide

This guide covers all deployment scenarios for PRAHO, from single-server setups to multi-server distributed deployments.

## Table of Contents

- [Quick Start](#quick-start)
- [Deployment Scenarios](#deployment-scenarios)
  - [Single Server (All Services)](#scenario-1-single-server-all-services)
  - [Container Services (DigitalOcean, etc.)](#scenario-2-container-services)
  - [Platform Only](#scenario-3-platform-only)
  - [Portal Only](#scenario-4-portal-only)
  - [Two Servers (Distributed)](#scenario-5-two-servers-distributed)
- [Using Ansible](#ansible-deployments)
- [Database Operations](#database-operations)
- [Rollback Procedures](#rollback-procedures)
- [Makefile Commands](#makefile-commands)
- [Environment Variables](#environment-variables)
- [Troubleshooting](#troubleshooting)

---

## Quick Start

```bash
# 1. Clone repository
git clone https://github.com/captainpragmatic/PRAHO.git
cd PRAHO

# 2. Copy and configure environment
cp .env.example .env
# Edit .env with your settings

# 3. Deploy (single server with all services)
make deploy-single-server
```

---

## Deployment Scenarios

### Scenario 1: Single Server (All Services)

Deploy Platform, Portal, PostgreSQL, and Caddy on a single server. Best for small to medium deployments.

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
export DOMAIN=praho.example.com
export DB_PASSWORD=your-secure-password
export SECRET_KEY=your-django-secret-key
export ACME_EMAIL=admin@example.com

# Deploy
docker compose -f deploy/docker-compose.single-server.yml up -d

# Or use the deploy script
./deploy/scripts/deploy.sh single-server --build --migrate
```

**Using Make:**
```bash
make deploy-single-server
```

---

### Scenario 2: Container Services

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

### Scenario 3: Platform Only

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

### Scenario 4: Portal Only

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

### Scenario 5: Two Servers (Distributed)

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
export PRAHO_DOMAIN=praho.example.com
export PRAHO_DB_PASSWORD=secure-password
export PRAHO_SECRET_KEY=django-secret-key

# Deploy
cd deploy/ansible
ansible-playbook -i inventory/two-servers.yml playbooks/two-servers.yml
```

---

## Ansible Deployments

### Prerequisites

```bash
# Install Ansible
pip install ansible

# Install required collections
ansible-galaxy collection install community.docker
```

### Single Server Deployment

```bash
cd deploy/ansible

# Set environment variables
export PRAHO_SERVER_IP=your-server-ip
export PRAHO_DOMAIN=praho.example.com
export PRAHO_DB_PASSWORD=secure-password
export PRAHO_SECRET_KEY=your-secret-key
export PRAHO_ACME_EMAIL=admin@example.com

# Run playbook
ansible-playbook -i inventory/single-server.yml playbooks/single-server.yml
```

### Two Server Deployment

```bash
cd deploy/ansible

# Set environment variables
export PRAHO_PLATFORM_IP=10.0.0.1
export PRAHO_PORTAL_IP=10.0.0.2
export PRAHO_DOMAIN=praho.example.com
export PRAHO_DB_PASSWORD=secure-password
export PRAHO_SECRET_KEY=your-secret-key

# Run playbook
ansible-playbook -i inventory/two-servers.yml playbooks/two-servers.yml
```

### Ansible Backup Playbook

```bash
# Create backup
ansible-playbook -i inventory/single-server.yml playbooks/backup.yml

# Create backup and fetch to local machine
ansible-playbook -i inventory/single-server.yml playbooks/backup.yml -e fetch_backup=true
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

### Rollback Ansible Playbook

```bash
# Rollback to version
ansible-playbook -i inventory/single-server.yml playbooks/rollback.yml -e version=v1.2.3

# Restore database
ansible-playbook -i inventory/single-server.yml playbooks/rollback.yml -e restore_backup=true
```

---

## Makefile Commands

| Command | Description |
|---------|-------------|
| `make deploy-single-server` | Deploy all services on single server |
| `make deploy-platform` | Deploy platform only |
| `make deploy-portal` | Deploy portal only |
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

### Required Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `DOMAIN` | Production domain | `praho.example.com` |
| `DB_PASSWORD` | PostgreSQL password | `secure-password` |
| `SECRET_KEY` | Django secret key | `django-insecure-...` |
| `ACME_EMAIL` | Let's Encrypt email | `admin@example.com` |

### Optional Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `VERSION` | Image version tag | `latest` |
| `REGISTRY` | Docker registry | (empty) |
| `PLATFORM_PORT` | Platform service port | `8700` |
| `PORTAL_PORT` | Portal service port | `8701` |
| `BACKUP_DIR` | Backup directory | `./backups` |
| `RETENTION_DAYS` | Backup retention | `30` |

### Portal-Specific Variables

| Variable | Description | Required When |
|----------|-------------|---------------|
| `PLATFORM_API_BASE_URL` | Platform API URL | Portal-only deployment |

---

## Troubleshooting

### Check Service Health

```bash
# Using script
./deploy/scripts/health-check.sh

# Using make
make health-check

# Manual checks
curl http://localhost:8700/health/
curl http://localhost:8701/health/
```

### View Logs

```bash
# All services
docker compose -f deploy/docker-compose.single-server.yml logs -f

# Specific service
docker logs praho_platform -f
docker logs praho_portal -f
docker logs praho_db -f

# Using make
make deploy-logs
```

### Common Issues

**1. Database connection failed**
```bash
# Check if database is running
docker ps | grep praho_db

# Check database logs
docker logs praho_db

# Verify DATABASE_URL is correct
```

**2. SSL/HTTPS not working**
```bash
# Check Caddy logs
docker logs praho_caddy

# Verify domain DNS is correct
dig your-domain.com

# Check if ports 80/443 are open
```

**3. Portal can't connect to Platform**
```bash
# Verify PLATFORM_API_BASE_URL
echo $PLATFORM_API_BASE_URL

# Test connectivity from portal container
docker exec praho_portal curl http://platform:8700/health/
```

**4. Health checks failing**
```bash
# Check container status
docker ps -a

# Restart unhealthy service
docker restart praho_platform
```

### Emergency Procedures

**Quick rollback to last known good state:**
```bash
# 1. Stop current services
make deploy-stop

# 2. Restore database
make rollback-db

# 3. Deploy previous version
make rollback VERSION=v1.0.0
```

**Complete reset:**
```bash
# Stop and remove all containers
docker compose -f deploy/docker-compose.single-server.yml down -v

# Redeploy fresh
make deploy-single-server
```

---

## File Structure

```
deploy/
├── docker-compose.single-server.yml   # All services on one server
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
│   └── health-check.sh                # Health check script
└── ansible/
    ├── inventory/
    │   ├── single-server.yml          # Single server hosts
    │   └── two-servers.yml            # Multi-server hosts
    ├── group_vars/
    │   └── all.yml                    # Global variables
    ├── playbooks/
    │   ├── single-server.yml          # Single server deploy
    │   ├── two-servers.yml            # Multi-server deploy
    │   ├── backup.yml                 # Backup playbook
    │   └── rollback.yml               # Rollback playbook
    └── roles/
        ├── common/                    # Base server setup
        ├── docker/                    # Docker installation
        └── praho/                     # Application deployment
```
