# Virtualmin Integration Implementation - PRAHO Platform

## 🎯 Overview

This implementation provides comprehensive Virtualmin API integration for the PRAHO hosting platform, following the architecture specified in `virtualmin.md` and addressing security concerns from `virtualmin_review.md`.

## 📁 Files Implemented

### Core Components

- **`virtualmin_validators.py`** - Input validation with security focus
- **`virtualmin_models.py`** - Database models for Virtualmin integration
- **`virtualmin_gateway.py`** - API gateway with error handling
- **`virtualmin_service.py`** - Business logic service layer
- **`virtualmin_tasks.py`** - Django-Q2 async tasks

### Testing

- **`test_virtualmin_integration.py`** - Basic integration tests

## 🏗️ Architecture

### Strategic Seams Pattern

Following PRAHO's established patterns:

```python
virtualmin_validators.py  # Input validation
virtualmin_gateway.py     # External API integration
virtualmin_service.py     # Business logic
virtualmin_models.py      # Data layer
virtualmin_tasks.py       # Async operations
```

### Key Design Decisions

1. **PRAHO as Single Source of Truth** - Virtualmin servers are "cattle, not pets"
2. **Recovery Seeds** - Minimal metadata stored in Virtualmin comments for emergency recovery
3. **Enterprise Error Handling** - Comprehensive error taxonomy with retry logic
4. **Security First** - Input validation, rate limiting, encrypted credentials
5. **Async by Default** - All provisioning operations use Django-Q2 tasks

## 🔐 Security Features

### Input Validation
- Domain name RFC compliance validation
- Username pattern validation (alphanumeric + underscore)
- Password strength requirements
- API program whitelist (prevent dangerous commands)
- Parameter sanitization with length limits

### Authentication & Authorization
- Encrypted API credentials in database
- SSL certificate verification with optional pinning
- Rate limiting per server (100 calls/hour)
- Dedicated ACL user (not master admin)

### Error Handling
- Structured error taxonomy
- No sensitive data in logs
- Correlation IDs for request tracking
- Exponential backoff for retries

## 📊 Models

### VirtualminServer
- Server configuration and health monitoring
- Encrypted API credentials
- Capacity tracking and placement logic
- Health check timestamps and error tracking

### VirtualminAccount
- Links PRAHO Service to Virtualmin virtual server
- Recovery seeds for emergency restoration
- Usage statistics and quota tracking
- Status lifecycle management

### VirtualminProvisioningJob
- Async operation tracking
- Retry logic with exponential backoff
- Correlation IDs for observability
- Execution time metrics

### VirtualminDriftRecord
- Tracks discrepancies between PRAHO and Virtualmin
- Automated reconciliation support
- Audit trail for manual fixes

## 🔄 API Operations

### Core Operations
- `create-domain` - Create virtual server with web/mail/DNS
- `delete-domain` - Remove virtual server completely
- `enable-domain` / `disable-domain` - Suspend/unsuspend accounts
- `modify-domain` - Update domain settings and quotas
- `list-domains` - List virtual servers with filtering

### Advanced Features
- `create-alias` - Domain aliases and redirects
- `create-subdomain` - Subdomain management
- `request-letsencrypt-cert` - SSL automation
- `create-user` / `delete-user` - Mailbox management
- `backup-domain` / `restore-domain` - Backup operations

## ⚙️ Service Integration

### Billing Integration
```python
# Trigger provisioning after invoice payment
from apps.provisioning.virtualmin_tasks import provision_virtualmin_account

def on_invoice_paid(invoice):
    for service in invoice.services:
        provision_virtualmin_account.delay(
            service_id=str(service.id),
            domain=service.primary_domain
        )
```

### Customer Management
```python
# Suspend services for overdue customer
from apps.provisioning.virtualmin_tasks import suspend_virtualmin_account

def suspend_customer_services(customer, reason):
    accounts = VirtualminAccount.objects.filter(
        service__customer=customer,
        status="active"
    )
    for account in accounts:
        suspend_virtualmin_account.delay(str(account.id), reason)
```

## 🔧 Configuration

### Environment Variables
```bash
# AES-256-GCM encryption key for sensitive data (32 bytes, URL-safe base64)
DJANGO_ENCRYPTION_KEY="your-base64-encoded-32-byte-key-here"

# Optional SSL certificate pinning
VIRTUALMIN_PINNED_CERT_SHA256="sha256:abcd1234..."
```

### Server Configuration
```python
# Create Virtualmin server
server = VirtualminServer.objects.create(
    name="primary-hosting",
    hostname="virtualmin.example.com",
    api_username="praho_api_user",
    max_domains=1000
)
server.set_api_password("secure_api_password")
server.save()
```

### Django-Q2 Scheduled Tasks
```bash
# Set up scheduled tasks
python manage.py setup_virtualmin_tasks

# Start workers
python manage.py qcluster

# Monitor at /admin/django_q/
```

**Schedule Details:**
- Health Check: Every hour
- Statistics Update: Every 6 hours
- Retry Failed Jobs: Every 15 minutes
- Chain backups (differential, flag-gated): Every hour

## 🚀 Usage Examples

### Create Account
```python
from apps.provisioning.virtualmin_service import VirtualminProvisioningService

service = VirtualminProvisioningService()
result = service.create_virtualmin_account(
    service=praho_service,
    domain="customer.com",
    template="SharedHosting"
)

if result.is_ok():
    account = result.unwrap()
    print(f"Created account: {account.domain}")
else:
    error = result.unwrap_err()
    print(f"Failed: {error}")
```

### Async Provisioning
```python
from apps.provisioning.virtualmin_tasks import provision_virtualmin_account

# Queue provisioning task
task = provision_virtualmin_account.delay(
    service_id=str(service.id),
    domain="customer.com",
    template="SharedHosting"
)

# Check task status
result = task.get()  # Blocks until complete
print(f"Provisioning result: {result}")
```

### Server Health Check
```python
from apps.provisioning.virtualmin_service import VirtualminServerManagementService

management = VirtualminServerManagementService()
result = management.health_check_server(server)

if result.is_ok():
    health_data = result.unwrap()
    print(f"Server healthy: {health_data}")
else:
    error = result.unwrap_err()
    print(f"Health check failed: {error}")
```

## 🧪 Testing

### Run Basic Tests
```bash
# Run Virtualmin integration tests
python manage.py test apps.provisioning.test_virtualmin_integration
```

### Manual Testing
```python
# Test domain validation
from apps.provisioning.virtualmin_validators import VirtualminValidator

domain = VirtualminValidator.validate_domain_name("test.com")
print(f"Validated domain: {domain}")

# Test server connection
from apps.provisioning.virtualmin_gateway import VirtualminGateway, VirtualminConfig

config = VirtualminConfig(server=virtualmin_server)
gateway = VirtualminGateway(config)
result = gateway.test_connection()
print(f"Connection test: {result}")
```

## 📈 Monitoring & Observability

### Metrics Available
- Provisioning success/failure rates
- API response times
- Server health status
- Domain count per server
- Failed job retry statistics

### Logging
```python
# Structured logging with correlation IDs
logger.info(
    "🔗 [Virtualmin] Calling create-domain on server1.example.com (correlation: prov_123)"
)
```

### Health Endpoints
```python
# Monitor server health
GET /api/provisioning/virtualmin/servers/{id}/health/

# View provisioning jobs
GET /api/provisioning/virtualmin/jobs/?status=failed
```

## 🔄 Migration Strategy

### From Manual Virtualmin
1. **Import Existing Domains** - Use emergency recovery service
2. **Gradual Migration** - Move domains in batches
3. **Parallel Running** - Test PRAHO alongside existing setup
4. **Data Validation** - Verify domain data consistency

### Disaster Recovery
```python
from apps.provisioning.virtualmin_disaster_recovery import VirtualminDisasterRecoveryService

dr = VirtualminDisasterRecoveryService()
readiness = dr.verify_praho_data_integrity()   # rebuild-input readiness report
result = dr.rebuild_server_from_praho(server)  # recreates accounts from PRAHO data
# Per-account recreation goes through reprovision_virtualmin_account
# (rotated password, recovery seed in the Virtualmin comment field).
```

### Backup & Restore (job-based, #431)
- `VirtualminBackupManagementService.create_backup_job` / `create_restore_job`
  admit under the account-operation lock and run in Django-Q tasks (the CLI
  `manage.py virtualmin_backup` uses the same job layer with inline execution).
- Backups: `backup-domain` writes a UUID-named archive into the node's
  private staging directory `/var/lib/praho-transfer` → the
  `virtualmin_backup_fetch.yml` playbook pulls it into the private transfer
  spool (checksum-evidenced; the remote archive and its sidecars deleted) →
  the manifest is finalized → archive then metadata land in S3 (`backup.*`
  settings).
- Staging: Virtualmin writes every archive and its `.dom`/`.info` sidecars
  0644 whatever the destination, and the `.dom` sidecar holds the domain's
  database passwords. Only the parent directory keeps them private, so the
  staging directory (`REMOTE_ARCHIVE_DIR`) is root-owned 0700 and outside
  the world-writable `/tmp`.
  - Backup calls send `mkdir`, so Virtualmin creates it 0700 when it is
    missing; the push playbooks create it the same way.
  - The fetch playbooks refuse to move an archive unless the directory is a
    root-owned 0700 directory (a refused fetch removes the archive).
  - The fetch and cleanup playbooks remove the sidecars. The migration source
    keeps its archive by design, but not the sidecars.
- Differential base: Virtualmin keeps one differential base per domain, and
  any full backup sent without `no-differential` replaces it (contract Q2/Q3).
  `BackupConfig.chain_role` is `standalone` by default, and every standalone
  backup-domain call sends `no-differential`: the ordinary full and
  config-only backups, the pre-restore safety backup and the migration backup
  (`migration_backup_params`). Only a complete full backup explicitly marked
  `base` omits it; config-only or partial backups cannot be a base. The role
  is stored in the job parameters (a job without one is standalone) and in the
  manifest. Any restore still deletes the base (contract Q8).
- Differential chains (ADR-0059, off by default behind
  `provisioning.incremental_backups_enabled`):
  - A **base** is a complete backup that resets the node's snapshot; a
    **differential** holds only what changed since the live base. Neither goes
    through remote.cgi: each is one allowlisted playbook run
    (`virtualmin_chain_backup.yml`) that, under `flock` on a per-domain lock,
    fingerprints the snapshot before and after the backup and refuses a
    differential whose expected fingerprint differs. The chain lives on the
    account (`chain_base`, `chain_base_fingerprint`, `chain_epoch`) and every
    transition is fenced by the job's token and the epoch
    (`virtualmin_chain.py`).
  - Anything that can reset the snapshot (a restore, a new base, a migration,
    a delete) clears the chain in its admission transaction. A step that is
    uncertain (timeout, ambiguous error, dead worker) parks in `attention` and
    keeps the account; "Confirm stopped" writes a cancel marker on the node,
    and "Node lost" (failed server or destroyed deployment only) releases a
    chain job or a pair restore without it.
  - **Pair restore** (`virtualmin_pair_restore.py`, `virtualmin_pair_restore.yml`):
    base then differential in one locked node execution, behind a server-level
    Apache `<If>` section answering 503 plus `disable-domain`, re-applied and
    verified after each restore. Files deleted after the base was taken
    reappear, and databases come from the differential's full dump. A
    maintenance virtual host is not a barrier: Virtualmin rewrites it during
    `restore-domain`. The domain stays disabled and the account suspended;
    reconcile (ADR-0051) enables it.
  - **Scheduler** (`virtualmin_chain_schedule.py`): the hourly Django-Q
    schedule `virtualmin-chain-backups` takes a base when an account has no
    live base or the base is older than `provisioning.chain_base_interval_days`
    (7), and a differential when the last backup of the chain is older than
    `provisioning.chain_differential_interval_hours` (24). It decides from the
    chain, never from error text. Failures that leave the chain alone back off
    (30 minutes, doubling to a day) and raise one audit alert at
    `provisioning.chain_alert_after_failures` (3) in a row; the node's evidence that a snapshot is absent or different ends the
    chain and the next run takes a base. At most 20 jobs are admitted per
    sweep, stalest account first. Register it with `setup_virtualmin_scheduled_tasks`.
  - Staff: "Take base backup", "Take differential backup" (account page, only
    while the flag is on) and "Restore pair" (also only while the flag is on). CLI:
    `virtualmin_backup backup <domain> --chain-role base|differential` and
    `virtualmin_backup restore <domain> <base-id> --differential-backup-id <id>
    --force-restore`. No bulk differential actions.
  - Retention extends a base while a retained differential names it, and
    deletion refuses a base any differential names. The flag gates creating
    bases and differentials and the pair restore; restoring a single backup,
    retention and deletion work whatever it says.
- Restores: fail-closed gates (backup↔account authorization, target-ownership
  that `force_restore` can never override, live-domain force requirement,
  pre-restore safety backup) → push playbook → `restore-domain` with an
  explicit-success envelope → post-restore verification. Ambiguous outcomes
  park the job in the non-terminal `attention` status for operator review.
- Budgets derive from each job's size estimate against
  `provisioning.backup_min_transfer_mib_s`; chain steps and pair restores add
  their own stage budgets (`backup_task_timeout`, `pair_restore_task_timeout`).
- remote.cgi turns each parameter into argv. An empty value is a bare
  `--flag`; any other value is `--flag value`; a list repeats the pair.
  Flags must therefore be sent as `""`, never `True`. Virtualmin 8.3.0 rejects
  unknown options outright.
  - Full backups send `all-features` plus one `except-feature` per excluded
    component.
  - Config-only backups send `feature=virtualmin` and `feature=dir`.
  - Neither sends `newformat`, which needs a directory destination.
- The 8.x JSON listings key attributes in snake_case (`username`, `disabled`).
  Read them through `listing_attribute()` and `listing_enabled()`.
  - A full row also carries `hashed_password` and `password_for_mysql`.
    `list_migration_domains()` keeps only `SNAPSHOT_ATTRIBUTES` (the
    migration snapshot is persisted), and job results pass through
    `without_secrets()` before they are stored.
  - `list-domains --domain <absent>` answers with the failure
    "Virtual server <domain> does not exist". `get_domain_state()` and
    `get_domain_owner()` read exactly that envelope as "absent", so a create
    retry is idempotent; any other failure stays an error.
- `create-domain` on 8.x:
  - the built-in template is "Default Settings" (`DEFAULT_VIRTUALMIN_TEMPLATE`);
    there is no template "Default";
  - nothing is enabled without a feature flag, so PRAHO sends
    `default-features` (the node playbook pins the default-on set to unix,
    dir, web, ssl, logrotate, mysql and webmin);
  - there is no `--comment`: the recovery seed goes in `--desc`, which refuses
    ":", so the seed is `PRAHO=<uuid>|CID=<id>|STATUS=<status>`
    (`parse_recovery_seed()` still reads the old ":" form).
- Node playbooks (`infrastructure/ansible/playbooks/`), checked on 8.3.0:
  - `virtualmin.yml` installs with the Virtualmin 8 installer
    (`download.virtualmin.com`; the old `software.virtualmin.com/gpl/scripts`
    URL serves the Virtualmin 7 installer). It creates the API user with
    `files/praho-webmin-api-user.pl`: a Webmin user whose only module is
    virtual-server, with Virtualmin master rights, password on stdin, reset on
    every deploy. `create-admin` makes per-domain extra admins and
    `modify-config` does not exist.
  - Why master, and how it is contained: ADR-0060. The user may log in only
    from `infrastructure.node_admin_allowed_cidrs` (Platform's egress
    addresses plus admin networks), through Webmin's per-user IP allow list,
    and `virtualmin_harden.yml` opens ports 22 and 10000 only to the same
    list. Both plays refuse to run while the setting is empty, and the harden
    play also refuses when its own SSH connection comes from outside it.
  - `virtualmin_backup.yml` creates the nightly backup with
    `virtualmin create-scheduled-backup` (all servers, all features,
    `--no-differential`, dated directory under `backup_local_path`, `--purge`
    for retention) and removes the `sched` file and `backup_*` keys earlier
    versions wrote, which Virtualmin never ran.
- `backup.s3_endpoint_url` points the archive store at S3-compatible storage
  such as MinIO; the client then uses path-style addressing.
- Proving ground: `deploy/virtualmin-lab/` provides two Virtualmin 8.3.0
  nodes plus MinIO.
  - `make test-virtualmin-lab` runs the full backup and restore round trip,
    then `virtualmin_lab_checks` on vm-b: create-domain through the
    provisioning service, the differential base kept by every standalone
    backup, private staging, both node playbooks, the differential chain (base,
    differential, confirm stopped, the hourly schedule taking a base again after
    the node loses the snapshot, and a pair restore behind the write barrier with
    a probe on ports 80 and 443), and the access lock (the
    API user and port 10000 refused from a host outside the allowlist).
  - `make virtualmin-probe` refreshes the differential-backup evidence in
    `docs/domain/virtualmin-incremental-contract.md`.

## 🎯 Key Benefits

### Operational
- **Zero Downtime Deployment** - Async provisioning with rollback
- **Multi-Server Load Balancing** - Automatic server placement
- **Health Monitoring** - Proactive server health checks
- **Failed Job Recovery** - Automatic retry with exponential backoff

### Security
- **Encrypted Credentials** - All sensitive data encrypted at rest
- **Input Validation** - Comprehensive validation prevents injection
- **Rate Limiting** - Prevents API abuse and server overload
- **Audit Trail** - Complete operation history for compliance

### Developer Experience
- **Type Safety** - Full type hints with mypy compatibility
- **Error Handling** - Clear error messages with suggested actions
- **Correlation IDs** - Easy request tracing across services
- **DRY Validation** - Reusable validators following PRAHO patterns

## 🚨 Important Notes

1. **ACL User Required** - Create dedicated Webmin ACL user, not master admin
2. **Backup Testing** - Restore a recent backup on a staging node periodically; the pipeline verifies checksums, but only a real restore proves recoverability
3. **Rate Limits** - Monitor API usage to stay within Virtualmin limits
4. **SSL Verification** - Use certificate pinning in production
5. **Recovery Seeds** - Limited to ~200 chars in Virtualmin comments

## 📚 Next Steps

1. **Run Migrations** - `python manage.py makemigrations provisioning`
2. **Configure Servers** - Add VirtualminServer instances
3. **Set Up Django-Q2** - Configure scheduled tasks and start workers
4. **Test Integration** - Verify with staging Virtualmin server
5. **Monitor Operations** - Set up alerts for failed provisioning jobs

This implementation provides a robust, secure, and scalable foundation for Virtualmin integration that follows PRAHO's architectural principles while addressing the security concerns identified in the review.
