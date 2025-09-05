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
# Encryption key for sensitive data
DJANGO_ENCRYPTION_KEY="your-fernet-key-here"

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

### Emergency Recovery
```python
from apps.provisioning.virtualmin_service import VirtualminEmergencyRecoveryService

recovery = VirtualminEmergencyRecoveryService()
result = recovery.rebuild_from_virtualmin_domains(server)
# Rebuilds PRAHO data from Virtualmin server state
```

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
2. **Backup Testing** - Implement and test backup verification monthly
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
