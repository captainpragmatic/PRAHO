# PRAHO Platform Architecture

**Version:** 1.2.0
**Last Updated:** March 1, 2026
**Status:** ✅ Services Architecture Complete

> **Note**: Architecture diagrams available in `docs/architecture/` (Mermaid format):
> - `diagrams/system-overview.mmd` - High-level service boundaries and data flow
> - `diagrams/data-flow.mmd` - Sequence diagram showing Portal ↔ Platform communication
> - `diagrams/deployment.mmd` - Docker network topology and security isolation
> - `diagrams/app-dependencies.mmd` - Inter-app dependency graph (17 platform apps, 4 tiers)
> - `diagrams/entity-relationships.mmd` - Database ER diagram (~20 core entities)

## 🏗️ Architecture Overview

PRAHO Platform uses **Services-based Django architecture** for secure separation between business logic and customer-facing APIs. This architecture provides security isolation while maintaining development simplicity.

### **Core Principles**

1. **� Security Isolation** - Portal service cannot access platform database or models
2. **🎯 Service Boundaries** - Clear separation between platform (business logic) and portal (customer API)
3. **�️ Database Cache** - Django database cache replaces Redis for simplified deployment
4. **🐳 Docker Services** - Containerized deployment with network isolation
5. **🇷🇴 Romanian First** - Built for Romanian hosting provider compliance

---

## 📁 Services Structure

```bash
PRAHO/                          # 🚀 Romanian Hosting Provider PRAHO Platform
├─ services/                    # 🏗️ Services Architecture
│  ├─ platform/                # 🏢 Main Django application (full database access)
│  │  ├─ apps/                 # 17 Django apps (business domains)
│  │  │  ├─ users/             # Authentication & user management
│  │  │  ├─ customers/         # Customer organization management
│  │  │  ├─ billing/           # Invoice & payment processing
│  │  │  ├─ tickets/           # Support ticket system
│  │  │  ├─ provisioning/      # Service provisioning
│  │  │  ├─ audit/             # Compliance & audit logging
│  │  │  ├─ common/            # Shared utilities
│  │  │  ├─ ui/                # Templates & UI components
│  │  │  └─ ... (17 total)     # See ls services/platform/apps/
│  │  ├─ config/               # Django configuration
│  │  └─ manage.py             # Django management
│  └─ portal/                  # 🌐 Customer API service (stateless, session-only DB)
│     ├─ apps/                 # 9 Django apps (API proxies, no business models)
│     │  ├─ api_client/        # HMAC authentication client
│     │  ├─ users/             # User API proxy
│     │  ├─ billing/           # Billing API proxy
│     │  ├─ tickets/           # Support API proxy
│     │  └─ ... (9 total)      # See ls services/portal/apps/
│     ├─ config/               # Minimal Django configuration
├─ deploy/                      # 🐳 Docker deployment configuration
│  ├─ platform/                # Platform service Dockerfile
│  ├─ portal/                  # Portal service Dockerfile
│  ├─ nginx/                   # Reverse proxy configuration
│  ├─ docker-compose.services.yml  # Production services
│  └─ docker-compose.dev.yml   # Development services
├─ tests/                      # 🧪 Cross-service testing
│  └─ integration/             # Integration tests for service communication
└─ Makefile                    # ⚙️ Service management commands

---

## 🏢 Platform Service Architecture

**Location**: `services/platform/`
**Purpose**: Main Django application with full database access and business logic

### Business Domain Applications

#### 👤 users/ - Authentication & User Management
- **Models**: User (AbstractUser), UserProfile, CustomerMembership
- **Services**: Registration, 2FA, password reset, role management
- **Features**: Email-based authentication, TOTP 2FA, role-based access

#### 🏢 customers/ - Business Organizations & Contacts
- **Models**: Customer, CustomerTaxProfile, CustomerBillingProfile, CustomerAddress
- **Services**: Customer CRUD, multi-tenant access, CUI validation
- **Features**: Romanian business registration, VAT handling

#### 💰 billing/ - Invoicing & Payment Processing
- **Models**: ProformaInvoice, Invoice, InvoiceLine, Payment, CreditLedger
- **Services**: Invoice generation, payment processing, VAT compliance
- **Features**: e-Factura integration, Romanian tax compliance

#### 🎫 tickets/ - Support System & SLA Tracking
- **Models**: Ticket, TicketComment, TicketAttachment, TicketWorklog, SupportCategory
- **Services**: Ticket management, SLA tracking, escalation
- **Features**: File attachments, time tracking, customer satisfaction

#### 🖥️ provisioning/ - Hosting Services & Server Management
- **Models**: ServicePlan, Server, Service, ProvisioningTask
- **Services**: Service provisioning, server management, resource allocation
- **Features**: Automated provisioning, resource monitoring

#### 📋 audit/ - Compliance & Audit Logging
- **Models**: AuditEntry, GDPRRequest, ComplianceLog
- **Services**: Audit trail creation, GDPR compliance, data export
- **Features**: Immutable audit logs, Romanian compliance

## 🌐 Portal Service Architecture

**Location**: `services/portal/`
**Purpose**: Customer-facing API service — **NO business data access**

### Database Isolation

Portal uses a **minimal SQLite database for Django session storage only**. It has:
- ✅ Session storage (required by Django's session framework)
- ❌ NO business models (no User, Customer, Invoice, etc.)
- ❌ NO PostgreSQL access (no connection to platform database)
- ❌ NO direct data queries (all business data fetched via Platform API)

This maintains stateless architecture while leveraging Django's built-in session management.

### API Endpoints

#### 🔐 Authentication API
```
POST /api/v1/auth/login/     # Customer login
POST /api/v1/auth/logout/    # Session termination
POST /api/v1/auth/refresh/   # Token refresh
```

#### 🏢 Account API
```
GET  /api/v1/account/profile/      # Customer profile
PUT  /api/v1/account/profile/      # Update profile
GET  /api/v1/account/services/     # Service list
GET  /api/v1/account/invoices/     # Billing history
```

#### 🎫 Support API
```
GET  /api/v1/tickets/              # Customer tickets
POST /api/v1/tickets/              # Create ticket
GET  /api/v1/tickets/{id}/         # Ticket details
POST /api/v1/tickets/{id}/comments/ # Add comment
```

### Security Constraints
- ❌ **NO PostgreSQL access** (no psycopg driver, no connection to business database)
- ❌ **NO direct model imports** from platform (enforced by pre-commit hooks)
- ❌ **NO business data models** (apps have no models.py with domain entities)
- ✅ **SQLite for sessions only** (minimal local storage, no business data)
- ✅ **HMAC-signed API communication** with platform for all business operations
- ✅ **Stateless design** - can be destroyed/recreated without data loss

---

## 🗄️ Data Architecture

### Database Design (Platform Only)
```sql
-- Core business entities
Users ←→ CustomerMembership ←→ Customers
Customers ←→ Invoices ←→ InvoiceLines
Customers ←→ Tickets ←→ TicketComments
Customers ←→ Services ←→ Servers

-- Database cache table (replaces Redis)
django_cache_table (
    cache_key VARCHAR(255) PRIMARY KEY,
    value TEXT NOT NULL,
    expires TIMESTAMP NOT NULL
);
```

### Service Communication
```
Portal Service                Platform Service
      │                            │
      │ HTTP API Calls             │
      │────────────────────────────▶│
      │                            │
      │◄───────────────────────────│
      │     JSON Responses         │
```

---

## 🔒 Security Model

### Service Isolation
1. **Import Prevention**: Portal cannot import platform models
2. **Database Blocking**: Portal has no database drivers
3. **Network Isolation**: Docker networks separate concerns
4. **Session Separation**: Different cookie names prevent conflicts

### Security Testing
```python
# Automated security validation
def test_portal_isolation():
    # Portal cannot import platform models
    with pytest.raises(ImportError):
        from apps.billing.models import Invoice

    # Portal cannot access database
    with pytest.raises(Exception):
        from django.db import connection
```

---

## 🚀 Deployment Architecture

### Docker Services
```yaml
# deploy/docker-compose.services.yml
version: '3.8'
services:
  platform:
    build:
      context: .
      dockerfile: deploy/platform/Dockerfile
    environment:
      - DATABASE_URL=postgres://user:pass@db:5432/praho
      - DJANGO_SETTINGS_MODULE=config.settings.prod
    networks:
      - platform-network

  portal:
    build:
      context: .
      dockerfile: deploy/portal/Dockerfile
    environment:
      - PLATFORM_API_URL=http://platform:8700
      - PLATFORM_API_KEY=secret-api-key
    networks:
      - api-network

  nginx:
    image: nginx:alpine
    volumes:
      - ./deploy/nginx/nginx.conf:/etc/nginx/nginx.conf
    ports:
      - "80:80"
      - "443:443"
    networks:
      - api-network

  db:
    image: postgres:16
    environment:
      - POSTGRES_DB=praho
      - POSTGRES_USER=praho_user
      - POSTGRES_PASSWORD=secure_password
    volumes:
      - postgres_data:/var/lib/postgresql/data
    networks:
      - platform-network

networks:
  platform-network:  # Database + Platform
  api-network:       # Portal + Nginx

volumes:
  postgres_data:
```

### Network Isolation
- **platform-network**: Platform service + Database only
- **api-network**: Portal service + Nginx proxy
- **No direct connection**: Portal cannot reach database

---

## 🔧 Development Workflow

### Local Development
```bash
# Start both services
make dev

# Or start individually
make dev-platform    # Platform on :8700 (full Django)
make dev-portal      # Portal on :8701 (API only)
```

### Testing Strategy
```bash
# Service-specific testing
make test-platform     # Unit tests with database access
make test-portal       # API tests without database

# Cross-service testing
make test-integration  # Service communication tests
make test-security     # Service isolation validation
make test-cache        # Database cache functionality
```

### Database Operations
```bash
# Platform service manages all database operations
make migrate          # Run platform migrations only
make shell-platform   # Django shell with full database access
make fixtures         # Load sample data via platform
```

---

## 📊 Performance & Monitoring

### Database Cache Performance
- **Cache Operations**: ~1-2ms latency for typical cache operations
- **Transaction Safety**: ACID guarantees with database operations
- **Simplified Deployment**: No Redis maintenance or memory management

### Service Communication
- **Internal APIs**: <10ms latency between services in Docker network
- **Authentication**: Two independent HMAC-SHA256 systems:
  - **System 1** (Portal→Platform): Canonical string signing with nonce dedup (`HMAC_SECRET`)
  - **System 2** (Platform→Portal webhooks): `ts.body` signing with replay dedup (`PLATFORM_TO_PORTAL_WEBHOOK_SECRET`)

### Rate Limiting Architecture

Rate limiting runs in three layers and is intentionally cumulative:

1. **Portal middleware (pre-DRF)**: protects Portal auth and API routes before outbound calls are made.
2. **Platform global DRF throttles**: routes traffic by source:
   - HMAC service traffic: `PortalHMACRateThrottle` + `PortalHMACBurstThrottle`
   - Direct/customer traffic: `CustomerRateThrottle` + `BurstRateThrottle`
3. **Platform per-view DRF throttles**: operation-level controls:
   - `StandardAPIThrottle` (`sustained`)
   - `BurstAPIThrottle` (`api_burst`)
   - `AuthThrottle` (`auth`)

For internal HMAC traffic, `request._portal_authenticated` drives mutual exclusion:
- portal HMAC throttles apply
- customer/burst fallback classes skip processing for the same request

Throttle scope rates are centrally configured via `THROTTLE_RATES` and validated at startup
to fail fast on invalid rate strings or missing scopes.

### Health Monitoring
```python
# Platform service health endpoints
/health/database/     # Database connectivity
/health/cache/        # Cache table operations
/health/migrations/   # Migration status

# Portal service health endpoints
/health/api/          # Platform API connectivity
/health/auth/         # Authentication flow status
```

---

## 🎯 Migration Benefits

### Security Improvements
1. **Data Isolation**: Customer API cannot access sensitive business data
2. **Attack Surface Reduction**: Portal service has minimal dependencies
3. **Compliance**: Clear audit boundaries between services
4. **Defense in Depth**: Multiple security layers

### Operational Benefits
1. **Scalability**: Services scale independently based on load
2. **Reliability**: Portal issues don't affect platform operations
3. **Simplified Deployment**: Database cache eliminates Redis complexity
4. **Monitoring**: Service-specific metrics and alerting

### Development Benefits
1. **Clear Boundaries**: Service responsibilities are well-defined
2. **Testing Isolation**: Each service can be tested independently
3. **Team Structure**: Teams can own specific services
4. **Technology Choices**: Services can evolve different tech stacks

---

This architecture provides a secure, scalable foundation for the PRAHO platform while maintaining the development simplicity of Django and preparing for future microservices evolution.
