# PRAHO Platform Architecture

**Version:** 0.3.2  
**Last Updated:** August 19, 2025  
**Status:** ✅ Core Foundation Complete + Domain Management + Service Relationships  

## 🏗️ Architecture Overview

PRAHO Platform uses **Enhanced Option A** - a modular monolith with strategic seams for future scaling. This architecture balances rapid development for MVP delivery with built-in migration paths to layered architecture.

### **Core Principles**

1. **📐 Modular Monolith** - Django apps as bounded business contexts
2. **🔗 Strategic Seams** - `services.py`, `repos.py`, `gateways.py` pattern for future extraction
3. **🚀 Zero-Runtime JavaScript** - Server-rendered components with HTMX
4. **🇷🇴 Romanian First** - Built for Romanian hosting provider compliance
5. **⚡ Performance by Design** - Query budgets, optimization patterns, caching strategy

---

## 📁 Project Structure

```bash
pragmatichost/                  # 🚀 Romanian Hosting Provider PRAHO Platform
├─ config/                      # ⚙️ Django project configuration
│  ├─ settings/                 # Environment-specific settings
│  │  ├─ base.py               # Shared: DB, apps, middleware, Romanian defaults
│  │  ├─ dev.py                # Development: DEBUG, SQLite, django-extensions
│  │  ├─ test.py               # Testing: in-memory DB, fast test configuration
│  │  └─ prod.py               # Production: security headers, Sentry, PostgreSQL
│  ├─ urls.py                  # Root URL configuration with /auth/ prefix
│  ├─ asgi.py                  # ASGI for async Django (WebSockets, background tasks)
│  ├─ wsgi.py                  # WSGI for traditional deployment (Gunicorn)
│  └─ logging.py               # Structured JSON logging with request IDs
│
├─ apps/                        # 📦 Business Domain Applications
│  ├─ users/                    # 👤 Authentication & User Management
│  │  ├─ models.py             # User (AbstractUser), UserProfile, CustomerMembership
│  │  ├─ services.py           # 🔥 Business logic: registration, 2FA, password reset
│  │  ├─ views.py              # HTTP endpoints: login/logout, profile management
│  │  ├─ forms.py              # Django forms with Romanian validation
│  │  ├─ admin.py              # Django admin customization
│  │  └─ signals.py            # User lifecycle signals
│  │
│  ├─ customers/                # 🏢 Business Organizations & Contacts
│  │  ├─ models.py             # Customer, CustomerTaxProfile, CustomerBillingProfile, CustomerAddress
│  │  ├─ views.py              # Customer CRUD, multi-tenant access management
│  │  ├─ forms.py              # Customer forms with CUI validation, registration alignment
│  │  └─ admin.py              # Comprehensive admin interface
│  │
│  ├─ billing/                  # 💰 Invoicing & Payment Processing
│  │  ├─ models.py             # ProformaInvoice, Invoice, InvoiceLine, Payment, CreditLedger
│  │  ├─ views.py              # Billing interface, invoice management
│  │  └─ admin.py              # Comprehensive billing admin with Romanian compliance
│  │
│  ├─ tickets/                  # 🎫 Support System & SLA Tracking
│  │  ├─ models.py             # Ticket, TicketComment, TicketAttachment, TicketWorklog, SupportCategory
│  │  ├─ views.py              # Support interface, ticket management
│  │  └─ admin.py              # Advanced ticket admin with SLA tracking
│  │
│  ├─ provisioning/             # 🖥️ Hosting Services & Server Management
│  │  ├─ models.py             # ServicePlan, Server, Service, ProvisioningTask
│  │  │                        # ServiceRelationship, ServiceDomain, ServiceGroup, ServiceGroupMember
│  │  ├─ views.py              # Service management interface
│  │  └─ admin.py              # Server and service management admin
│  │
│  ├─ domains/                  # 🌐 Domain Management & TLD Configuration
│  │  ├─ models.py             # TLD, Registrar, Domain, DomainOrderItem
│  │  ├─ views.py              # Domain CRUD, renewal, transfer operations
│  │  ├─ admin.py              # Complete domain management interface
│  │  └─ urls.py               # Domain management endpoints
│  │
│  ├─ integrations/             # 🔌 External Service Integrations & Webhooks
│  │  ├─ models.py             # WebhookEvent, WebhookDelivery (deduplication system)
│  │  ├─ views.py              # Webhook endpoints and management API
│  │  ├─ webhooks/             # Webhook processing framework
│  │  │  ├─ base.py           # Common deduplication and retry logic
│  │  │  ├─ stripe.py         # Stripe payment webhook handling
│  │  │  └─ [future].py       # Virtualmin, PayPal, registrar webhooks
│  │  ├─ admin.py              # Webhook monitoring and management
│  │  └─ management/commands/  # Webhook processing commands
│  │
│  ├─ audit/                    # 📋 Compliance & Audit Logging
│  │  ├─ models.py             # AuditEvent, DataExport, ComplianceLog (immutable)
│  │  ├─ views.py              # Audit trail views (read-only)
│  │  └─ admin.py              # Compliance admin with security controls
│  │
│  │  # Note: website app not yet implemented - planned for future marketing needs
│  │
│  └─ common/                   # 🔧 Shared Utilities & Infrastructure
│     ├─ types.py              # Result types, Romanian validators (CUI, VAT)
│     ├─ utils.py              # Shared utilities, Romanian formatting
│     ├─ middleware.py         # Request ID middleware
│     ├─ context_processors.py # Template context for Romanian business
│     ├─ views.py              # Shared views (health check, dashboard)
│     └─ management/           # Django management commands
│        └─ commands/
│           └─ generate_sample_data.py # Sample data for development
│
├─ apps/ui/                     # 🎨 User Interface Components
│  ├─ templatetags/             # Django template tags for Romanian business
│  │  ├─ ui_components.py      # HTMX components: buttons, modals, tables
│  │  └─ formatting.py         # Romanian formatting: currency, dates, CUI
│  ├─ models.py                # UI-specific models (themes, preferences)
│  └─ apps.py                  # App configuration
│
├─ assets/                      # 🎨 Frontend Assets & Design System
│  ├─ styles/                   # CSS with Romanian design tokens
│  │  ├─ tokens.css            # Romanian brand colors, typography, spacing
│  │  ├─ app.css               # Tailwind integration, business components
│  │  └─ email.css             # Email-specific styles for notifications
│  ├─ tailwind.config.js        # Tailwind configuration with Romanian utilities
│  └─ icons/                    # SVG icon library for business interface
│
├─ templates/                   # 📄 Django Templates (Server-Rendered)
│  ├─ base.html                # Base template with Romanian meta tags
│  ├─ dashboard.html           # Main dashboard layout
│  ├─ components/              # Reusable template components
│  ├─ billing/                 # Billing-specific templates
│  ├─ customers/               # Customer management templates
│  ├─ users/                   # Authentication templates
│  └─ website/                 # Marketing pages (pre-Hugo migration)
│
├─ static/                      # 📦 Static Files (Production)
│  ├─ css/                     # Compiled CSS (Tailwind output)
│  ├─ js/                      # Minimal JavaScript (HTMX, Alpine.js)
│  ├─ images/                  # Romanian branding assets
│  └─ build/                   # Build artifacts, manifests
│
├─ worker/                      # ⚙️ Background Job Processing
│  ├─ rq_worker.py             # Redis Queue worker with Romanian business context
│  └─ beat_scheduler.py        # Periodic task scheduler (invoices, backups, monitoring)
│
├─ scripts/                     # 🔧 Operational Scripts
│  ├─ backup.py                # Database & media backup with S3 integration
│  ├─ deploy.py                # Zero-downtime deployment with rollback
│  └─ migrate_data.py          # Data migration utilities
│
├─ tests/                       # 🧪 End-to-End & Integration Tests
│  ├─ conftest.py              # Pytest configuration, fixtures
│  ├─ test_billing.py          # Billing workflow tests
│  ├─ test_customers.py        # Customer management tests
│  └─ e2e/                     # End-to-end user journey tests
│
├─ requirements/                # 📋 Python Dependencies
│  ├─ base.txt                 # Core dependencies: Django, Redis, Django-Q2
│  ├─ dev.txt                  # Development: debug toolbar, pytest, mypy
│  └─ prod.txt                 # Production: Gunicorn, Sentry, monitoring
│
├─ docs/                        # 📚 Documentation
│  ├─ decisions/               # Architecture Decision Records (ADRs)
│  │  ├─ 001-project-structure-enhanced-option-a.md
│  │  └─ 002-database-structure.md
│  └─ deployment/              # Deployment guides, runbooks
│
├─ pyproject.toml              # Python project configuration (ruff, mypy, pytest)
├─ .env.example                # Environment variables template (200+ Romanian defaults)
├─ Makefile                    # Development workflow automation (.venv integration)
├─ docker-compose.yml          # Local development environment
├─ Dockerfile                  # Production container configuration
└─ manage.py                   # Django management entry point
```

---

## 🔥 Strategic Seams Pattern

Every Django app follows this pattern to enable future migration without rewrites:

### **Service Layer** (`services.py`)
```python
# Business logic - pure functions when possible
def generate_invoice(customer_id: int, items: List[BillingItem]) -> Result[Invoice]:
    # Domain logic here - future core/ extraction target
    return InvoiceRepository.create_with_sequential_number(customer_id, items)
```

### **Repository Layer** (`repos.py`)
```python
# Data access with query optimization
class InvoiceRepository:
    @staticmethod
    def create_with_sequential_number(...) -> Invoice:
        # Expected queries: 3 (documented for performance)
        return Invoice.objects.select_related('customer').create(...)
```

### **Gateway Layer** (`gateways.py`)
```python
# External service integrations - future infra/ extraction target
class StripeGateway:
    def create_payment_intent(...) -> StripeResponse:
        # Idempotent operations with retries
        return self._stripe_client.payment_intents.create(...)
```

---

## � Domain Management Architecture

### **Multi-Registrar Support**
```python
# TLD configuration with registrar assignments
class TLD(models.Model):
    extension = models.CharField(max_length=10)  # 'com', 'ro', 'eu'
    registrar = models.ForeignKey(Registrar)     # Primary registrar
    registration_price_cents = models.BigIntegerField()
    renewal_price_cents = models.BigIntegerField()
    transfer_price_cents = models.BigIntegerField()
    
# Multi-registrar domain distribution
registrar_assignment = {
    '.com': 'namecheap',      # International domains
    '.ro': 'rotld',           # Romanian domains
    '.eu': 'godaddy',         # European domains
}
```

### **Domain Lifecycle Management**
```python
# Complete domain workflow
def register_domain(domain_name: str, customer: Customer, years: int) -> Domain:
    # 1. Check availability via registrar API
    # 2. Create domain record with pending status
    # 3. Submit registration via webhook-enabled API
    # 4. Update status when webhook confirms registration
    # 5. Schedule renewal reminders
    return Domain.objects.create_with_registration(...)
```

### **Romanian TLD Compliance**
- **`.ro` domain validation** - Romanian entity requirements
- **ROTLD integration** - Official Romanian registry API
- **Local billing** - Romanian VAT for .ro domains
- **Grace periods** - Romanian-specific redemption rules

---

## 🔗 Service Relationship Architecture

### **Service Dependencies**
```python
# Complex hosting package hierarchies
class ServiceRelationship(models.Model):
    parent_service = models.ForeignKey(Service, related_name='child_relationships')
    child_service = models.ForeignKey(Service, related_name='parent_relationships')
    relationship_type = models.CharField(choices=[
        ('addon', 'Add-on Service'),           # Backup, SSL, monitoring
        ('included', 'Included Service'),       # Free subdomain, basic SSL
        ('dependency', 'Required Dependency'),  # Domain for hosting
        ('upgrade', 'Service Upgrade'),         # VPS to dedicated server
    ])
    billing_impact = models.CharField(choices=[
        ('separate', 'Billed Separately'),      # Additional charges
        ('included', 'Included in Parent'),     # No extra cost
        ('discounted', 'Discounted Rate'),      # Reduced pricing
    ])
```

### **Service Groups & Packages**
```python
# Multi-service hosting packages
class ServiceGroup(models.Model):
    name = models.CharField(max_length=100)  # "VPS Premium Package"
    customer = models.ForeignKey(Customer)
    group_type = models.CharField(choices=[
        ('package', 'Hosting Package'),         # VPS + Domain + SSL
        ('cluster', 'Service Cluster'),         # Load-balanced services
        ('bundle', 'Product Bundle'),           # Marketing bundle
    ])
    
# Coordinated operations across service groups
def suspend_service_group(group: ServiceGroup):
    # Suspend all services in coordinated manner
    # Maintain dependencies (don't suspend domain if hosting active)
    # Send unified notifications
```

### **Domain-Service Binding**
```python
# Link domains to hosting services
class ServiceDomain(models.Model):
    service = models.ForeignKey(Service, related_name='domains')
    domain = models.ForeignKey(Domain, related_name='services')
    domain_type = models.CharField(choices=[
        ('primary', 'Primary Domain'),          # Main website domain
        ('addon', 'Add-on Domain'),            # Additional domain on same hosting
        ('subdomain', 'Subdomain'),            # blog.example.com
        ('redirect', 'Domain Redirect'),        # Forward to primary
    ])
    dns_management = models.BooleanField(default=True)
    ssl_enabled = models.BooleanField(default=False)
```

---

## 🔌 Integration Architecture

### **Webhook Deduplication System**
```python
# Production-ready webhook handling
class WebhookEvent(models.Model):
    source = models.CharField()      # 'stripe', 'virtualmin', 'registrar'
    event_id = models.CharField()    # External service unique ID
    status = models.CharField()      # 'pending', 'processed', 'failed', 'skipped'
    
    class Meta:
        unique_together = ('source', 'event_id')  # Prevents duplicates
```

### **External Service Framework**
```python
# Standardized external integrations
class BaseWebhookProcessor:
    def process_webhook(self, payload, signature):
        # 1. Verify signature
        # 2. Check for duplicates
        # 3. Route to specific handler
        # 4. Update status with retry logic
        
# Service-specific processors
StripeWebhookProcessor()      # Payment events
VirtualminWebhookProcessor()  # Server provisioning
RegistrarWebhookProcessor()   # Domain events
```

---

## �🇷🇴 Romanian Business Features

### **Legal Compliance**
- **Sequential invoice numbering** for Romanian tax compliance
- **e-Factura integration** with XML generation and API submission
- **VAT calculations** (19% Romanian VAT, EU validation)
- **GDPR compliance** with data exports and right to erasure
- **CUI validation** and formatting (RO 12345678)

### **Currency & Formatting**
```python
# Romanian business formatting
{{ invoice.total|romanian_currency }}     # 1.234,56 RON
{{ amount|romanian_vat }}                 # 95,22 RON TVA
{{ company.cui|cui_format }}              # RO 12345678
{{ invoice.date|romanian_date }}          # 15 ian. 2024
{{ created_at|romanian_relative_date }}   # acum 2 ore
```

### **Multi-Tenant Relationship Model**
```python
# Users ↔ Customers is many-to-many through UserCustomerRole
user.customers.all()  # Multiple customer accounts
UserCustomerRole.objects.filter(user=user, role="billing")
```

---

## ⚡ Performance Architecture

### **Query Budget Pattern**
```python
# Every list view MUST have documented query budget
def get_invoices_with_customer(customer_id: int):
    # Expected queries: 2 (1 for invoices, 1 for prefetch)
    return Invoice.objects.filter(customer_id=customer_id)\
        .select_related('customer')\
        .prefetch_related('line_items')\
        .order_by('-created_at')  # Uses index: (customer_id, -created_at)
```

### **N+1 Prevention Checklist**
- Template loops showing `.user`, `.plan` → **`select_related()`**
- Many-to-many relations → **`prefetch_related()`**
- Counts in lists → **`annotate(Count())`**
- Fat models in lists → **`only()`/`defer()`**

### **Database Optimization**
```python
# Index strategy for Romanian business queries
class Migration(migrations.Migration):
    operations = [
        migrations.AddIndex(
            model_name="invoice",
            index=models.Index(
                fields=["customer_id", "-created_at"],
                name="inv_cust_created_idx",
            ),
        ),
    ]
```

---

## 🎨 UI Component System

### **Zero-Runtime JavaScript Architecture**
- **Server-rendered components** with HTMX for interactions
- **No build step required** for basic functionality
- **Progressive enhancement** with Alpine.js for complex interactions

### **Romanian HTMX Components**
```django
<!-- Romanian business button with HTMX -->
{% button "Plătește Factura" variant="success" hx_post="/billing/pay/" %}

<!-- Modal for invoice workflows -->
{% modal "invoice-modal" "Factură Nouă" size="lg" %}

<!-- Romanian form input with validation -->
{% input_field "cui" label="CUI Firmă" romanian_validation=True %}

<!-- Data table with Romanian pagination -->
{% data_table headers=invoice_headers rows=invoice_data sortable=True %}
```

### **Design Token System** (Hugo Portable)
```css
/* Romanian hosting brand tokens */
:root {
  --brand-h: 220; --brand-s: 90%; --brand-l: 56%;
  --bg: #0b0c10; --bg-elev: #111217; --content: #e6e8eb;
  --primary: hsl(var(--brand-h) var(--brand-s) var(--brand-l));
  --radius: 0.75rem;
}
```

---

## ⚙️ Background Processing Architecture

### **Redis Queue System**
```python
# Queue hierarchy for Romanian business priorities
QUEUES = {
    'high':    # Critical: payment processing, security alerts
    'default': # Standard: invoice generation, provisioning
    'low':     # Background: backups, cleanup, monitoring
    'email':   # Email notifications and marketing
    'reports': # Analytics and business intelligence
}
```

### **Scheduled Tasks** (Romanian Business Hours)
```python
# Daily tasks aligned with Romanian business operations
"08:00": generate_daily_invoices,      # Morning invoice generation
"10:00": send_payment_reminders,       # Business hours reminders
"02:00": backup_servers,               # Night-time maintenance
"18:00": generate_daily_reports,       # End-of-day reporting

# Monthly Romanian tax compliance
"25th": generate_romanian_tax_reports,  # Tax deadline preparation
```

---

## 🔒 Security Architecture

### **Production Security Headers**
```python
# config/settings/prod.py
SECURE_SSL_REDIRECT = True
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
CSP_DEFAULT_SRC = ["'self'"]
SECURE_HSTS_SECONDS = 31536000
```

### **Authentication & Authorization**
- **2FA required** via TOTP for admin users
- **Session security** with secure cookies and CSRF protection
- **Rate limiting** on authentication endpoints
- **Audit logging** for all sensitive operations
- **Request ID tracking** for forensic analysis

---

## 🚀 Deployment Architecture

### **Zero-Downtime Deployment**
```bash
# Atomic deployment with health checks
./scripts/deploy.py --branch main
# → Git clone → Dependencies → Migrations → Symlink → Health check
```

### **Backup & Recovery**
```bash
# Automated backup system
./scripts/backup.py
# → Database → Media → Config → S3 upload → Retention cleanup
```

### **Infrastructure Stack**
- **Application:** Gunicorn + Django
- **Web Server:** Nginx (static files, SSL termination)
- **Database:** PostgreSQL (primary), Redis (cache/queues)
- **Background Jobs:** Redis Queue + Python workers
- **Storage:** Local files + S3 (backups)
- **Monitoring:** Sentry (errors) + structured logging

---

## 🔄 Migration Path to Option B

Move to layered architecture when **any 2 apply**:
- Team grows to 3+ developers
- Adding second payment provider (PayPal)
- Adding second provisioning system  
- Complex domain rules emerge (resellers, advanced pricing)

### **Extraction Strategy**
1. **Services → Core Layer** - Business logic extraction
2. **Repos → Infrastructure** - Data access layer
3. **Gateways → Infrastructure** - External integrations
4. **Async Tasks → Application Services** - Background processing

---

## 📊 Monitoring & Observability

### **Structured Logging**
```json
{
  "time": "2025-08-19T10:30:45Z",
  "level": "INFO", 
  "message": "🧾 Invoice generated successfully",
  "request_id": "req_abc123",
  "customer_id": 456,
  "invoice_id": 789
}
```

### **Health Checks**
- **Application health:** `/health/` endpoint
- **Database connectivity:** PostgreSQL/Redis status
- **External services:** Stripe/Virtualmin API status
- **Queue processing:** Background job lag monitoring

### **Performance Metrics**
- **Query budget enforcement** in tests
- **Response time monitoring** for Romanian business hours
- **Background job processing** times and failure rates
- **Romanian tax compliance** reporting and alerts

---

## 🎯 Romanian Hosting Provider Context

### **Business Model**
- **Hosting services:** Shared, VPS, dedicated servers with service relationships
- **Domain management:** Romanian .ro domains, international TLDs with multi-registrar support
- **Service packages:** Complex hosting packages with dependencies and add-ons
- **Support system:** SLA tracking, knowledge base in Romanian
- **Billing:** Proforma → Final invoice flow, VAT compliance, service group billing

### **Integration Ecosystem**
- **Payment:** Stripe (cards), Romanian bank transfers (webhook-ready infrastructure)
- **Provisioning:** Virtualmin for cPanel-style hosting (webhook integration prepared)
- **Domain Management:** Multi-registrar support (Namecheap, GoDaddy, ROTLD for .ro)
- **Compliance:** e-Factura API for Romanian tax system
- **Monitoring:** Server health, uptime, resource usage
- **Communication:** Email notifications, SMS alerts
- **Webhook Deduplication:** Production-ready framework prevents double-processing

---

## 📈 Performance Targets

### **Response Times** (Romanian Business Hours 9-18)
- **Dashboard:** < 200ms
- **Invoice generation:** < 500ms  
- **Customer search:** < 100ms
- **Payment processing:** < 2s

### **Background Processing**
- **Invoice generation:** < 30s per batch
- **Server provisioning:** < 5 minutes
- **Backup creation:** < 15 minutes
- **Email delivery:** < 1 minute

### **Availability**
- **Uptime target:** 99.9% (8.76 hours downtime/year)
- **Maintenance window:** Sundays 2-4 AM Romanian time
- **Recovery time:** < 15 minutes from backup

---

## 📊 Current Implementation Status

### ✅ **Completed** (Production Ready)
- **Core Django foundation** - Settings, URL routing, middleware
- **All 11 Django apps** with complete models and relationships
- **Database schema** - All migrations applied, normalized design with domain management
- **Comprehensive admin interfaces** - Full CRUD with Romanian business context
- **Authentication system** - Custom user model, 2FA ready
- **Romanian compliance** - CUI validation, VAT calculations, address handling
- **Domain management system** - Complete TLD, registrar, and domain lifecycle management
- **Service relationships** - Advanced service dependencies and grouping
- **Webhook deduplication** - Production-ready external service integration infrastructure
- **Development environment** - Docker, sample data generation
- **Code quality** - Strategic linting framework (Ruff + MyPy), performance optimizations, security-first approach

### 🚧 **In Progress** (Development Stage)
- **Template system** - Base templates complete, forms need styling consistency
- **Frontend integration** - HTMX components partially implemented
- **UI polish** - Navigation, forms, and styling refinements
- **Test coverage** - Core tests exist, need comprehensive coverage

### 📅 **Planned** (Future Releases)
- **External integrations** - Stripe, e-Factura, Virtualmin APIs (webhook foundation ready)
- **Background processing** - Django-Q2 task implementation
- **Advanced reporting** - Business intelligence dashboards
- **Mobile responsiveness** - Complete mobile optimization
- **Production deployment** - Docker compose, monitoring, backups

### 🏗️ **Architecture Readiness**
- **Scalability seams** - Repository and service patterns ready for extraction
- **Security foundation** - CSRF, authentication, audit logging implemented
- **Romanian context** - Business rules, validation, formatting complete
- **Database optimization** - Indexes, query patterns, performance considerations
- **Domain infrastructure** - Multi-registrar support, automated renewals, Romanian TLD compliance
- **Service orchestration** - Complex hosting package management and dependencies
- **Integration framework** - Webhook deduplication prevents double-processing in production

---

*This architecture documentation is maintained alongside ADR collection and updated as the system evolves. For implementation details, see individual app documentation in `/docs/decisions/`.*
