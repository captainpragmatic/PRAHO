# ADR-001: Project Structure - Enhanced Option A with Strategic Seams

**Status:** ✅ Accepted  
**Date:** 2025-08-15  
**Authors:** Development Team  
**Reviewers:** Technical Lead  

## Context

We are building a hosting provider PRAHO Platform/billing system for the Romanian market with the following requirements:

- **MVP Timeline:** 4-6 weeks with 1-2 developers
- **Technical Stack:** Django + HTMX + Tailwind CSS
- **Compliance:** Romanian e-Factura, GDPR, DSA requirements
- **Future Plans:** Marketing site migration to Hugo, potential microservices scaling
- **Integrations:** Stripe (payment), Virtualmin (provisioning), e-Factura API
- **Security:** High-security posture required for hosting provider

We evaluated two main architectural approaches:
- **Option A:** Modular monolith (fastest to MVP)
- **Option B:** Layered architecture with core/infra/apps separation

## Decision

We choose **Enhanced Option A with Strategic Seams** - a modular monolith structure that includes architectural seams to enable future migration to Option B without rewrites.

### Complete Directory Structure

```bash
pragmatichost/                  # 🚀 Root directory for Romanian hosting provider PRAHO Platform
├─ config/                      # ⚙️ Django project configuration (not an app)
│  ├─ settings/                 # Environment-specific Django settings
│  │  ├─ base.py               # Shared defaults: DB config, installed apps, middleware
│  │  ├─ dev.py                # Development: DEBUG=True, django-debug-toolbar, SQLite
│  │  ├─ test.py               # Testing: in-memory DB, disabled cache, fast tests
│  │  └─ prod.py               # Production: security headers, Sentry, Redis cache, PostgreSQL
│  ├─ urls.py                  # Root URL configuration, includes app URLs
│  ├─ asgi.py                  # ASGI server entry point for async Django
│  ├─ wsgi.py                  # WSGI server entry point for traditional Django
│  └─ logging.py               # Structured logging with request IDs, JSON output for prod
├─ apps/                        # 📦 Django applications - each is a bounded business context
│  ├─ users/                    # � User management, authentication & authorization
│  │  ├─ models.py             # User (extends AbstractUser), Session, TwoFactorAuth
│  │  ├─ services.py           # 🔥 Business logic: registration, login, 2FA setup, password reset
│  │  ├─ repos.py              # 🔥 Data access: user queries, session management, avoid N+1
│  │  ├─ views.py              # HTTP endpoints: login/logout, registration, profile
│  │  ├─ forms.py              # Django forms: login, registration, 2FA setup with validation
│  │  ├─ admin.py              # Django admin customization: user management, 2FA status
│  │  ├─ tests/                # Unit tests for services, integration tests for views
│  │  │  ├─ test_services.py   # Test business logic without Django overhead
│  │  │  ├─ test_views.py      # Test HTTP endpoints with Django test client
│  │  │  └─ test_models.py     # Test model methods and constraints
│  │  └─ migrations/           # Django database migrations for user-related tables
│  ├─ customers/                # 🏢 Business entities that purchase hosting services
│  │  ├─ models.py             # Customer (organization), Contact, Address, VATInfo, UserCustomerRole
│  │  ├─ services.py           # 🔥 Customer onboarding, GDPR data exports, VAT validation
│  │  ├─ repos.py              # 🔥 Customer queries with billing data, prefetch optimization
│  │  ├─ views.py              # Customer CRUD, customer switching UI, contact management
│  │  ├─ forms.py              # Customer creation/edit forms, VAT number validation
│  │  ├─ admin.py              # Customer management in Django admin, GDPR tools
│  │  ├─ tests/                # Customer business logic and GDPR compliance tests
│  │  │  ├─ test_gdpr.py       # Test GDPR export, deletion, consent management
│  │  │  └─ test_vat.py        # Test Romanian VAT number validation
│  │  └─ migrations/           # Customer, contact, and role relationship tables
│  ├─ billing/                  # 💰 Financial operations, invoicing & payment processing
│  │  ├─ models.py             # Invoice, Payment, Product, Subscription, TaxRate
│  │  ├─ services.py           # 🔥 Invoice generation, Romanian tax calculation, payment processing
│  │  ├─ repos.py              # 🔥 Billing queries with proper joins, financial reporting data
│  │  ├─ gateways.py           # 🔥 External integrations: Stripe client, e-Factura API client
│  │  ├─ webhooks.py           # Stripe webhook handlers: payment confirmation, failed payments
│  │  ├─ views.py              # Invoice management UI, payment dashboard, financial reports
│  │  ├─ forms.py              # Invoice creation forms, payment method forms
│  │  ├─ admin.py              # Financial administration: invoice management, payment tracking
│  │  ├─ tests/                # Financial logic tests, tax calculation verification
│  │  │  ├─ test_invoicing.py  # Test invoice generation with Romanian e-Factura rules
│  │  │  ├─ test_taxes.py      # Test VAT calculation, tax compliance
│  │  │  └─ test_webhooks.py   # Test Stripe webhook processing, idempotency
│  │  └─ migrations/           # Billing tables: invoices, payments, products
│  ├─ tickets/                  # 🎫 Customer support system & knowledge base
│  │  ├─ models.py             # Ticket, Reply, Attachment, Category, SLA, KnowledgeArticle
│  │  ├─ services.py           # 🔥 Ticket routing, SLA tracking, escalation logic
│  │  ├─ repos.py              # 🔥 Support queries: ticket queues, performance metrics
│  │  ├─ views.py              # Support dashboard, ticket management, customer portal
│  │  ├─ forms.py              # Ticket creation forms, reply forms with file uploads
│  │  ├─ admin.py              # Support staff tools: ticket assignment, bulk actions
│  │  ├─ tests/                # Support workflow tests, SLA compliance tests
│  │  └─ migrations/           # Support tables: tickets, replies, knowledge base
│  ├─ provisioning/             # 🖥️ Server & hosting service provisioning automation
│  │  ├─ models.py             # Server, HostingPlan, Service, ProvisioningJob, Resource
│  │  ├─ services.py           # 🔥 Hosting account creation, resource allocation, service management
│  │  ├─ repos.py              # 🔥 Server queries, resource utilization, provisioning status
│  │  ├─ gateways.py           # 🔥 Virtualmin/Webmin API client, server control panel integration
│  │  ├─ tasks.py              # 🔥 Async RQ jobs: account creation, service deployment, backups
│  │  ├─ views.py              # Service management UI, server dashboard, resource monitoring
│  │  ├─ admin.py              # Server administration: manual provisioning, troubleshooting
│  │  ├─ tests/                # Provisioning workflow tests, integration tests with mocked APIs
│  │  └─ migrations/           # Provisioning tables: servers, services, jobs
│  ├─ audit/                    # 📋 Compliance & audit trail (append-only logging)
│  │  ├─ models.py             # AuditLog (immutable), AuditEvent, ComplianceReport
│  │  ├─ services.py           # 🔥 Audit event recording, compliance report generation
│  │  ├─ views.py              # Audit trail viewer (admin/compliance staff only)
│  │  ├─ admin.py              # Read-only audit log interface, export tools
│  │  ├─ tests/                # Audit logging tests, compliance verification
│  │  └─ migrations/           # Audit tables with proper indexes for time-series queries
│  ├─ website/                  # 🌐 Public marketing website (future Hugo migration path)
│  │  ├─ views.py              # Marketing pages: homepage, pricing, features, contact
│  │  ├─ api.py                # Public API endpoints: /api/public/status.json, /api/public/pricing.json
│  │  ├─ templates/website/    # Marketing page templates (will be migrated to Hugo)
│  │  │  ├─ index.html         # Homepage with hero section, features, testimonials
│  │  │  ├─ pricing.html       # Pricing plans, comparison table, Romanian currency
│  │  │  ├─ features.html      # Hosting features, technical specifications
│  │  │  └─ contact.html       # Contact form, Romanian business information
│  │  └─ tests/                # Marketing page tests, SEO meta tag verification
│  └─ common/                   # � Shared utilities, types & middleware (no business logic)
│     ├─ types.py              # 🔥 Shared types: Result[T], Ok, Err for error handling
│     ├─ testing.py            # 🔥 Test utilities: assert_max_queries, factory helpers
│     ├─ middleware.py         # 🔥 Request ID tracking, CSP headers, audit middleware
│     ├─ decorators.py         # Authentication decorators, rate limiting, permissions
│     ├─ utils.py              # Date formatting, currency conversion, Romanian localization
│     └─ tests/                # Tests for shared utilities and middleware
├─ ui/                          # 🎨 Reusable UI components (framework-agnostic, portable to Hugo)
│  ├─ templates/                # Template directory structure
│  │  ├─ components/           # 🧩 Atomic, reusable HTMX-powered components
│  │  │  ├─ button.html        # Button variants: primary, secondary, danger, loading states
│  │  │  ├─ input.html         # Form inputs with validation states, Romanian localization
│  │  │  ├─ modal.html         # HTMX modal component: confirmation dialogs, forms
│  │  │  ├─ table.html         # Sortable data tables with pagination, search, export
│  │  │  ├─ toast.html         # Success/error notifications with auto-dismiss
│  │  │  ├─ card.html          # Content cards: dashboards, invoice summaries
│  │  │  └─ breadcrumb.html    # Navigation breadcrumbs for complex workflows
│  │  ├─ layouts/              # 📐 Page layout templates
│  │  │  ├─ base.html          # Root template: meta tags, CSP, Tailwind CSS, HTMX
│  │  │  ├─ app.html           # Authenticated user layout: sidebar, header, notifications
│  │  │  ├─ public.html        # Marketing layout: header, footer, SEO optimization
│  │  │  └─ admin.html         # Admin dashboard layout: admin navigation, tools
│  │  └─ pages/                # 📄 Full page templates (compose components + layouts)
│  │     ├─ dashboard.html     # Main dashboard: metrics, recent activity, quick actions
│  │     └─ error.html         # Error pages: 404, 500 with Romanian messaging
│  └─ templatetags/            # 🏷️ Django template tags for UI components
│     ├─ ui_components.py      # Inclusion tags for components: {% button %}, {% modal %}
│     └─ formatting.py         # Romanian formatting: money (RON), dates, VAT numbers
├─ assets/                      # 🎨 Frontend source files (build-time only, not served directly)
│  ├─ styles/                  # CSS source files for Tailwind processing
│  │  ├─ tokens.css            # 🔥 Design tokens: colors, spacing, typography (portable to Hugo)
│  │  ├─ app.css               # @tailwind directives + base application styles
│  │  └─ email.css             # Email-specific styles: inline-compatible, dark mode
│  ├─ icons/                   # 📐 SVG icon library (Lucide/Heroicons, CSP-friendly)
│  │  ├─ user.svg              # User management icons
│  │  ├─ billing.svg           # Financial icons
│  │  └─ server.svg            # Hosting/server icons
│  └─ tailwind.config.js       # 🔥 Tailwind configuration: Romanian brand colors, custom utilities
├─ static/                      # 📦 Static files served by web server (nginx/Apache)
│  ├─ build/                   # 🏗️ Built assets (gitignored, generated by CI/Tailwind CLI)
│  │  ├─ app.css               # Compiled Tailwind CSS with hash for caching
│  │  └─ app.css.map           # Source map for development debugging
│  └─ images/                  # 🖼️ Optimized images: logos, illustrations, favicons
├─ worker/                      # 🔄 Background job processing (separate from web process)
│  ├─ rq_worker.py             # Redis Queue worker entry point for async tasks
│  └─ beat_scheduler.py        # Periodic task scheduler: invoicing, cleanup, monitoring
├─ scripts/                     # 🛠️ Operational scripts & management commands
│  ├─ backup.py                # Database backup script with Romanian cloud storage
│  ├─ deploy.py                # Zero-downtime deployment automation
│  └─ migrate_data.py          # Data migration utilities for production updates
├─ tests/                       # 🧪 Integration & end-to-end tests (cross-app functionality)
│  ├─ conftest.py              # Pytest configuration: fixtures, database setup, mocks
│  ├─ e2e/                     # 🎭 Critical user journey tests (Playwright/Selenium)
│  │  ├─ test_user_registration.py  # Complete signup → payment → provisioning flow
│  │  ├─ test_invoice_generation.py # Billing cycle → invoice → e-Factura submission
│  │  └─ test_support_workflow.py   # Ticket creation → assignment → resolution
│  ├─ test_performance.py      # 🚀 Query budget enforcement, page load speed tests
│  └─ fixtures/                # 📋 Shared test data: sample customers, invoices, users
├─ docs/                        # 📚 Documentation & architectural decisions
│  ├─ README.md                # Project overview, setup instructions, Romanian context
│  ├─ ARCHITECTURE.md          # System architecture, component relationships
│  ├─ CLAUDE.md                # AI context file for code generation & assistance
│  ├─ API.md                   # API documentation for public endpoints
│  └─ decisions/               # 📋 Architectural Decision Records (ADRs)
│     ├─ 001-project-structure.md      # This document
│     ├─ 002-authentication-model.md   # Multi-tenant auth decisions
│     └─ 003-payment-processing.md     # Stripe integration & Romanian compliance
├─ .github/                     # 🤖 GitHub automation & CI/CD
│  ├─ workflows/               # GitHub Actions workflows
│  │  ├─ tests.yml             # CI: run tests, diff-coverage, security scan
│  │  ├─ deploy.yml            # CD: automated deployment with Romanian infrastructure
│  │  └─ security.yml          # Security scanning: dependencies, SAST, secrets
│  ├─ copilot-instructions.md  # GitHub Copilot context for consistent code generation
│  └─ ISSUE_TEMPLATE/          # Issue templates for bugs, features, security
├─ requirements/                # 📦 Python dependencies (environment-specific)
│  ├─ base.txt                 # Core dependencies: Django, psycopg2, redis
│  ├─ dev.txt                  # Development: django-debug-toolbar, pytest, black
│  └─ prod.txt                 # Production: gunicorn, sentry-sdk, newrelic
├─ manage.py                    # 🐍 Django management script (standard)
├─ Makefile                     # 🔨 Development commands: test, build-css, deploy, backup
├─ pyproject.toml              # 🛠️ Python project config: ruff linting, mypy type checking, coverage
├─ docker-compose.yml          # 🐳 Local development environment: PostgreSQL, Redis, MailHog
└─ .env.example                # 🔐 Environment variables template with Romanian defaults
```

### Strategic Seams (Future-Proofing)

Each app includes these architectural boundaries:
- **`services.py`** - Business logic (future `core/` extraction)
- **`repos.py`** - Data access patterns (future `infra/db/` migration)
- **`gateways.py`** - External service clients (future `infra/gateways/`)

## Rationale

### Why Enhanced Option A

1. **Speed to MVP:** Standard Django structure, minimal ceremony
2. **Team Size Match:** Optimal for 1-2 developers
3. **Learning Curve:** Low overhead, no complex layering
4. **AI-Friendly:** Clear app boundaries for code generation

### Why Not Pure Option B

1. **Over-engineering Risk:** Complex layering before domain is proven
2. **Slower Development:** Extra interfaces slow small team
3. **Premature Abstraction:** Domain boundaries will evolve post-launch

### Why Strategic Seams

1. **Migration Path:** A→B transition is file moves, not rewrites
2. **Clean Code:** Services/repos patterns prevent technical debt
3. **Testability:** Business logic separated from framework concerns
4. **Performance:** Repository pattern enables query optimization

## Consequences

### Positive

- **Fast MVP delivery** within 4-6 week timeline
- **Maintainable code** with clear separation of concerns
- **Future flexibility** for scaling to multiple developers
- **Tailwind portability** for Hugo migration
- **Security-first** architecture with audit trails

### Negative

- **More files** than typical Django app structure
- **Discipline required** to maintain service/repo boundaries
- **Import complexity** slight increase in import paths

### Risks & Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| Seams ignored, code becomes tangled | High | Code review checklist, linting rules |
| Over-abstraction in services layer | Medium | Keep services focused on business logic only |
| N+1 queries despite repo pattern | High | Query budget tests, automated monitoring |

## Implementation Notes

### Phase 1: Foundation (Week 1)
- Django project setup with security defaults
- Authentication app with 2FA
- UI component system with Tailwind tokens
- Basic customer/billing models

### Phase 2: Core Features (Week 2-3)
- Invoice generation with e-Factura prep
- Stripe integration via gateways pattern
- Basic provisioning workflows
- Audit logging system

### Phase 3: Polish & Security (Week 4-5)
- HTMX interactivity
- Comprehensive test coverage
- Production deployment setup
- Performance optimization

### Phase 4: Future Evolution Triggers

Migrate to Option B when **any 2** apply:
- Team grows to 3+ developers
- Adding second payment provider (PayPal)
- Adding second provisioning system
- Complex domain rules emerge (resellers, complex pricing)

### Technology Decisions

- **Python 3.11+** with strict typing
- **Django 4.2 LTS** for stability
- **HTMX** for interactivity without SPA complexity
- **Tailwind CSS** with design tokens for portability
- **RQ + Redis** for background jobs
- **PostgreSQL** for production database

### Security Measures

- CSP/HSTS headers in production settings
- Request ID tracking for audit trails
- Rate limiting on API endpoints
- Proper CSRF/session security
- Structured logging with Sentry integration

### Performance Standards

- Query budgets: ≤6 queries per page render
- Page load: <200ms for authenticated pages
- Background job processing: <30s for provisioning
- Diff coverage: ≥90% on touched code

## References

- Original design document: `Pragmatic Hosting - PRAHO Platform design.md`
- Security requirements: Configuration in `config/settings/prod.py`
- UI component examples: `ui/templates/components/`

---

**Next ADR:** ADR-002 will document the specific authentication & authorization model for multi-tenant hosting provider requirements.
