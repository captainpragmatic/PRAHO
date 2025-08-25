# PRAHO Platform - PRAHO Really Automates Hosting Operations

> **PRAHO - Pragmatic Hosting Automation**  
> Built with Django 5.x for Romanian business compliance and hosting operations

[![Django 5.x](https://img.shields.io/badge/Django-5.x-green.svg)](https://www.djangoproject.com/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16+-blue.svg)](https://www.postgresql.org/)
[![License](https://img.shields.io/badge/license-AGPL--3.0--or--later-blue.svg)](LICENSE.md)
[![Code Quality](https://img.shields.io/badge/code%20quality-excellent-green.svg)]()

## 📋 Overview

**PRAHO Platform** is a comprehensive customer relationship management and billing system designed specifically for **Romanian hosting providers**. It provides complete business process management including customer onboarding, service provisioning, billing with Romanian VAT compliance, support ticket management, and regulatory compliance.

### 🎯 Key Features

- **🏢 Customer Management**: Multi-user customer accounts with role-based access
- **💰 Romanian Billing**: VAT-compliant invoicing with e-Factura integration
- **🎫 Support System**: SLA-based ticket management with time tracking
- **🖥️ Service Provisioning**: Automated hosting service deployment
- **📊 Compliance**: GDPR compliance with comprehensive audit trails
- **🔐 Security**: Two-factor authentication, encryption, and secure defaults

## 🏗️ Architecture

**Modular Monolith** (Enhanced Option A) with strategic seams for future microservices migration:

```
PRAHO Platform
├── 🔐 apps/users/          # Authentication & User Management
├── 👥 apps/customers/      # Customer Organization Management  
├── 💰 apps/billing/        # Invoice & Payment Processing
├── 🎫 apps/tickets/        # Customer Support System
├── 🖥️ apps/provisioning/   # Hosting Service Management
├── 📋 apps/audit/          # Compliance & Audit Logging
├── 🔧 apps/common/         # Shared Utilities & Validators
└── 🎨 apps/ui/             # UI Components & Templates
```

### Database Schema
- **PostgreSQL 16+** primary database
- **Redis** for caching and session storage
- **Normalized design** with soft deletes and audit trails

## 🚀 Quick Start

### Prerequisites
- **Python 3.11+**
- **PostgreSQL 16+**
- **Redis 7+**
- **Git**

### Installation

1. **Clone the repository**
```bash
git clone https://github.com/your-org/pragmatichost.git
cd pragmatichost
```

2. **Set up Python environment**
```bash
python -m venv .venv
source .venv/bin/activate  # Linux/Mac
# or .venv\Scripts\activate  # Windows
```

3. **Install dependencies**
```bash
pip install -r requirements/dev.txt
```

4. **Configure environment**
```bash
cp .env.example .env
# Edit .env with your database credentials
```

5. **Set up database**
```bash
# Create PostgreSQL database
createdb pragmatichost

# Run migrations
python manage.py migrate

# Create superuser
python manage.py createsuperuser
```

6. **Generate sample data** (optional)
```bash
python manage.py generate_sample_data
```

7. **Start development server**
```bash
python manage.py runserver
```

Visit [http://localhost:8000](http://localhost:8000) to access the application.

## 📱 Application Structure

### Core Apps

#### 🔐 Users (`apps/users/`)
- **Custom User model** (email-based, no username)
- **Two-factor authentication** with TOTP support
- **Role-based access control** (admin, support, billing, manager)
- **Customer membership relationships**
- **GDPR compliance features**

#### 👥 Customers (`apps/customers/`)
- **Normalized customer structure** with soft deletes
- **Romanian business validation** (CUI, VAT numbers)
- **Separated profiles**: Tax, Billing, Address (versioned)
- **Multi-user access** with granular permissions
- **Audit trail preservation**

#### 💰 Billing (`apps/billing/`)
- **Separate Proforma/Invoice models** (Romanian practice)
- **Sequential numbering** for tax compliance
- **Multi-currency support** (RON, EUR, USD)
- **Stripe integration** with webhook handling
- **e-Factura API compliance**
- **VAT calculations** (19% Romanian rate)

#### 🎫 Tickets (`apps/tickets/`)
- **SLA tracking** and automated escalation
- **Categorized tickets** with Romanian context
- **Time tracking** and worklog functionality
- **File attachments** with security scanning
- **Customer satisfaction ratings**

#### 🖥️ Provisioning (`apps/provisioning/`)
- **Service plans/packages** (shared, VPS, dedicated)
- **Server resource management** and monitoring
- **Automated provisioning** tasks with retry logic
- **Virtualmin integration** ready
- **Resource usage tracking**

#### 📋 Audit (`apps/audit/`)
- **Immutable audit trails** for all changes
- **GDPR data export** tracking
- **Romanian compliance logging**
- **Security incident tracking**

## 🔧 Configuration

### Settings Structure
```
config/settings/
├── base.py      # Core Django settings
├── dev.py       # Development configuration
├── prod.py      # Production security & optimization
└── test.py      # Testing configuration
```

### Environment Variables
Key environment variables in `.env`:
```bash
# Database
DB_NAME=pragmatichost
DB_USER=pragmatichost_user
DB_PASSWORD=secure_password
DB_HOST=localhost
DB_PORT=5432

# Security
DJANGO_SECRET_KEY=your-secret-key-here
DEBUG=False

# External Services
STRIPE_SECRET_KEY=sk_test_...
EFACTURA_API_KEY=your-efactura-key

# Romanian Business
COMPANY_NAME=PragmaticHost SRL
COMPANY_CUI=RO12345678
COMPANY_EMAIL=contact@pragmatichost.com
```

## 🎨 Frontend Technology

### Tech Stack
- **Tailwind CSS** - Utility-first styling
- **HTMX** - Server-rendered interactivity
- **Alpine.js** - Reactive components
- **Zero-runtime JavaScript** approach

### Templates
- **Component-based** template organization
- **Romanian localization** throughout
- **Responsive design** with mobile-first approach
- **Accessibility** (WCAG 2.1 AA compliant)

## 🧪 Testing

### Test Structure
```bash
# Run all tests
python manage.py test

# Run with coverage
coverage run --source='.' manage.py test
coverage report
coverage html  # Generate HTML report
```

### Test Categories
- **Unit tests** - Model validation, business logic
- **Integration tests** - View responses, form processing
- **API tests** - REST endpoints and serialization
- **Romanian compliance** - VAT, CUI validation

## 📊 Monitoring & Observability

### Logging
- **Structured JSON logging** in production
- **Audit trails** for all business operations
- **Security event logging**
- **Performance monitoring**

### Metrics
- **Business metrics** (customers, revenue, tickets)
- **Technical metrics** (response times, errors)
- **Compliance metrics** (GDPR, e-Factura status)

## 🚀 Deployment

### Docker Deployment
```bash
# Build and run with Docker Compose
docker-compose up -d

# Production deployment
docker-compose -f docker-compose.prod.yml up -d
```

### Production Checklist
- [ ] Environment variables configured
- [ ] SSL certificates installed
- [ ] Database backups configured
- [ ] Redis persistence enabled
- [ ] Static files served via CDN
- [ ] Monitoring and logging configured
- [ ] e-Factura API credentials configured

## 🔐 Security Features

### Authentication & Authorization
- **Email-based authentication** (no usernames for security)
- **Two-factor authentication** (TOTP)
- **Role-based access control**
- **Session security** with secure cookies

### Data Protection
- **Soft deletes** with audit trails
- **GDPR compliance** with data export/erasure
- **Encryption** for sensitive data
- **SQL injection prevention**

### Infrastructure Security
- **CSRF protection**
- **HTTPS enforcement**
- **Content Security Policy**
- **Rate limiting** on critical endpoints

## 🇷🇴 Romanian Compliance

### Business Compliance
- **Sequential invoice numbering** (required by law)
- **e-Factura integration** (mandatory for B2B)
- **VAT calculations** (19% Romanian VAT)
- **CUI validation** and formatting
- **Romanian phone number** validation

### GDPR Compliance
- **Data processing consent** tracking
- **Right to erasure** implementation
- **Data export** functionality
- **Audit logging** for data access

## 📚 Documentation

- **[Architecture Guide](docs/ARCHITECTURE.md)** - Detailed system design
- **[Linting Guide](docs/LINTING_GUIDE.md)** - Strategic code quality framework
- **[API Documentation](docs/API.md)** - REST API reference
- **[Deployment Guide](docs/DEPLOYMENT.md)** - Production deployment
- **[Romanian Business Guide](docs/ROMANIAN_COMPLIANCE.md)** - Compliance features
- **[ADRs](docs/adrs/)** - Architecture decision records
- **[Changelog](docs/CHANGELOG.md)** - Version history

## 🤝 Contributing

### Development Setup
1. Fork the repository
2. Create a feature branch: `git checkout -b feature/new-feature`
3. Make changes and add tests
4. Run quality checks: `make lint test`
5. Submit a pull request

### Code Quality
- **Strategic Linting Framework** - Ruff + MyPy with business-impact focus (see [Linting Guide](docs/LINTING_GUIDE.md))
- **Performance Optimization** - O(N) list operations, query optimization
- **Security-First Approach** - Manual credential review, OWASP compliance
- **AI/LLM Readability** - Consistent patterns, type annotations
- **Coverage** minimum 85%

## 📞 Support

### Getting Help
- **Documentation**: Check `/docs/` folder first
- **Issues**: Open a GitHub issue for bugs/features
- **Security**: Email security@pragmatichost.com

### Commercial Support
Professional support and customization available for Romanian hosting providers.

## 📄 License

This project is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later) - see the [LICENSE.md](LICENSE.md) file for details.

**Attribution Requirements**: If you deploy this software (including over a network), you must preserve the attribution notice in the "About" or similar screen as specified in the license.

## 📋 TODO: Missing Critical Features

### ❌ **MISSING CRITICAL FEATURES** (From Design Document)

#### **🔐 Security & Compliance Stack**
- ❌ **CSP/HSTS headers** configuration
- ❌ **2FA (TOTP)** implementation  
- ❌ **Rate limiting** middleware
- ❌ **CSRF protection** hardening
- ❌ **Idempotent webhooks** system

#### **📧 Communication System**
- ❌ **Email templates** (`EmailTemplate` model)
- ❌ **Email delivery log** (`EmailLog` model)
- ❌ **Notification system** integration

#### **🔄 Integration & Webhooks**
- ❌ **Webhook event system** (`WebhookEvent` model for Stripe/provider events)
- ❌ **Event deduplication** mechanism
- ❌ **Stripe Checkout** integration (referenced but not implemented)

#### **📊 Advanced Features**
- ❌ **Usage billing system** (`ServiceUsage` model)
- ❌ **Promotions/coupons** system (`Promotion` model)
- ❌ **Server management** (`Server` model for multiple Virtualmin instances)

#### **📈 Operations & Monitoring**
- ❌ **Sentry integration** (frontend + backend monitoring)
- ❌ **Structured logging** with request IDs
- ❌ **Alert system** for HTTP 5xx spikes and job queue lag

#### **🧪 Testing Infrastructure** 
- ❌ **Diff coverage ≥90%** enforcement
- ❌ **Query budget tests** for N+1 prevention  
- ❌ **Integration test** framework

#### **🇷🇴 Romanian Legal Compliance**
- ❌ **DSA notice-and-action** endpoint (Digital Services Act)
- ❌ **GDPR tooling** (data subject requests, cookie consent)
- ❌ **NIS2 compliance** checks (if applicable)

---

### 🚨 **PRIORITY IMPLEMENTATION ROADMAP**

#### **Phase 1: Security & Stability (Critical)** 🔥
1. **Security headers** (CSP/HSTS/CSRF hardening)
2. **Sentry monitoring** (frontend + backend)
3. **Rate limiting** middleware
4. **Structured logging** with request IDs

#### **Phase 2: Romanian Compliance (Legal Requirements)** ⚖️
1. **DSA notice-and-action** system
2. **GDPR data subject request** tooling
3. **Cookie consent** management
4. **Enhanced e-Factura** validation

#### **Phase 3: Business Operations (Revenue Impact)** 💰
1. **Stripe Checkout** full integration
2. **Email templates & delivery tracking**
3. **Webhook event** system 
4. **Usage billing** for VPS/resources

#### **Phase 4: Scale & Quality (Growth)** 📈
1. **Diff coverage** enforcement
2. **Query budget** tests
3. **Promotions/coupons** system
4. **Advanced monitoring** (job queue lag, etc.)

---

## 🎯 Roadmap

### Version 1.0 (Q1 2025)
- [ ] **Multi-tenant architecture** for hosting resellers
- [ ] **Advanced reporting** with business intelligence
- [ ] **API-first architecture** with GraphQL
- [ ] **Mobile application** for technicians

### Version 1.1 (Q2 2025)
- [ ] **Kubernetes deployment** support
- [ ] **Advanced monitoring** with Prometheus/Grafana
- [ ] **Machine learning** for predictive support
- [ ] **Integration marketplace** for third-party tools

---

**Built with ❤️ for Romanian hosting providers**

*PRAHO Platform - Professional hosting business automation*
