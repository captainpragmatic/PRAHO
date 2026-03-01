# PRAHO Platform - PRAHO Really Automates Hosting Operations

> **Pre-release software (v0.20.0-alpha)** - Under active development. Not yet recommended for production use.

[![Version](https://img.shields.io/badge/version-0.20.0--alpha-orange.svg)](CHANGELOG.md)
[![Django 5.2](https://img.shields.io/badge/Django-5.2-green.svg)](https://www.djangoproject.com/)
[![Python 3.11+](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://www.python.org/)
[![PostgreSQL 16+](https://img.shields.io/badge/PostgreSQL-16+-blue.svg)](https://www.postgresql.org/)
[![HTMX](https://img.shields.io/badge/HTMX-2.0-blue.svg)](https://htmx.org/)
[![Tailwind CSS](https://img.shields.io/badge/Tailwind_CSS-4.1-blue.svg)](https://tailwindcss.com/)
[![License: GPL v3+](https://img.shields.io/badge/License-GPLv3%2B-blue.svg)](LICENSE.md)

[![Platform CI](https://github.com/captainpragmatic/PRAHO/actions/workflows/platform.yml/badge.svg)](https://github.com/captainpragmatic/PRAHO/actions/workflows/platform.yml)
[![Portal CI](https://github.com/captainpragmatic/PRAHO/actions/workflows/portal.yml/badge.svg)](https://github.com/captainpragmatic/PRAHO/actions/workflows/portal.yml)
[![Integration Tests](https://github.com/captainpragmatic/PRAHO/actions/workflows/integration.yml/badge.svg)](https://github.com/captainpragmatic/PRAHO/actions/workflows/integration.yml)
![Tests](https://img.shields.io/badge/tests-5%2C000%2B-brightgreen.svg)

[![mypy: strict](https://img.shields.io/badge/mypy-strict_%E2%9C%93-brightgreen.svg)](https://mypy-lang.org/)
[![Ruff](https://img.shields.io/badge/Ruff-lint_%E2%9C%93-brightgreen.svg)](https://docs.astral.sh/ruff/)
[![pre-commit](https://img.shields.io/badge/pre--commit-enabled-brightgreen?logo=pre-commit)](https://pre-commit.com/)
[![i18n: RO+EN](https://img.shields.io/badge/i18n-RO%20%2B%20EN%20100%25-brightgreen.svg)](services/platform/locale/)
![GDPR](https://img.shields.io/badge/GDPR-compliant-brightgreen.svg)

## Overview

**PRAHO** is a hosting provider management platform built for **Romanian business compliance**. It handles customer management, VAT-compliant invoicing, e-Factura integration, service provisioning, support tickets, and GDPR compliance - all in a single Django-based system.

### Key Features

- **Customer Management** - Multi-user accounts with role-based access and soft deletes
- **EU VAT Billing** - All 27 EU country rates, Romanian 21% (Aug 2025), reverse charge for EU B2B, e-Factura XML
- **Service Provisioning** - Virtualmin integration with two-phase provisioning and rollback
- **Support System** - SLA-based ticket management with time tracking
- **Domain Management** - Multi-registrar support (.ro via ROTLD, international)
- **Security** - 2FA (TOTP), encrypted credentials, HMAC inter-service auth
- **Compliance** - GDPR with data export/erasure, immutable audit trails

## Architecture

PRAHO uses a **two-service architecture** for security isolation:

```
services/
├── platform/   # Staff/admin service (:8700) - full database access
│   ├── apps/   # 17 Django apps with models, services, views
│   ├── config/ # Django settings (base, dev, prod, staging, test)
│   └── tests/  # Mirrors apps/ structure
│
└── portal/     # Customer-facing service (:8701) - SQLite sessions only
    ├── apps/   # 9 Django apps (API proxies, no business models)
    └── tests/  # Enforces no business DB access
```

- **Platform** owns all data (PostgreSQL) and business logic
- **Portal** uses SQLite for session storage only - NO business data access
- **Portal** is stateless - communicates with Platform via HMAC-signed requests
- **No Redis required** - uses Django's database cache

> **Architecture Diagrams**: See [`docs/architecture/`](docs/architecture/) for Mermaid diagrams showing system overview, data flow, and deployment topology.

## Quick Start

### Prerequisites

- **Python 3.11+**
- **[uv](https://docs.astral.sh/uv/)** - Python package manager (used for workspace management)
- **PostgreSQL 16+** (production) or SQLite (development)
- **Git**

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/captainpragmatic/PRAHO.git
cd PRAHO

# 2. Install dependencies (installs uv workspace for both services)
make install

# 3. Configure environment
cp .env.example .env
# Edit .env with your settings (database, encryption keys, etc.)

# 4. Set up database and load sample data
make migrate
make fixtures        # Full sample data (or: make fixtures-light for minimal)

# 5. Start development servers
make dev             # Both services: platform (:8700) + portal (:8701)
```

Visit:
- **Platform**: http://localhost:8700 (staff interface)
- **Portal**: http://localhost:8701 (customer API)

**Test credentials**: `admin@example.com` / `admin123`

## Development Commands

All commands run from project root via Makefile:

```bash
# Development servers
make dev               # Start both services
make dev-platform      # Platform only (:8700)
make dev-portal        # Portal only (:8701)

# Testing
make test              # Run ALL tests (platform + portal + integration)
make test-platform     # Platform tests (Django test runner)
make test-portal       # Portal tests (no DB access enforced)
make test-integration  # Cross-service integration tests
make test-e2e          # Playwright E2E tests
make test-security     # Service isolation validation

# Code quality
make lint              # Ruff linting (all services)
make type-check        # MyPy type checking
make pre-commit        # Run all pre-commit hooks

# Database
make migrate           # Run platform migrations
make fixtures          # Load sample data

# Docker deployment
make docker-build      # Build service images
make docker-dev        # Start dev environment
make docker-prod       # Start production services
```

## Configuration

### Settings Structure

Each service has its own Django settings under `config/settings/`:

```
services/{platform,portal}/config/settings/
├── base.py       # Shared Django settings
├── dev.py        # Development (DEBUG=True, SQLite OK)
├── prod.py       # Production (security hardening, PostgreSQL)
├── staging.py    # Staging environment
└── test.py       # Test configuration
```

### Environment Variables

Copy `.env.example` to `.env` and configure. Key variables:

```bash
# Core
DJANGO_SETTINGS_MODULE=config.settings.dev
SECRET_KEY=your-secret-key
DEBUG=True

# Database (PostgreSQL for production, SQLite for dev)
DATABASE_URL=postgresql://user:pass@localhost:5432/praho

# Security (required for 2FA and credential vault)
DJANGO_ENCRYPTION_KEY=your-fernet-key
CREDENTIAL_VAULT_MASTER_KEY=your-vault-key

# Romanian compliance
EFACTURA_API_URL=https://api.anaf.ro/prod/FCTEL/rest
EFACTURA_API_KEY=your-key
COMPANY_CUI=RO12345678

# Payments
STRIPE_SECRET_KEY=sk_test_...
STRIPE_WEBHOOK_SECRET=whsec_...
```

See `.env.example` for the complete list with documentation.

## Tech Stack

- **Backend**: Django 5.2, Python 3.11+
- **Database**: PostgreSQL 16+ (production), SQLite (development)
- **Frontend**: Tailwind CSS + HTMX + Alpine.js (zero-runtime JavaScript)
- **Package Management**: [uv](https://docs.astral.sh/uv/) (workspace)
- **Code Quality**: Ruff (linting/formatting), MyPy (type checking)
- **Testing**: Django test runner + pytest, Playwright (E2E)
- **Deployment**: Docker, Ansible, Terraform (in `deploy/` and `services/platform/infrastructure/`)

## VAT & Romanian Compliance

PRAHO is built for Romanian hosting providers with **full EU VAT support**:

- **All 27 EU VAT rates** - Centralized `TaxService` with temporal validity (rate changes tracked by date)
- **EU B2B reverse charge** - 0% VAT for intra-EU business transactions with valid VAT number
- **EU B2C destination rate** - Automatic country-specific rate for consumer sales (e.g., DE 19%, HU 27%)
- **Non-EU export** - 0% VAT for customers outside the EU
- **Romanian 21% VAT** - Updated for Emergency Ordinance 156/2024 (Aug 2025), reduced rate consolidated to 11%
- **e-Factura** - Electronic invoicing via ANAF (Romanian tax authority)
- **CUI/VAT validation** - Romanian company identifier validation
- **Sequential invoice numbering** - Required by Romanian tax law
- **GDPR compliance** - Romanian Law 190/2018, data export/erasure, consent tracking
- **Full i18n coverage** - 100% Romanian + English translations across Platform (4,470 entries) and Portal (1,285 entries), with automated translation tooling (`make translate-*`), i18n linter, and YAML review workflow

## Security

- **Email-based auth** (no usernames), Argon2 hashing
- **Two-factor authentication** (TOTP with encrypted secrets)
- **Credential vault** with Fernet encryption and rotation
- **HMAC inter-service auth** (SHA-256 signed requests)
- **CSRF/XSS/CSP protection**, rate limiting, audit logging
- **Portal isolation** - customer-facing service has zero database access

## Documentation

- **[Architecture Guide](docs/ARCHITECTURE.md)** - System design and patterns
- **[Architecture Diagrams](docs/architecture/)** - Mermaid diagrams (system, data flow, deployment)
- **[Deployment Guide](docs/DEPLOYMENT.md)** - Production deployment scenarios
- **[Linting Guide](docs/LINTING_GUIDE.md)** - Code quality framework
- **[Changelog](CHANGELOG.md)** - Version history (SemVer)
- **[ADRs](docs/ADRs/)** - Architecture decision records

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

- **License**: GPL-3.0-or-later (inbound = outbound)
- **DCO required**: Sign off commits with `git commit -s`
- **Quality gates**: Pre-commit hooks enforce linting, type checking, and template validation

## Versioning

This project follows [Semantic Versioning](https://semver.org/). Current version: **v0.20.0** (alpha).

- Pre-1.0: API and features may change between minor versions
- Each minor bump (0.Y.0) represents a new feature milestone
- See `git tag -l 'v*' --sort=version:refname` for all release tags
- Version tracked in `pyproject.toml` and annotated git tags

## License

This project is licensed under the **GNU General Public License v3.0 or later** (GPL-3.0-or-later). See [LICENSE.md](LICENSE.md).

---

**Built for Romanian hosting providers** | *PRAHO - Automation that really works*
