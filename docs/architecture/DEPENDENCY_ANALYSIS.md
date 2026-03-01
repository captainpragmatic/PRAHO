# PRAHO Platform - Dependency Analysis Report

**Generated:** March 1, 2026
**Version:** 0.20.0

---

## Executive Summary

Fresh analysis of inter-app dependencies across 17 platform apps (416 Python files). Compared to the v0.16.0 report (14 apps, 10 circular pairs), the codebase has grown by 3 apps (`api`, `infrastructure`, `promotions`) and circular dependencies have increased to 14 pairs.

| Category | Count | Severity |
|----------|-------|----------|
| Platform apps | 17 | - |
| Python files | 416 | - |
| Circular dependency pairs | 14 | Critical |
| Apps with fan-out >= 7 | 5 | High |
| `common` outbound domain imports | 7 apps | High |

---

## 1. App Inventory

| App | Files | Purpose |
|-----|-------|---------|
| `api` | 40 | Centralized REST API layer (DRF) |
| `audit` | 23 | Immutable audit trails, GDPR compliance |
| `billing` | 61 | Romanian VAT invoicing, payments, e-Factura, subscriptions |
| `common` | 49 | Shared utilities, validators, decorators, types |
| `customers` | 25 | Customer orgs, profiles (tax, billing, address) |
| `domains` | 16 | Multi-registrar domain management (.ro, international) |
| `infrastructure` | 25 | Server management, Ansible, Terraform, SSH keys |
| `integrations` | 16 | Webhook handling (Stripe, Virtualmin) |
| `notifications` | 18 | Bilingual email templates (RO/EN) |
| `orders` | 24 | Order lifecycle management |
| `products` | 10 | Product catalog, multi-currency pricing |
| `promotions` | 10 | Discount codes, promotional campaigns |
| `provisioning` | 45 | Virtualmin integration, hosting service lifecycle |
| `settings` | 20 | System configuration key-value store |
| `tickets` | 12 | Support tickets with SLA tracking |
| `ui` | 9 | Shared UI components, template tags |
| `users` | 13 | Email-based auth, 2FA (TOTP), staff roles |

---

## 2. Dependency Matrix

Each row shows what an app imports from (fan-out) and how many apps import it (fan-in).

| App | Fan-Out | Fan-In | Imports From |
|-----|---------|--------|-------------|
| `api` | 9 | 1 | audit, billing, common, customers, orders, products, provisioning, tickets, users |
| `audit` | 3 | 13 | common, tickets, users |
| `billing` | 7 | 7 | audit, common, customers, orders, tickets, ui, users |
| `common` | 7 | 15 | billing, customers, orders, products, provisioning, tickets, users |
| `customers` | 7 | 8 | audit, billing, common, provisioning, settings, tickets, users |
| `domains` | 7 | 0 | audit, billing, common, customers, orders, settings, users |
| `infrastructure` | 3 | 0 | audit, common, settings |
| `integrations` | 4 | 0 | audit, billing, common, customers |
| `notifications` | 2 | 0 | common, settings |
| `orders` | 8 | 4 | audit, billing, common, customers, products, provisioning, tickets, users |
| `products` | 3 | 3 | audit, billing, common |
| `promotions` | 2 | 0 | audit, settings |
| `provisioning` | 7 | 4 | api, audit, common, customers, settings, ui, users |
| `settings` | 2 | 8 | audit, common |
| `tickets` | 4 | 6 | audit, common, settings, users |
| `ui` | 1 | 2 | common |
| `users` | 4 | 9 | audit, common, customers, settings |

**Leaf apps** (fan-in = 0, safe to modify): `domains`, `infrastructure`, `integrations`, `notifications`, `promotions`.

**Hub apps** (fan-in >= 8): `common` (15), `audit` (13), `users` (9), `settings` (8), `customers` (8).

---

## 3. Circular Dependencies (14 Pairs)

### 3.1 `common` Cycles (6 pairs) -- Most Critical

The `common` module imports from 7 domain apps, creating cycles with all of them since nearly every app imports `common`.

| Cycle | Root Cause | Key Files |
|-------|-----------|-----------|
| `common` <-> `billing` | Dashboard + sample data generators import Invoice/Currency models | `common/views.py:14-15`, `common/management/commands/generate_sample_data.py` |
| `common` <-> `customers` | Validators import Customer/CustomerTaxProfile directly | `common/validators.py:33-34` |
| `common` <-> `users` | Decorators + validators import User model | `common/decorators.py:18`, `common/validators.py:35` |
| `common` <-> `orders` | Sample data generator imports Order models | `common/management/commands/generate_sample_data.py:21` |
| `common` <-> `products` | Sample data generator imports Product models | `common/management/commands/generate_sample_data.py:22` |
| `common` <-> `provisioning` | Dashboard + credential vault + sample data import Service/Server models | `common/views.py:17`, `common/management/commands/setup_credential_vault.py` |
| `common` <-> `tickets` | Dashboard imports Ticket model | `common/views.py:18` |

### 3.2 Domain-Level Cycles (8 pairs)

| Cycle | Direction A | Direction B |
|-------|-----------|-----------|
| `billing` <-> `customers` | billing imports customer models for invoicing | customers imports billing models for balance calculation (`profile_models.py:136`) |
| `billing` <-> `orders` | billing imports order data for invoice generation | orders imports billing for Currency model |
| `customers` <-> `users` | customers imports User model across 8+ files | users imports Customer model for memberships |
| `customers` <-> `provisioning` | customers views/signals import Service model | provisioning views import Customer model |
| `audit` <-> `users` | audit needs user context for log entries | users imports audit for security logging |
| `audit` <-> `tickets` | audit references ticket models | tickets imports audit for change tracking |
| `api` <-> `provisioning` | api imports provisioning for API endpoints | provisioning imports api (unexpected reverse dep) |

---

## 4. Tight Coupling Analysis

### 4.1 `common` -- God Module Problem

`common` (49 files) violates the utility module contract by importing from 7 domain apps. The primary offenders:

| File | Imports From | Why It's Wrong |
|------|-------------|---------------|
| `common/views.py` | billing, customers, provisioning, tickets | Dashboard aggregation queries belong in a dashboard app or service |
| `common/validators.py` | customers, users | Domain-specific validation belongs in the domain app |
| `common/decorators.py` | users | Auth decorators should use `get_user_model()` or live in `users` |
| `common/management/commands/generate_sample_data.py` | 7 apps | Data seeding command imports every domain model |
| `common/management/commands/setup_scheduled_tasks.py` | orders, provisioning, users | Task setup imports from domain apps |

### 4.2 Files With Most Cross-App Imports

| File | Cross-App Imports | Concern |
|------|------------------|---------|
| `billing/views.py` | 11 | View layer directly queries multiple domain models |
| `users/services.py` | 10 | User service has tendrils into many domains |
| `orders/views.py` | 10 | Order views import from many apps |
| `generate_sample_data.py` | 9 | Management command; acceptable for data seeding |
| `infrastructure/deployment_service.py` | 8 | Orchestration service; inherently cross-cutting |
| `customers/customer_views.py` | 8 | Views pull from billing, provisioning, tickets, users |

### 4.3 Cross-Boundary Model Imports

60+ direct model imports cross app boundaries. The worst patterns:

- **`customers/`** imports models from `billing`, `orders`, `provisioning`, `tickets`, `users` (in views, services, signals)
- **`billing/views.py`** imports from `customers`, `orders`, `products`, `users`
- **`common/views.py`** imports 5 domain models for dashboard stats

These should go through service-layer calls or repository interfaces, not direct model access.

---

## 5. Dependency Graph

```
                          ┌────────────┐
                          │   common   │◄─────── 15 apps depend on this
                          │ (49 files) │
                          └─────┬──────┘
       ┌──────────────────┬─────┴─────┬──────────────────┐
       │                  │           │                  │
       ▼                  ▼           ▼                  ▼
 ┌──────────┐      ┌──────────┐ ┌─────────┐      ┌──────────┐
 │  audit   │◄─────│  users   │◄┤customers│◄────►│ billing  │
 │(13 fan-in│      │(9 fan-in)│ │(8 fan-in│      │(7 fan-in)│
 └────┬─────┘      └──────────┘ └────┬────┘      └────┬─────┘
      │                              │                 │
      │                              ▼                 ▼
      │                        ┌──────────┐      ┌──────────┐
      │                        │provisioning│     │  orders  │
      │                        │ (45 files)│     │ (24 files)│
      │                        └──────────┘      └──────────┘
      │
      ▼
 ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐
 │ settings │  │ tickets  │  │    ui    │  │ products │
 │(8 fan-in)│  │(6 fan-in)│  │(2 fan-in)│  │(3 fan-in)│
 └──────────┘  └──────────┘  └──────────┘  └──────────┘

 Leaf apps (no dependents):
 ┌──────────┐ ┌──────────────┐ ┌──────────────┐ ┌───────────────┐ ┌────────────┐
 │ domains  │ │infrastructure│ │ integrations │ │ notifications │ │ promotions │
 └──────────┘ └──────────────┘ └──────────────┘ └───────────────┘ └────────────┘

 ◄───► = circular dependency (14 pairs total)
```

---

## 6. Change Since v0.16.0

| Metric | v0.16.0 | v0.20.0 | Delta |
|--------|---------|---------|-------|
| Apps | 14 | 17 | +3 (`api`, `infrastructure`, `promotions`) |
| Circular pairs | 10 | 14 | +4 |
| `common` fan-in | 13 | 15 | +2 |
| `common` outbound deps | 6 | 7 | +1 (`products`) |
| Largest app (files) | provisioning (36) | billing (61) | billing grew significantly |
| Leaf apps | 3 | 5 | +2 (infrastructure, promotions) |

New circular pairs: `api <-> provisioning`, `common <-> products`, `billing <-> customers`, `customers <-> provisioning`.

---

## 7. Refactoring Recommendations

### Priority 1: Clean Up `common` (Break 6+ Cycles)

| Action | Impact | Effort |
|--------|--------|--------|
| Move `common/views.py` dashboard logic to a dedicated `dashboard` app or into each domain's service | Breaks 4 cycles | 1-2 days |
| Move `common/validators.py` customer/user validation into `customers/validators.py` | Breaks 2 cycles | 1 day |
| Change `common/decorators.py` to use `get_user_model()` instead of direct User import | Breaks 1 cycle | 0.5 day |
| Move `generate_sample_data` command to a `dev_tools` app or use lazy imports | Breaks 5 cycles (mgmt commands) | 1 day |

### Priority 2: Break Domain Cycles

| Action | Impact | Effort |
|--------|--------|--------|
| `customers/profile_models.py:136` -- Replace direct Invoice import with a service call for balance calculation | Breaks `billing <-> customers` | 0.5 day |
| Replace direct Currency model import in `orders/` with a billing service method | Breaks `billing <-> orders` | 0.5 day |
| Use `TYPE_CHECKING` + string annotations for FK references between `users` and `customers` | Breaks `customers <-> users` at model level | 1 day |
| Investigate `provisioning -> api` import (unexpected direction) | Breaks `api <-> provisioning` | 0.5 day |

### Priority 3: Reduce View-Layer Coupling

High-import view files (`billing/views.py`: 11, `orders/views.py`: 10) should delegate to service methods that return DTOs/dicts instead of importing models from 5+ apps. This also makes future Portal API proxying cleaner.

### Priority 4: Interface Extraction (Medium-Term)

Services that are imported across 3+ app boundaries should expose abstract interfaces:

| Service | Imported By | Recommended Interface |
|---------|-----------|----------------------|
| `AuditService` | 13 apps | `IAuditLogger` in `common/interfaces.py` |
| `User` model queries | 9 apps | `IUserRepository` |
| `Customer` model queries | 8 apps | `ICustomerRepository` |
| `VirtualminGateway` | provisioning internal | `IHostingGateway` (for panel abstraction) |

---

## 8. Success Metrics

| Metric | Current (v0.20.0) | Target |
|--------|-------------------|--------|
| Circular dependency pairs | 14 | 0 |
| `common` outbound domain imports | 7 apps | 0 apps |
| Files with 8+ cross-app imports | 6 | 0 |
| Services with DI / interfaces | 0% | Core services (billing, provisioning, audit) |
| View files importing 5+ app models | 4 | 0 (use service layer) |

---

*Generated from static import analysis of `services/platform/apps/`. Does not account for runtime dynamic imports or test-only dependencies.*
