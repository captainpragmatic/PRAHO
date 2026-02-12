# PRAHO Platform - Dependency Analysis Report

**Generated:** December 27, 2025
**Version:** 0.14.0

---

## Executive Summary

This document provides a comprehensive analysis of the PRAHO Platform's dependency structure, identifying circular dependencies, tight coupling violations, and opportunities for architectural improvements through dependency inversion and interface extraction.

### Key Findings

| Category | Count | Severity |
|----------|-------|----------|
| Circular Dependencies | 10 pairs | 🔴 Critical |
| Tight Coupling Violations | 6 modules | 🟠 High |
| Classes Needing Interfaces | 12 classes | 🟡 Medium |
| Dependency Injection Opportunities | 8 services | 🟡 Medium |

---

## 1. Codebase Structure Overview

### Platform Architecture

```
services/platform/
├── config/                   # Django project configuration
│   └── settings/             # Environment-specific settings
└── apps/                     # Django applications (14 total)
    ├── audit/                # Audit logging, GDPR compliance
    ├── billing/              # Invoicing, payments, refunds, VAT
    ├── common/               # Shared utilities (OVER-COUPLED)
    ├── customers/            # Customer management, profiles
    ├── domains/              # Domain registration
    ├── integrations/         # Webhook handling, Stripe
    ├── notifications/        # Email templates, logging
    ├── orders/               # Order management
    ├── products/             # Product catalog
    ├── provisioning/         # Virtualmin, server management
    ├── settings/             # System configuration
    ├── tickets/              # Support tickets
    ├── ui/                   # UI components, widgets
    └── users/                # Authentication, MFA
```

---

## 2. Circular Dependencies (10 Pairs)

### 🔴 Critical Circular Dependencies

#### 2.1 `common` ↔ Multiple Apps (6 Cycles)

**Root Cause:** The `common` module was designed as a utility library but has accumulated business logic that imports from domain modules.

| Cycle | Files Involved | Root Cause |
|-------|---------------|------------|
| `common` ↔ `billing` | `common/utils.py:184` imports `Invoice` model | Business logic (invoice numbering) in utility module |
| `common` ↔ `customers` | `common/validators.py:33-35` imports Customer models | Validation logic coupled to domain models |
| `common` ↔ `users` | `common/decorators.py:19` imports `User` model | Security decorators need user model |
| `common` ↔ `orders` | `common/utils.py` imports order tasks | Task scheduling in utility module |
| `common` ↔ `provisioning` | `common/utils.py` imports virtualmin models | Cross-domain business logic |
| `common` ↔ `tickets` | `common/utils.py` imports ticket models | Cross-domain business logic |

**Current State (`common/utils.py:184`):**
```python
def generate_invoice_number(year: int | None = None) -> str:
    from apps.billing.models import Invoice  # CIRCULAR IMPORT
    # ... business logic
```

**Current State (`common/validators.py:33-35`):**
```python
from apps.customers.customer_models import Customer
from apps.customers.profile_models import CustomerTaxProfile
from apps.users.models import CustomerMembership, User  # CIRCULAR IMPORTS
```

#### 2.2 `billing` ↔ `orders`

**Root Cause:** Bidirectional dependency between billing and order management.

| Direction | Import Location | Purpose |
|-----------|----------------|---------|
| `orders` → `billing` | `orders/services.py:13` | Uses `Currency` model for order creation |
| `billing` → `orders` | `billing/invoice_service.py` | Creates invoices from orders |

#### 2.3 `users` ↔ `customers`

**Root Cause:** User model directly imports Customer for relationship, and Customer references User.

| Direction | Import Location | Purpose |
|-----------|----------------|---------|
| `users` → `customers` | `users/models.py:29` | User has `customers` M2M field |
| `customers` → `users` | `customer_models.py:19` | TYPE_CHECKING import, FK references |

**Current State (`users/models.py:29`):**
```python
from apps.customers.models import Customer  # Direct import for M2M relationship
```

#### 2.4 `audit` ↔ `users`

**Root Cause:** Audit service logs user actions, users module logs to audit.

#### 2.5 `audit` ↔ `tickets`

**Root Cause:** Ticket changes create audit entries, audit references ticket models.

---

## 3. Dependency Injection Opportunities

### 3.1 Services That Should Use Dependency Injection

| Service | Current Implementation | Recommended Pattern |
|---------|----------------------|---------------------|
| `VirtualminProvisioningService` | Creates `VirtualminGateway` internally | Inject `IGateway` interface |
| `InvoiceService` | Directly queries `Currency`, `InvoiceSequence` | Inject repository interfaces |
| `OrderService` | Creates models directly | Inject `IOrderRepository` |
| `RefundService` | Direct model access | Inject `IRefundRepository` |
| `CustomerService` | Direct model queries | Inject `ICustomerRepository` |
| `AuditService` | Static logging function | Inject `IAuditLogger` interface |
| `VirtualminBackupService` | Creates gateway internally | Inject `IBackupGateway` |
| `EmailService` | Direct SMTP/template access | Inject `IEmailSender` |

### 3.2 Recommended DI Pattern

**Before (`provisioning/virtualmin_service.py:61-86`):**
```python
class VirtualminProvisioningService:
    def __init__(self, server: VirtualminServer | None = None):
        self.server = server
        self._gateway: VirtualminGateway | None = None  # Created internally

    def _get_gateway(self, server: VirtualminServer | None = None) -> VirtualminGateway:
        # Gateway created on demand - tight coupling
        config = VirtualminConfig(server=target_server, ...)
        self._gateway = VirtualminGateway(config)  # Concrete dependency
        return self._gateway
```

**After (with DI):**
```python
from abc import ABC, abstractmethod

class IVirtualminGateway(ABC):
    @abstractmethod
    def call(self, command: str, params: dict) -> Result[VirtualminResponse, str]: ...

    @abstractmethod
    def test_connection(self) -> Result[dict[str, Any], str]: ...

class VirtualminProvisioningService:
    def __init__(
        self,
        gateway_factory: Callable[[VirtualminServer], IVirtualminGateway],
        server: VirtualminServer | None = None
    ):
        self.server = server
        self._gateway_factory = gateway_factory  # Injected factory
        self._gateway: IVirtualminGateway | None = None
```

---

## 4. Classes Needing Interfaces/Abstractions

### 4.1 Concrete Classes That Should Be Abstracted

| Current Class | Proposed Interface | Location | Reason |
|--------------|-------------------|----------|--------|
| `VirtualminGateway` | `IHostingGateway` | `provisioning/virtualmin_gateway.py` | Allow mock testing, support other panels |
| `VirtualminBackupService` | `IBackupService` | `provisioning/virtualmin_backup_service.py` | Abstract backup operations |
| `InvoiceService` | `IInvoiceService` | `billing/services.py` | Enable invoice generation mocking |
| `RefundService` | `IRefundService` | `billing/refund_service.py` | Decouple refund logic |
| `CustomerService` | `ICustomerRepository` | `customers/customer_service.py` | Repository pattern |
| `OrderService` | `IOrderService` | `orders/services.py` | Decouple order creation |
| `AuditService` | `IAuditLogger` | `audit/services.py` | Cross-cutting concern |
| `SecureInputValidator` | `IInputValidator` | `common/validators.py` | Allow validation customization |
| `EmailService` | `IEmailSender` | `notifications/services.py` | Mock email in tests |
| `StripeWebhookHandler` | `IPaymentWebhookHandler` | `integrations/webhooks/stripe.py` | Support multiple payment providers |
| `Currency` (queries) | `ICurrencyRepository` | `billing/models.py` | Abstract data access |
| `User` (queries) | `IUserRepository` | `users/models.py` | Abstract user operations |

### 4.2 Recommended Interface Definitions

**Location: `apps/common/interfaces.py` (NEW FILE)**

```python
from abc import ABC, abstractmethod
from typing import Any, Generic, TypeVar
from apps.common.types import Result

T = TypeVar('T')
E = TypeVar('E')

class IRepository(ABC, Generic[T]):
    """Base repository interface"""

    @abstractmethod
    def get_by_id(self, id: Any) -> Result[T | None, str]: ...

    @abstractmethod
    def save(self, entity: T) -> Result[T, str]: ...

    @abstractmethod
    def delete(self, entity: T) -> Result[bool, str]: ...

class IAuditLogger(ABC):
    """Audit logging interface"""

    @abstractmethod
    def log_security_event(
        self,
        event_type: str,
        details: dict[str, Any],
        request_ip: str | None = None
    ) -> None: ...

class IHostingGateway(ABC):
    """Hosting panel gateway interface"""

    @abstractmethod
    def create_domain(self, domain: str, username: str, password: str) -> Result[dict, str]: ...

    @abstractmethod
    def delete_domain(self, domain: str) -> Result[bool, str]: ...

    @abstractmethod
    def suspend_domain(self, domain: str, reason: str) -> Result[bool, str]: ...

    @abstractmethod
    def get_domain_info(self, domain: str) -> Result[dict, str]: ...
```

---

## 5. Tight Coupling Violations

### 5.1 Separation of Concerns Violations

#### 5.1.1 `common` Module - Most Severe

**Problem:** The `common` module violates the Single Responsibility Principle and has become a "god module" that knows about all other modules.

| File | Violation | Imported From |
|------|-----------|---------------|
| `common/utils.py` | Invoice number generation | `billing.models` |
| `common/validators.py` | Customer validation | `customers.models`, `users.models` |
| `common/decorators.py` | Role-based security | `users.models` |
| `common/views.py` | Dashboard data | Multiple modules |

**Impact:**
- 13 out of 14 apps depend on `common`
- 6 circular dependencies originate from `common`
- Cannot modify `common` without potentially breaking all apps

#### 5.1.2 `billing` ↔ `orders` Cross-Dependency

**Problem:** Billing and orders are tightly coupled through direct imports.

```
orders/services.py:13  →  from apps.billing.models import Currency
billing/services.py    →  Imports order data for invoice creation
```

**Violation:** Order management should not depend on billing implementation details.

#### 5.1.3 `provisioning` Module Size

**Problem:** The `provisioning` module has 36 files - too large for a single module.

**Suggested Split:**
```
provisioning/           # Current (36 files)
├── core/               # Base models, services
├── virtualmin/         # Virtualmin-specific
├── backups/            # Backup management
└── disaster_recovery/  # DR operations
```

### 5.2 Layer Violations

```
┌─────────────────────────────────────────────────────────────┐
│                    PRESENTATION LAYER                        │
│  views.py files, forms.py, template tags                     │
└───────────────────────────┬─────────────────────────────────┘
                            │ ✅ OK
┌───────────────────────────▼─────────────────────────────────┐
│                    APPLICATION LAYER                         │
│  services.py files, tasks.py                                 │
└───────────────────────────┬─────────────────────────────────┘
                            │ ❌ VIOLATION: services directly
                            │    import from other services
┌───────────────────────────▼─────────────────────────────────┐
│                      DOMAIN LAYER                            │
│  models.py files, business logic                             │
└───────────────────────────┬─────────────────────────────────┘
                            │ ❌ VIOLATION: models import
                            │    from other domain models
┌───────────────────────────▼─────────────────────────────────┐
│                   INFRASTRUCTURE LAYER                       │
│  gateways, external APIs, database                           │
└─────────────────────────────────────────────────────────────┘
```

---

## 6. Dependency Graphs

### 6.1 Current State (Problematic)

```
                           ┌─────────────┐
                           │   common    │◄──────────────────┐
                           │  (25 files) │                   │
                           └──────┬──────┘                   │
          ┌────────────────────┬──┴──┬────────────────────┐  │
          │                    │     │                    │  │
          ▼                    ▼     ▼                    ▼  │
    ┌──────────┐         ┌─────────┐ ┌──────────┐   ┌───────┐│
    │  users   │◄───────►│customers│ │  billing │◄──┤ audit ││
    │(11 files)│         │(19files)│ │(22 files)│   │(10 f.)││
    └────┬─────┘         └────┬────┘ └────┬─────┘   └───┬───┘│
         │                    │           │             │    │
         │                    │           ▼             │    │
         │                    │     ┌──────────┐        │    │
         │                    │     │  orders  │◄───────┤    │
         │                    │     │(13 files)│        │    │
         │                    │     └────┬─────┘        │    │
         │                    │          │              │    │
         │         ┌──────────┴──────────┴──────────────┘    │
         │         │                                          │
         ▼         ▼                                          │
    ┌──────────────────┐      ┌─────────────┐                │
    │   provisioning   │◄────►│   tickets   │────────────────┘
    │   (36 files)     │      │  (9 files)  │
    └──────────────────┘      └─────────────┘
         │
         ▼
    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
    │  products   │    │   domains   │    │integrations │
    │  (7 files)  │    │ (13 files)  │    │ (13 files)  │
    └─────────────┘    └─────────────┘    └─────────────┘

Legend:
  ─────► One-way dependency
  ◄────► Circular dependency (PROBLEM)
```

### 6.2 Ideal State (Proposed)

```
                    ┌─────────────────────────────────────┐
                    │           INTERFACE LAYER            │
                    │  IRepository, IAuditLogger, etc.     │
                    └─────────────────┬───────────────────┘
                                      │
        ┌─────────────────────────────┼─────────────────────────────┐
        │                             │                             │
        ▼                             ▼                             ▼
┌───────────────┐            ┌───────────────┐            ┌───────────────┐
│    DOMAIN     │            │    DOMAIN     │            │    DOMAIN     │
│   customers   │            │    billing    │            │    orders     │
│   (models)    │            │   (models)    │            │   (models)    │
└───────┬───────┘            └───────┬───────┘            └───────┬───────┘
        │                             │                             │
        ▼                             ▼                             ▼
┌───────────────┐            ┌───────────────┐            ┌───────────────┐
│  APPLICATION  │            │  APPLICATION  │            │  APPLICATION  │
│CustomerService│───────────►│InvoiceService │◄───────────│ OrderService  │
│ (interfaces)  │            │ (interfaces)  │            │ (interfaces)  │
└───────────────┘            └───────────────┘            └───────────────┘
        │                             │                             │
        └─────────────────────────────┼─────────────────────────────┘
                                      │
                                      ▼
                    ┌─────────────────────────────────────┐
                    │        INFRASTRUCTURE LAYER          │
                    │  Repositories, Gateways, External    │
                    └─────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│                         SHARED KERNEL (New common)                       │
│  - Pure utilities (no domain imports)                                    │
│  - Type definitions (Result, Ok, Err)                                    │
│  - Constants                                                             │
│  - Abstract interfaces                                                   │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 7. Recommended Refactoring Roadmap

### Phase 1: Break `common` Circular Dependencies (Priority: Critical)

| Task | Effort | Impact |
|------|--------|--------|
| Move `generate_invoice_number()` to `billing/utils.py` | 1 day | Breaks 1 cycle |
| Move customer validation to `customers/validators.py` | 1 day | Breaks 1 cycle |
| Create `common/interfaces.py` for abstract types | 2 days | Foundation |
| Move security decorators to use TYPE_CHECKING | 1 day | Breaks 1 cycle |

### Phase 2: Introduce Interface Layer (Priority: High)

| Task | Effort | Impact |
|------|--------|--------|
| Define `IRepository` base interface | 1 day | Pattern foundation |
| Create `IAuditLogger` interface | 1 day | Decouples audit |
| Create `IHostingGateway` interface | 2 days | Decouples provisioning |
| Update services to accept interfaces | 3 days | Enables DI |

### Phase 3: Implement Dependency Injection (Priority: Medium)

| Task | Effort | Impact |
|------|--------|--------|
| Create DI container/factory module | 2 days | Central composition |
| Refactor `VirtualminProvisioningService` | 2 days | Testability |
| Refactor `InvoiceService` | 1 day | Testability |
| Refactor `OrderService` | 1 day | Testability |

### Phase 4: Split Large Modules (Priority: Medium)

| Task | Effort | Impact |
|------|--------|--------|
| Split `provisioning` into sub-packages | 3 days | Maintainability |
| Extract `common` pure utilities | 2 days | Clean architecture |

---

## 8. Immediate Actions Checklist

### Quick Wins (< 1 day each)

- [ ] Use `TYPE_CHECKING` for User import in `common/decorators.py`
- [ ] Move `generate_invoice_number()` from `common/utils.py` to `billing/`
- [ ] Use string references in ForeignKey definitions where possible
- [ ] Document import conventions in CONTRIBUTING.md

### Short-term (1-2 weeks)

- [ ] Create `common/interfaces.py` with abstract base classes
- [ ] Refactor `common/validators.py` to use interface-based validation
- [ ] Implement `IRepository` pattern for `Customer`, `Order`, `Invoice`

### Medium-term (1-2 months)

- [ ] Full DI implementation for all services
- [ ] Split `provisioning` module into sub-packages
- [ ] Achieve zero circular dependencies

---

## 9. Metrics for Success

| Metric | Current | Target |
|--------|---------|--------|
| Circular Dependencies | 10 | 0 |
| `common` module imports | 6 domain modules | 0 domain modules |
| Services with DI | 0% | 100% |
| Test coverage with mocks | Limited | Full isolation |
| Modules > 20 files | 2 (common, provisioning) | 0 |

---

## Appendix A: Full Dependency Matrix

| Module | Depends On | Depended By | Circular With |
|--------|-----------|-------------|---------------|
| `audit` | common, tickets, users | 10 apps | users, tickets |
| `billing` | audit, common, customers, orders, tickets, ui, users | 5 apps | orders, common |
| `common` | billing, customers, orders, provisioning, tickets, users | 13 apps | 6 modules |
| `customers` | audit, common, users | 7 apps | common, users |
| `domains` | audit, billing, common, customers, orders, settings, users | 0 (leaf) | - |
| `integrations` | audit, billing, common, customers | 0 (leaf) | - |
| `notifications` | common, settings | 0 (leaf) | - |
| `orders` | audit, billing, common, customers, products, tickets, users | 3 apps | billing, common |
| `products` | audit, billing, common | 1 (orders) | - |
| `provisioning` | audit, common, customers, settings, ui, users | 1 (common) | common |
| `settings` | audit, common | 3 apps | - |
| `tickets` | audit, common, users | 4 apps | audit, common |
| `ui` | common | 2 apps | - |
| `users` | audit, common, customers | 8 apps | audit, common, customers |

---

## Appendix B: Files with Most Cross-Module Imports

| File | Module Imports | Recommendation |
|------|----------------|----------------|
| `common/validators.py` | 5 modules | Extract to domain-specific validators |
| `billing/views.py` | 6 modules | Use service layer, not direct models |
| `orders/views.py` | 6 modules | Use service layer, not direct models |
| `common/utils.py` | 4 modules | Split into pure utils + domain helpers |
| `provisioning/virtualmin_service.py` | 4 modules | Use dependency injection |

---

*This analysis was generated to guide architectural improvements for the PRAHO Platform. Implementation should be prioritized based on business needs and development capacity.*
