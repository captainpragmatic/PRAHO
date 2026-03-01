# ADR-0007: Function-Level Cross-App Imports for Circular Import Prevention

**Date**: 2025-08-26
**Status**: Accepted
**Context**: PRAHO Platform Django app architecture and import management

## Context and Problem Statement

The PRAHO Platform uses a modular monolith architecture with multiple Django apps (`users`, `customers`, `billing`, `tickets`, `audit`, etc.) that need to reference models and services from each other. This creates a significant circular import challenge that affects code organization, type safety, and linting compliance.

**Key challenges:**
- PLC0415 (import-outside-top-level): 144 instances of function-level imports flagged by linting
- Cross-app model imports create circular dependency risks if placed at module top-level
- Django's app interdependency patterns conflict with Python import best practices
- Type safety requirements vs. runtime import safety
- Maintainable architecture that supports future microservices extraction

## Decision Drivers

- **Circular Import Prevention**: Avoid Django app startup failures due to circular dependencies
- **Type Safety**: Maintain proper type hints and IDE support for cross-app references
- **Django Best Practices**: Follow established Django community patterns for app interdependency
- **Future-Proof Architecture**: Support potential microservices extraction using strategic seams
- **Code Quality**: Clean linting that identifies real issues vs. architectural necessities

## Considered Options

### Option 1: Top-level imports with careful ordering
```python
# At top of file
from apps.tickets.models import Ticket
from apps.customers.models import Customer

def export_user_data(user):
    tickets = Ticket.objects.filter(created_by=user)
```

**Pros**: Follows Python import conventions, clean linting
**Cons**: High risk of circular imports in Django apps, fragile import ordering, prevents modular architecture

### Option 2: String references only (Django lazy loading)
```python
# In models.py
customer = models.ForeignKey('customers.Customer', on_delete=models.RESTRICT)

# In services.py
from django.apps import apps
Ticket = apps.get_model('tickets', 'Ticket')
```

**Pros**: No circular imports, very safe
**Cons**: No type safety, no IDE support, runtime overhead, less readable

### Option 3: Function-level imports with TYPE_CHECKING pattern
```python
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from apps.tickets.models import Ticket

def export_user_data(user) -> dict:
    # Runtime import prevents circular dependency
    from apps.tickets.models import Ticket  # noqa: PLC0415
    tickets: list['Ticket'] = list(Ticket.objects.filter(created_by=user))
```

**Pros**: Type safety + runtime safety, follows Django patterns, supports strategic seams
**Cons**: Requires linting configuration, slightly more verbose

### Option 4: Hybrid approach with apps.get_model fallback
```python
def get_model_safe(app_label: str, model_name: str):
    try:
        from django.apps import apps
        return apps.get_model(app_label, model_name)
    except LookupError:
        return None
```

**Pros**: Very defensive, handles optional apps
**Cons**: Complex, runtime overhead, limited type safety

## Decision

**Chosen Option 3: Function-level imports with TYPE_CHECKING pattern**

This approach aligns with both Django community best practices and modern Python typing conventions, while supporting our modular monolith architecture.

### Implementation Pattern:

```python
# Standard pattern for cross-app imports
from typing import TYPE_CHECKING

# Type-only imports (no runtime cost)
if TYPE_CHECKING:
    from apps.tickets.models import Ticket
    from apps.customers.models import Customer

class DataExportService:
    def export_user_data(self, user, scope: dict) -> dict:
        """Export user data with proper typing support"""
        data = {'user_id': user.id}

        # Runtime import prevents circular dependency
        if scope.get('include_tickets', True):
            from apps.tickets.models import Ticket  # noqa: PLC0415
            tickets: list['Ticket'] = list(Ticket.objects.filter(created_by=user))

            data['tickets'] = [
                {'id': t.id, 'subject': t.subject, 'status': t.status}
                for t in tickets
            ]

        return data
```

### Linting Configuration:

**Strategic Per-Line Approach** for surgical precision and maximum code quality:

```python
# ✅ Strategic cross-app imports with explicit noqa comments
def export_user_data(user) -> dict:
    from apps.tickets.models import Ticket  # noqa: PLC0415 - Circular import prevention
    tickets: list['Ticket'] = list(Ticket.objects.filter(created_by=user))

# ✅ Safe imports moved to top-level (no longer flagged)
from django.db import transaction
from io import BytesIO
from django.contrib.auth import logout

def my_function():
    # Uses imports available at module level
```

**No per-file ignores** - each function-level import requires explicit justification.

## Rationale for Function-Level Imports

### Django-Specific Justification:

1. **Circular Import Prevention**: Django apps frequently have bidirectional relationships (User ↔ Customer, Billing ↔ Audit, etc.)

2. **App Independence**: Services layer should be able to reference other apps without creating tight coupling at module level

3. **Optional App Support**: Some apps (tickets, integrations) may be optional, requiring conditional imports

4. **Migration Compatibility**: Django migrations work better with lazy model loading

### Expert Community Consensus:

Based on research from Django Forum, Stack Overflow, and Django core developer recommendations:
- Function-level imports are **explicitly recommended** for cross-app model imports
- Django's own codebase uses this pattern extensively
- Preferred over `apps.get_model()` for performance and readability
- Standard pattern in Django REST Framework and other major Django projects

## Consequences

### Positive:
- **Surgical Precision**: Per-line noqa comments target only legitimate architectural needs
- **Maximum Code Quality**: Maintains ruff's ability to catch genuine import organization issues
- **Architectural Flexibility**: Supports modular monolith with strategic seams for future microservices
- **Type Safety**: Full IDE support and type checking for cross-app references
- **Circular Import Prevention**: Eliminates Django startup failures
- **Performance**: Safe imports moved to module-level for better performance
- **Self-Documenting**: Each noqa comment explains the architectural reason
- **Django Alignment**: Follows established Django community patterns
- **Explicit Intent**: Every function-level import requires conscious justification

### Negative:
- **Per-Line Maintenance**: Each cross-app import needs individual noqa comment
- **Training**: New team members need to understand this pattern
- **Comment Discipline**: Developers must provide meaningful noqa explanations
- **Import Duplication**: Same imports appear at top (TYPE_CHECKING) and in functions

## Per-Line Implementation Guidelines

### ✅ **When to use `# noqa: PLC0415`:**

**Cross-App Model Imports** (Circular dependency prevention):
```python
from apps.tickets.models import Ticket  # noqa: PLC0415 - Circular import prevention
from apps.customers.models import Customer  # noqa: PLC0415 - Cross-app relationship
```

**Optional App Dependencies** (Conditional functionality):
```python
try:
    from apps.tickets.models import Ticket  # noqa: PLC0415 - Optional app import
except ImportError:
    Ticket = None
```

**Audit Service Integrations** (Cross-app logging):
```python
from apps.audit.services import audit_service  # noqa: PLC0415 - Cross-app audit logging
```

### 🔧 **When to move to top-level:**

**Django Core** (No circular dependency risk):
```python
# Move to top of file - these are safe
from django.db import transaction
from django.contrib.auth import logout
from django.db.models import QuerySet, F
```

**Standard Library** (Always safe):
```python
# Move to top of file
from io import BytesIO
import logging
from datetime import timedelta
```

**Third-Party Libraries** (Performance optimization):
```python
# Move to top of file
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
```

## Compliance and Review

### Implementation Status:
- **Per-file ignores removed** from pyproject.toml for surgical precision
- **Strategic noqa comments added** for legitimate cross-app imports only
- **Safe imports optimized** by moving Django core/stdlib/third-party to module-level
- **Maximum code quality maintained** while respecting Django architectural patterns

### Review Process:
1. **New PLC0415 warnings** require explicit noqa comment with justification
2. **Cross-app imports** must explain circular dependency prevention in noqa comment
3. **Django core/stdlib imports** should be moved to top-level (no noqa needed)
4. **Each noqa comment** should specify the architectural reason (circular imports, optional apps, etc.)

### Quality Gates:
- ❌ **Function-level imports without noqa comments** fail CI
- ✅ **Strategic noqa comments with clear explanations** pass review
- 🔧 **Safe imports moved to module-level** improve performance

## Related Decisions

- **ADR-0002**: Strategic linting framework (establishes per-file ignore patterns)
- **ADR-0003**: Type safety implementation (TYPE_CHECKING pattern usage)
- **Future consideration**: Microservices extraction strategy (strategic seams architecture)

## Expert References

- Django Forum: "Best Practices for Avoiding Circular Imports" (2024)
- Stack Overflow: "Django inter-app imports accepted practices"
- Django Documentation: "Lazy relationship references" and `apps.get_model()`
- Python typing PEP 563: Forward references and TYPE_CHECKING

---

**Tags**: architecture, django, imports, type-safety, circular-dependencies
**Updated**: Initial version
