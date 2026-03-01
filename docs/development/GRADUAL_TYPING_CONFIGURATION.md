# PRAHO Platform - Gradual Typing Configuration Guide

This document outlines the gradual typing strategy implemented for the PRAHO Platform, enabling progressive type adoption while maintaining development velocity.

## Overview

Our gradual typing configuration is designed to:
- **Enable type adoption without blocking development** - Relaxed global settings
- **Prevent type debt accumulation** - Progressive strictness per app/module
- **Support Django patterns** - Proper django-stubs integration
- **Provide clear adoption roadmap** - Week-by-week rollout plan

## Configuration Architecture

### Global Strategy: Permissive by Default

```toml
# pyproject.toml - Global settings
[tool.mypy]
strict = false  # ✅ Relaxed globally
disallow_untyped_defs = false  # ✅ Allow untyped functions
ignore_missing_imports = true  # ✅ Don't block on third-party stubs
```

**Why Permissive?**
- Existing codebase can pass type checking immediately
- Developers aren't overwhelmed with hundreds of type errors
- Enables incremental adoption without friction

### Progressive Strictness: Module Overrides

The configuration uses targeted `[[tool.mypy.overrides]]` sections to enforce increasing strictness:

## Phase 1: Foundation Modules (Week 1) - STRICT MODE ✅

**Target Modules:**
- `apps.common.types` - Type definitions
- `apps.common.validators` - Validation functions
- `apps.common.utils` - Utility functions

**Strictness Level:** Maximum
```toml
strict = true
disallow_untyped_defs = true
disallow_incomplete_defs = true
warn_return_any = true
```

**Rationale:** These modules provide types for the rest of the system and must be fully typed.

## Phase 2: Core Apps (Week 1-2) ⚡

**Target Modules:**
- `apps.audit.*` - Audit logging (already well-typed)
- `apps.billing.*` - Billing system (high business value)
- `apps.users.*` - User management (security critical)

**Strictness Level:** High
```toml
disallow_untyped_defs = true  # ✅ Require function signatures
disallow_incomplete_defs = false  # 🔄 Allow partial typing during transition
check_untyped_defs = true  # ✅ Check existing types
```

**Why These Apps First?**
- Already have good type coverage from previous work
- High business impact and security requirements
- Core functionality that other apps depend on

## Phase 3: Business Logic Apps (Week 3-4) 📋

**Target Modules:**
- `apps.customers.*` - Customer management
- `apps.tickets.*` - Support ticketing
- `apps.orders.*` - Order processing
- `apps.products.*` - Product catalog

**Strictness Level:** Medium
```toml
disallow_untyped_defs = false  # 🔄 Relaxed during migration
check_untyped_defs = true  # ✅ Check what IS typed
```

**Transition Strategy:**
1. Add types to new functions first
2. Gradually type existing functions
3. Enable `disallow_untyped_defs = true` when ready

## Phase 4: Infrastructure Apps (Week 5-6) 🔧

**Target Modules:**
- `apps.provisioning.*` - Service provisioning
- `apps.domains.*` - Domain management
- `apps.integrations.*` - External integrations
- `apps.notifications.*` - Notification system

**Strictness Level:** Permissive Initially
```toml
disallow_untyped_defs = false
ignore_missing_imports = true  # Many third-party integrations
```

**Why Most Permissive?**
- Complex integration code with many third-party dependencies
- External API responses often lack proper typing
- Focus on functionality first, types second

## Strategic Modules: Always Strict 💎

**Target Modules:**
- `apps.*.services` - Business logic layer
- `apps.*.repos` - Data access layer
- `apps.*.gateways` - External integration layer

**Strictness Level:** High
```toml
disallow_untyped_defs = true
check_untyped_defs = true
```

**Rationale:**
- Service layer benefits most from type safety
- Clean architecture boundaries need clear contracts
- Future microservices extraction points

## Django Integration

### Django-Stubs Configuration

```toml
[tool.django-stubs]
django_settings_module = "config.settings.dev"
strict_settings = false  # Relaxed during gradual adoption
ignore_missing_model_attributes = true  # Allow missing Django model attributes
```

### Common Django Typing Patterns

**Model Fields:**
```python
# Before
def get_customer_name(customer_id):
    return Customer.objects.get(id=customer_id).name

# After
def get_customer_name(customer_id: int) -> str:
    return Customer.objects.get(id=customer_id).name
```

**QuerySets:**
```python
from django.db.models import QuerySet
from apps.customers.models import Customer

def get_active_customers() -> QuerySet[Customer]:
    return Customer.objects.filter(status='active')
```

**Views:**
```python
from django.http import HttpRequest, HttpResponse

def customer_detail(request: HttpRequest, customer_id: int) -> HttpResponse:
    # Implementation
    pass
```

## Development Workflow

### Running Type Checks

```bash
# Check all code (permissive)
make lint

# Check specific app
mypy apps/billing/

# Check specific module with strict settings
mypy apps/common/types.py
```

### Adding Types to Existing Code

1. **Start with function signatures:**
   ```python
   # Before
   def calculate_total(items, tax_rate):

   # After
   def calculate_total(items: list[dict], tax_rate: float) -> Decimal:
   ```

2. **Add return types:**
   ```python
   def get_customer_balance(customer_id: int) -> Decimal:
       # Implementation
   ```

3. **Handle Django patterns:**
   ```python
   from typing import Optional
   from django.contrib.auth import get_user_model

   User = get_user_model()

   def find_user_by_email(email: str) -> Optional[User]:
       try:
           return User.objects.get(email=email)
       except User.DoesNotExist:
           return None
   ```

### Type Ignore Patterns

Use `# type: ignore` sparingly and with comments:

```python
# Complex Django magic that mypy doesn't understand
customer = Customer.objects.select_related('billing_profile').get(
    id=customer_id
)  # type: ignore[misc]  # Django select_related magic

# Third-party library without stubs
import some_external_lib
result = some_external_lib.complex_function()  # type: ignore[no-untyped-call]
```

## Rollout Timeline

### Week 1: Foundation & Core Apps
- [x] Configure gradual typing in `pyproject.toml`
- [x] Install django-stubs and type dependencies
- [ ] Enable strict mode for `apps.common.*` modules
- [ ] Verify `apps.audit.*`, `apps.billing.*`, `apps.users.*` pass type checking

### Week 2: Core App Refinement
- [ ] Address any type errors in core apps
- [ ] Add missing type annotations in service layers
- [ ] Document common Django typing patterns

### Week 3-4: Business Logic Apps
- [ ] Enable type checking for `apps.customers.*`
- [ ] Enable type checking for `apps.tickets.*`
- [ ] Enable type checking for `apps.orders.*`
- [ ] Enable type checking for `apps.products.*`

### Week 5-6: Infrastructure Apps
- [ ] Enable type checking for `apps.provisioning.*`
- [ ] Enable type checking for `apps.domains.*`
- [ ] Enable type checking for `apps.integrations.*`
- [ ] Enable type checking for `apps.notifications.*`

### Week 7-8: Project-wide Strict Mode
- [ ] Evaluate readiness for global strict mode
- [ ] Address remaining type errors
- [ ] Enable `strict = true` globally if achievable

## Monitoring Progress

### Type Coverage Report
```bash
# Generate type coverage report
python scripts/type_coverage_report.py

# View current coverage
cat type_coverage_report.json
```

### Mypy Configuration Testing
```bash
# Test configuration changes
mypy --config-file=pyproject.toml apps/

# Check specific phase compliance
mypy apps/billing/ apps/users/ apps/audit/  # Phase 2 apps
```

## Best Practices

### DO ✅
- Add types to new code immediately
- Use `typing.TYPE_CHECKING` for import cycles
- Leverage `apps.common.types` for shared type definitions
- Document complex type annotations
- Use `Optional[T]` instead of `T | None` for Django compatibility

### DON'T ❌
- Don't add `# type: ignore` without explanation comments
- Don't make everything `Any` - be specific where possible
- Don't enable strict mode globally until apps are ready
- Don't ignore type errors in service layer modules

### Django-Specific DO's ✅
- Use `django-stubs` provided types
- Type model fields with proper field types
- Use `QuerySet[ModelClass]` for queryset returns
- Type view functions with `HttpRequest` and `HttpResponse`

## Troubleshooting

### Common Issues

**1. Django Model Import Cycles**
```python
# Solution: Use TYPE_CHECKING
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from apps.customers.models import Customer

def process_customer(customer: 'Customer') -> None:
    # Implementation
```

**2. Missing Third-Party Stubs**
```bash
# Stubs are included in development dependencies
# Ensure your environment is synced
uv sync --group dev
```

**3. Complex Django QuerySet Types**
```python
# Use django-stubs provided types
from django.db.models import QuerySet
from apps.customers.models import Customer

def get_filtered_customers() -> QuerySet[Customer]:
    return Customer.objects.filter(active=True)
```

## Configuration Files Reference

### pyproject.toml - Main Configuration
The master configuration is in `pyproject.toml` under `[tool.mypy]` section.

### requirements/dev.txt - Dependencies
```
mypy>=1.5.0
django-stubs[compatible-mypy]>=4.2.0
types-requests>=2.31.0
types-python-dateutil>=2.8.0
```

## Quick Reference Commands

### Testing Type Configuration
```bash
# Test gradual typing configuration across all phases
python scripts/test_gradual_typing.py

# Check specific app/module
mypy --config-file=pyproject.toml apps/billing/

# Check with verbose output
mypy --config-file=pyproject.toml --verbose apps/common/types.py
```

### Development Workflow
```bash
# 1. Install/update type dependencies
uv sync --all-groups

# 2. Test current type coverage
python scripts/test_gradual_typing.py

# 3. Work on specific app types
mypy apps/users/services.py  # Focus on service layer first

# 4. Check overall progress
make lint  # Includes mypy in lint target
```

### Configuration Status

✅ **COMPLETED (Phase 2.2)**:
- Gradual typing configuration in `pyproject.toml`
- Django-stubs integration with proper plugins
- Per-app progressive strictness overrides
- Comprehensive documentation and testing scripts
- Development dependency updates

🔄 **NEXT STEPS (Phase 2.3+)**:
- Week 1-2: Fix foundation and core app type errors
- Week 3-4: Enable stricter checks for business logic apps
- Week 5-6: Address infrastructure app typing
- Week 7-8: Consider project-wide strict mode

## Support & Questions

For typing-related questions:
1. Check this documentation first
2. Review existing typed modules in `apps/common/`, `apps/audit/`, `apps/billing/`, `apps/users/`
3. Consult Django-stubs documentation: https://github.com/typeddjango/django-stubs
4. Use `reveal_type()` for debugging type inference
5. Run `python scripts/test_gradual_typing.py` to test configuration

---

*This configuration enables type safety adoption without overwhelming developers, supporting the PRAHO Platform's goal of maintainable, scalable code.*
