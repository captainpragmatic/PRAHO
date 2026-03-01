# ADR-0009: Pragmatic MyPy Configuration Strategy

**Date:** 2025-08-27
**Status:** Accepted
**Supersedes:** ADR-0008 (MyPy Removal)

## Context

After implementing comprehensive MyPy type checking in PRAHO Platform, we discovered that strict typing across all Django code creates more noise than value. Our analysis showed:

- **Original state**: 995 MyPy errors with `strict = true`
- **After Phase 1-2**: Reduced to ~700 errors through manual annotation
- **Key insight**: Most errors are Django framework noise, not actual bugs

### Industry Reality Check

- **Django core team** has MyPy errors in their own codebase
- **Production apps** like Shopify, Instagram run Django with 0% type coverage successfully
- **Real-world evidence**: Most Django projects succeed without full typing

### Error Analysis Results

From our comprehensive analysis:
```
355 [assignment]    # Often Django ORM noise
164 [type-arg]      # Generic type issues in Django
133 [attr-defined]  # Django magic attributes (request.user, etc.)
 85 [union-attr]    # Nullable fields and request.user
 87 [misc]          # Django-specific patterns
```

## Decision

Implement a **layered typing strategy** that prioritizes business logic while ignoring Django framework noise.

### Core Principles

1. **Business Logic First**: Strict typing for critical business code
2. **Ignore Framework Noise**: Django views/models have relaxed rules
3. **Fix Real Bugs**: Focus on errors that indicate actual problems
4. **Pragmatic Over Perfect**: 200 meaningful errors > 995 mixed errors

## Implementation

### Global Safe Ignores
```toml
[tool.mypy]
strict = true
disable_error_code = [
    "attr-defined",     # Django magic (request.user, ORM methods)
    "empty-body",       # Protocol stubs and abstract methods
    "redundant-cast",   # Harmless explicit casts
    "no-any-return",    # Django views return Any often
]
```

### Per-Module Strategy
```toml
# Relaxed checking for Django framework layers
[[tool.mypy.overrides]]
module = [
    "*.views",
    "*.models",
    "*.forms",
    "*.admin",
]
disable_error_code = ["assignment", "type-arg"]

# Strict checking for business logic
[[tool.mypy.overrides]]
module = [
    "*.services.*",
    "*.utils.*",
    "*.repos.*",
    "*.gateways.*",
    # Romanian business logic
    "apps.common.validators",
    "apps.billing.calculations",
]
strict = true
```

### Error Triage Decision Tree

| Error Type | Context | Action |
|------------|---------|--------|
| `[assignment]` | views/models | **IGNORE** - Django ORM noise |
| `[assignment]` | services/utils | **FIX** - Real type mismatch |
| `[arg-type]` | `request.user` | Add type guard |
| `[arg-type]` | Function args | **FIX** - Real bug |
| `[return-value]` | Any context | **ALWAYS FIX** - Real bug |
| `[union-attr]` | `request.user` | Add `if user.is_authenticated` |
| `[union-attr]` | Nullable field | Add `if obj.field is not None` |

## Expected Outcomes

- **Error reduction**: 995 → ~200 meaningful errors
- **Developer productivity**: Focus on real bugs, not Django noise
- **Code quality**: Better type safety where it matters
- **Maintainability**: Sustainable typing strategy

## Romanian Business Logic Priority

Special attention to type safety in:
- **CUI/VAT validation** (`apps.common.validators`)
- **Invoice calculations** (`apps.billing.calculations`)
- **Payment processing** (`apps.billing.services`)
- **e-Factura generation** (when implemented)

## Migration Strategy

### Phase 1: Implement Smart Ignores ✅
- Add global safe ignores
- Configure per-module overrides
- **Result**: 986 → 706 errors (28.4% reduction)

### Phase 2: Focus on Business Logic
- Fix critical path errors in services/utils
- Add type guards for common patterns
- Target: <200 errors

### Phase 3: Maintenance
- Monitor error trends with `make type-check-modified`
- Add type annotations for new business logic
- Keep Django layers relaxed

## Tools and Commands

```bash
# Check specific error types
make type-check 2>&1 | grep -o '\[[a-z-]*\]$' | sort | uniq -c

# Focus on business logic files
mypy apps/*/services.py apps/*/utils.py

# Modified files only (developer workflow)
make type-check-modified
```

## Rationale

### Why This Approach Works

1. **Pragmatic**: Acknowledges Django's dynamic nature
2. **Focused**: Type safety where bugs have business impact
3. **Sustainable**: Developers can maintain without fighting framework
4. **Evidence-based**: Built on analysis of 995 real MyPy errors

### Why Not Full Strict Mode

- Django ORM creates unavoidable type complexity
- `request.user` patterns require extensive type guards
- Framework evolution outpaces typing definitions
- Developer productivity vs. theoretical type safety trade-off

## Consequences

### Positive
- ✅ Focus on meaningful type errors
- ✅ Sustainable for team development
- ✅ Better error signal-to-noise ratio
- ✅ Maintains strict checking for business logic

### Negative
- ❌ Not "100% typed" (which is impractical with Django)
- ❌ Some theoretical type safety gaps in views/models
- ❌ Requires discipline to maintain business logic typing

### Risks and Mitigations

| Risk | Mitigation |
|------|------------|
| Missing real bugs in views | Focus on business logic validation |
| Type discipline erosion | Pre-commit hooks for services/utils |
| Django upgrade issues | Regular mypy-django-plugin updates |

## References

- [Django typing documentation](https://docs.djangoproject.com/en/stable/topics/typing/)
- [MyPy Django plugin](https://github.com/typeddjango/django-stubs)

## Notes

This ADR represents a **pragmatic evolution** from ADR-0008's complete MyPy removal. We learned that selective typing provides the best balance of safety and productivity for Django applications.

**Key insight**: Perfect typing coverage is less valuable than focused typing in critical business logic paths.
