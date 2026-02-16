# ADR-0006: Security Warning Configuration Strategy

**Date**: 2025-08-26
**Status**: Accepted
**Context**: PRAHO Platform security linting configuration

## Context and Problem Statement

The PRAHO Platform uses `ruff` with security rules (bandit S105/S106) to detect hardcoded passwords and secrets. However, our codebase contains 1200+ legitimate hardcoded credentials in test files, development utilities, and configuration files, creating excessive noise that obscures real security issues.

**Key challenges:**
- S105 (hardcoded-password-string): 17 instances
- S106 (hardcoded-password-func-arg): 1200+ instances in test files
- Legitimate development/test credentials flagged alongside real security risks
- `make lint` output overwhelmed with false positives

## Decision Drivers

- **Security Focus**: Maintain ability to detect real hardcoded production secrets
- **Developer Experience**: Clean lint output that highlights actionable issues
- **Django Best Practices**: Follow community standards for test fixtures and development utilities
- **Maintenance Burden**: Avoid per-line comment clutter across 1200+ locations

## Considered Options

### Option 1: Per-line `# noqa: S105,S106` comments
```python
password='testpass123'  # noqa: S106
```

**Pros**: Granular control, explicit acknowledgment per instance
**Cons**: 1200+ comments needed, code clutter, high maintenance burden

### Option 2: Disable S105/S106 globally
```toml
ignore = ["S105", "S106"]
```

**Pros**: Simple, no clutter
**Cons**: Completely disables security detection, misses real production secrets

### Option 3: File-level ignores with strategic exceptions
```toml
"tests/**/*.py" = ["S105", "S106"]  # Test credentials acceptable
```

**Pros**: Clean separation, maintains production security, follows Django patterns
**Cons**: Slightly less granular than per-line

## Decision

**Chosen Option 3: File-level ignores with strategic exceptions**

### Implementation in `pyproject.toml`:

```toml
[tool.ruff.lint.per-file-ignores]
# Test files - legitimate test credentials
"tests/**/*.py" = ["S105", "S106"]
"test_*.py" = ["S105", "S106"]

# Development settings - insecure keys acceptable in dev/test
"**/settings/dev.py" = ["S105"]
"**/settings/test.py" = ["S105", "S106"]

# Development utilities - sample data generation
"**/management/commands/*.py" = ["S105", "S106"]

# E2E test utilities
"tests/e2e/**/*.py" = ["S105", "S106"]
```

### Strategic exception maintained:
```python
# config/settings/base.py:311 - INTENTIONALLY KEPT AS WARNING
SECRET_KEY = 'django-insecure-dev-key-only-change-in-production-or-tests'
```

## Rationale for Base.py Exception

The fallback SECRET_KEY in `base.py` **intentionally remains flagged** despite being a legitimate development fallback:

### Why keep the warning:

1. **Development Reminder**: Ensures developers notice missing `DJANGO_SECRET_KEY` environment variable
2. **Security Consciousness**: Maintains awareness of insecure fallback usage
3. **Documentation**: Single S105 warning serves as living documentation of security consideration
4. **Production Protection**: Combined with `validate_production_secret_key()` in `prod.py` which crashes on insecure keys

### Safety mechanisms in place:
```python
# base.py - Fallback with warnings
if not SECRET_KEY:
    warnings.warn("🚨 SECURITY WARNING: Using default SECRET_KEY...")
    SECRET_KEY = 'django-insecure-...'  # ← S105 warning here

# prod.py - Production validation (crashes if insecure)
validate_production_secret_key()  # Prevents production deployment
```

## Consequences

### Positive:
- **Clean lint output**: Reduced from 1233 to 1 security warning
- **Focused security**: Real production secrets still detected
- **Developer efficiency**: `make lint` shows actionable issues only
- **Django alignment**: Follows community patterns for test fixtures
- **Maintenance reduced**: No per-line comment management needed

### Negative:
- **Slightly less granular**: File-level vs line-level control
- **Trust model**: Assumes developers won't add real secrets to ignored files

## Compliance

### Files where S105/S106 are ignored (acceptable):
- `tests/**/*.py` - Test fixtures and credentials
- `config/settings/dev.py` - Development SECRET_KEY only
- `config/settings/test.py` - Test credentials and fake API keys
- `apps/common/management/commands/*.py` - Sample data generation utilities
- `tests/e2e/**/*.py` - E2E test credentials

### Files where S105/S106 warnings remain active (critical):
- `config/settings/base.py` - Production-adjacent configuration
- `config/settings/prod.py` - Production settings
- All business logic files (`apps/*/models.py`, `apps/*/views.py`, etc.)

## Monitoring and Review

- **Current status**: 1 intentional S105 warning in `config/settings/base.py`
- **Review trigger**: Any new S105/S106 warnings outside ignored files require immediate investigation
- **Documentation**: This ADR explains the single remaining warning to prevent confusion

## Related Decisions

- **ADR-0005**: Single constants file architecture (security configuration centralization)
- **Future consideration**: Could evolve to fail-fast approach (no SECRET_KEY fallback) if environment variable discipline improves

---

**Tags**: security, linting, django, development-experience
**Updated**: Initial version
