# Strategic Linting Framework - Developer Guide

This document provides a quick reference for developers working with PRAHO Platform's strategic linting framework.

## Quick Reference

### Essential Commands
```bash
# Daily development linting
make lint                 # Standard development checks
make lint-fix            # Apply safe auto-fixes

# Focused security checks
make lint-security        # Security vulnerabilities
make lint-credentials     # Hardcoded password detection

# Performance optimization
make lint-performance     # O(N²) and efficiency patterns
```

## Rule Categories & Priorities

### 🔥 HIGH PRIORITY (Auto-fix enabled)
- **PERF**: Performance anti-patterns (list comprehensions, O(N²) detection)
- **S**: Security issues (hardcoded passwords flagged for manual review)
- **DJ**: Django best practices (model optimizations, view patterns)
- **ANN**: Type annotations (AI/LLM readability improvements)
- **SIM**: Code simplification (logical simplifications, readability)

### ✅ MEDIUM PRIORITY (Review recommended)
- **B**: Bug-prone patterns
- **E**: Error patterns
- **F**: Fatal errors (syntax, imports)

### 📝 STRATEGICALLY IGNORED (Cosmetic/Low Impact)
- **Line length** (E501): Romanian business terms are longer
- **Quote consistency** (Q000-Q003): Not business critical
- **Whitespace formatting** (W291-W293): Handled by IDE
- **Import sorting** (I001-I002): Handled by isort integration

## Performance Optimization Patterns

### List Operations (PERF401)
```python
# ⚡ PREFER: List comprehension
results = [transform(item) for item in items]

# ❌ AVOID: Append loop
results = []
for item in items:
    results.append(transform(item))
```

### Bulk Operations
```python
# ⚡ PREFER: Single extend operation
stack.extend(rel.child_service for rel in relationships)

# ❌ AVOID: Multiple appends
for rel in relationships:
    stack.append(rel.child_service)
```

## Security Guidelines

### Hardcoded Credentials (S105, S106)
- **69 credentials flagged** for manual review across the codebase
- **Test files**: Allowed (test data)
- **Production code**: Manual review required
- **Settings files**: Warnings enabled, not auto-fixed

### Security Best Practices
- Never auto-ignore security warnings
- Review flagged credentials quarterly
- Use environment variables for sensitive data
- Validate all inputs at the edge

## File-Specific Configurations

### Test Files (`tests/`)
```python
# Allowed in tests:
- Hardcoded test credentials
- Magic numbers for assertions
- Import star usage (fixtures)
```

### Migration Files (`*/migrations/`)
```python
# Ignored in migrations:
- All formatting rules (auto-generated)
- Performance rules still active
```

### Settings Files
```python
# Special handling:
- Credential warnings enabled
- Manual security review workflow
- Environment variable validation
```

## VS Code Integration

### Auto-Approved Commands
The following commands are auto-approved in terminals:
- `make lint`, `make lint-security`, `make lint-credentials`, `make lint-performance`, `make lint-fix` - Linting commands
- `make test`, `make test-fast` - Testing commands
- `.venv/bin/ruff` - Direct Ruff commands
- `head`, `tail` - File viewing
- `cat`, `ls` - Directory listing
- `grep` - Text searching

### Performance Monitoring
- Real-time linting in VS Code
- Auto-fix suggestions
- Performance issue highlighting

## Common Issues & Solutions

### Performance Anti-patterns
```python
# Issue: O(N²) nested loops
for user in users:
    for permission in user.permissions.all():  # N+1 query
        process(permission)

# Solution: Prefetch optimization
users = User.objects.prefetch_related('permissions')
for user in users:
    for permission in user.permissions.all():  # Cached
        process(permission)
```

### Security Patterns
```python
# Issue: Hardcoded credential
API_KEY = "sk-1234567890abcdef"  # Flagged by S105

# Solution: Environment variable
API_KEY = os.getenv('API_KEY')
if not API_KEY:
    raise ValueError("API_KEY environment variable required")
```

## Metrics & Progress Tracking

### Current Status
- **Initial Issues**: 848 linting issues identified
- **Performance Issues**: 10 → 0 (100% resolved)
- **Auto-fixable Issues**: 68 → 0 (100% resolved)
- **Security Warnings**: 69 (preserved for manual review)

### Continuous Improvement
- **Weekly**: Review new performance anti-patterns
- **Monthly**: Adjust rules based on codebase evolution
- **Quarterly**: Security audit of flagged credentials

## Related Documentation

- **ADR-0002**: Complete strategic linting framework decision record
- **CHANGELOG.md**: Performance and security improvements log
- **pyproject.toml**: Complete rule configuration
- **Makefile**: Enhanced linting commands

## Getting Help

### Common Commands
```bash
# Check specific rule category
.venv/bin/ruff check . --select=PERF --no-fix

# Get help for specific rule
.venv/bin/ruff rule PERF401

# Statistics overview
.venv/bin/ruff check . --statistics
```

### Performance Issues
If you encounter performance anti-patterns:
1. Check for list comprehension opportunities (PERF401)
2. Look for O(N²) nested operations
3. Consider bulk operations with `list.extend()`
4. Add performance comments with `# ⚡ PERFORMANCE:`

### Security Issues
If security warnings appear:
1. **Never auto-ignore** security rules
2. Use environment variables for credentials
3. Add to manual review list for quarterly audit
4. Document why credentials are needed (test data, etc.)

---

**Last Updated**: 2025-08-25
**Framework Version**: Ruff 0.6.8 + MyPy 1.17.1
**Documentation**: ADR-0002 Strategic Linting Framework
