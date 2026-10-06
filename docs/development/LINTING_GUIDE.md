# Strategic Linting Framework - Developer Guide

A quick reference for PRAHO's linting setup. The decision record is **ADR-0002**. The rule
configuration itself is `[tool.ruff]` in `pyproject.toml`, and that file wins wherever this guide
and it disagree.

## Quick Reference

### Essential Commands
```bash
make lint                          # Every phase, both services (see below)
make lint FILE=path/to/file.py     # Ruff on one file - use it on every file you change, tests included
make lint-fix                      # Apply Ruff's safe auto-fixes

make check-types                   # mypy (FILE=path relative to services/platform for one file)
make check-types-portal            # mypy for the portal

make lint-security                 # Security scanners (not part of `make lint`)
make lint-credentials              # Hardcoded-credential rules only (S105-S108)
```

`make lint` runs its phases in order and stops at the first failure. The Makefile's `lint:` target
is the authoritative list. Today the phases are:
- the Ruff no-new-debt gate;
- each service's checks;
- the test-layout audit;
- the test-suppression, i18n, code-health, FSM, cross-app-import and error-handling scans;
- the status-only test assertion ratchet.

The no-new-debt gate compares against your branch's merge base with `origin/master`. It sees only
committed changes, so lint uncommitted files with `make lint FILE=`.

## Rule Categories & Priorities

### 🔥 HIGH PRIORITY
- **PERF**: Performance anti-patterns (list comprehensions, O(N²) detection)
- **S**: Security issues (hardcoded passwords are flagged for manual review)
- **DJ**: Django best practices (model optimizations, view patterns)
- **ANN**: Type annotations
- **SIM**: Code simplification

### ✅ MEDIUM PRIORITY (review recommended)
- **B**: Bug-prone patterns
- **E**: Error patterns
- **F**: Fatal errors (syntax, imports)
- **I**: Import order. It is enforced, and `make lint-fix` sorts imports.

### 📝 STRATEGICALLY IGNORED (cosmetic or low impact)
- **Line length** (E501): Romanian business terms are long
- **Quote style** (Q000): not business critical
- **Trailing whitespace** (W291, W293): handled by the formatter

The full ignore list, with a reason for each entry, is in `pyproject.toml`.

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
- **Production code**: flagged everywhere, with no global ignore. Review every hit.
- **Test files, management commands and dev settings**: allowed through per-file ignores in `pyproject.toml`.
- Run `make lint-credentials` for the current list. Don't record a count here, because it goes stale.

### Security Best Practices
- Never auto-ignore security warnings
- Use environment variables for sensitive data
- Validate all inputs at the edge

## File-Specific Configurations

### Test Files and Migrations
- `tests` and `migrations` directories are in Ruff's `exclude` list, so a directory-wide run such as
  `make lint` skips them.
- A file passed explicitly (`make lint FILE=...`) is linted anyway. That is why every changed test
  file should get a `make lint FILE=` run.
- Under that explicit run, tests may use asserts, test credentials and magic numbers, and may omit
  type hints and docstrings. Migrations may have long lines.

### Settings Files
- Credential warnings stay enabled. Only the development settings may hold a hardcoded `SECRET_KEY`.
- Long lines are allowed.

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

## Getting Help

Ruff lives in the per-OS virtualenv: `.venv-darwin` on macOS, `.venv-linux` on Linux. Call it
directly, and don't use `uv run`, which re-syncs the environment:
```bash
RUFF=.venv-$(uname -s | tr '[:upper:]' '[:lower:]')/bin/ruff

$RUFF check services/platform/apps --select=PERF --no-fix   # One rule family
$RUFF rule PERF401                                          # Explain a rule
$RUFF check services/platform/apps --statistics             # Counts by rule
```

### Performance Issues
If you hit a performance anti-pattern:
1. Look for list comprehension opportunities (PERF401)
2. Look for O(N²) nested operations
3. Consider bulk operations with `list.extend()`
4. Add a performance comment with `# ⚡ PERFORMANCE:`

### Security Issues
If security warnings appear:
1. **Never auto-ignore** security rules
2. Use environment variables for credentials
3. Document why a credential is needed (test data, etc.)

## Related Documentation

- **ADR-0002**: Strategic linting framework decision record
- **`pyproject.toml`**: Complete rule configuration
- **`Makefile`**: The lint targets and the phases of `make lint`
- **`uv.lock`**: The pinned Ruff and mypy versions
