# 🔗 Pre-commit Hooks Guide - PRAHO Platform

## Overview

The PRAHO Platform uses pre-commit hooks to maintain **type safety** and **code quality** during development. This system prevents regression during the gradual typing rollout while ensuring performance and security standards.

## 🚀 Quick Start

### 1. Install Pre-commit Hooks

```bash
# One-time setup
make install-pre-commit
```

This will:
- Install pre-commit Python package
- Configure git hooks automatically
- Enable all type safety and linting checks

### 2. Normal Development Workflow

```bash
# Hooks run automatically on every commit
git add .
git commit -m "feat: add new feature"

# If hooks fail, fix issues and retry
git add .
git commit -m "feat: add new feature (fixed linting issues)"
```

### 3. Manual Hook Execution

```bash
# Run all hooks on all files
make pre-commit

# Run hooks only on staged files
make pre-commit-modified

# Skip hooks for urgent fixes
git commit --no-verify -m "hotfix: urgent production fix"
```

## 🎯 Pre-commit Features

### ⚡ **Strategic Linting (Ruff)**
- **Performance focus**: Detects O(N²) algorithms, inefficient loops
- **Security scanning**: Hardcoded credentials, SQL injection risks
- **Django best practices**: ORM optimization, template security

```bash
# Manual strategic linting
make lint
```

### 🏷️ **Type Safety Enforcement**
- **Modified files only**: Fast feedback (only checks changed files)
- **Progressive strictness**: Respects gradual typing configuration
- **Regression prevention**: Blocks new `# type: ignore` comments

```bash
# Manual type checking
make type-check-modified
.venv/bin/python scripts/check_types_modified.py --verbose
```

### 🚫 **Type Ignore Prevention**
- **Strict modules**: Zero tolerance for `# type: ignore` in core files
- **Legacy support**: Temporary allowances during transition
- **Clear guidance**: Suggests proper fixes instead of ignoring

```bash
# Check for type ignore violations
.venv/bin/python scripts/prevent_type_ignore.py --check-all
```

### 🎨 **Django Template Safety**
- **Syntax validation**: Prevents template comparison operator spacing issues
- **HTMX compatibility**: Ensures HTMX attributes work correctly
- **Auto-fixing**: Automatically corrects common template issues

```bash
# Template checking and fixing
make check-templates
make fix-templates
```

### 🔒 **Security Checks**
- **Credential scanning**: Detects hardcoded passwords/API keys
- **Informational mode**: Warns without blocking (manual review required)
- **Context-aware**: Distinguishes dev/test/prod contexts

## 🔧 Configuration Files

### `.pre-commit-config.yaml`
Main configuration file defining all hooks:
- **Ruff linting**: Strategic rules from `pyproject.toml`
- **Type checking**: Uses `scripts/check_types_modified.py`
- **Template validation**: Uses `scripts/fix_template_comparisons.py`
- **Security scanning**: Credential detection with context awareness

### `pyproject.toml`
- **Mypy configuration**: Gradual typing settings
- **Ruff rules**: Strategic linting configuration
- **Per-app strictness**: Different rules for different modules

### Helper Scripts
- `scripts/check_types_modified.py`: Efficient type checking
- `scripts/prevent_type_ignore.py`: Blocks type ignore regression
- `scripts/type_coverage_report.py`: Typing coverage analysis

## 🎛️ Hook Configuration

### Execution Stages
```yaml
default_stages: [pre-commit]  # Run on git commit
```

### File Exclusions
```yaml
exclude: ^(migrations/.*\.py|scripts/backup\.py)$
```

### Performance Optimization
- **Modified files only**: Type checking only runs on changed files
- **Strategic linting**: Focus on performance/security, ignore cosmetics
- **Fast feedback**: Hooks complete in seconds, not minutes

## 🚦 Bypassing Hooks

### When to Skip Hooks
- **Urgent hotfixes**: Production emergencies
- **Bulk operations**: Large refactoring/renaming
- **Experimental branches**: Early development phases

### How to Skip
```bash
# Skip all hooks
git commit --no-verify -m "hotfix: urgent fix"

# Skip specific hook types
SKIP=type-check-modified git commit -m "wip: work in progress"

# Skip multiple hooks
SKIP=ruff,type-check-modified git commit -m "experimental: trying new approach"
```

## 🎯 Developer Workflow Integration

### Standard Development
```bash
# 1. Make changes
vim apps/users/models.py

# 2. Run tests
make test

# 3. Commit (hooks run automatically)
git add .
git commit -m "feat(users): add email validation"

# 4. If hooks fail, fix and retry
make lint-fix  # Auto-fix what's possible
git add .
git commit -m "feat(users): add email validation"
```

### Working with Type Safety
```bash
# Check type issues before committing
make type-check-modified

# Generate type coverage report
make type-coverage

# Check for type ignore violations
.venv/bin/python scripts/prevent_type_ignore.py --check-all --allow-legacy
```

## 📊 Monitoring & Reports

### Type Coverage Tracking
```bash
# Generate JSON report
make type-coverage

# View markdown report
.venv/bin/python scripts/type_coverage_report.py --markdown
```

### CI/CD Integration
```bash
# Run all pre-commit checks in CI
make ci-pre-commit

# Type safety validation
make ci-type-safety
```

## 🔍 Troubleshooting

### Common Issues

#### 1. **"pre-commit not found"**
```bash
make install-pre-commit
```

#### 2. **"Type checking failed"**
```bash
# Check specific file
mypy --config-file=pyproject.toml apps/users/models.py

# Fix type issues
# Add type hints, use Union types, etc.
```

#### 3. **"Template syntax error"**
```bash
# Auto-fix templates
make fix-templates

# Manual check
make check-templates
```

#### 4. **"Hook installation failed"**
```bash
# Reinstall hooks
rm -rf .git/hooks/pre-commit
make install-pre-commit
```

### Hook Performance Issues

#### Slow Hook Execution
```bash
# Check which hooks are slow
.venv/bin/pre-commit run --verbose

# Skip slow hooks temporarily
SKIP=type-check-modified git commit -m "message"
```

#### Large File Changes
```bash
# For bulk changes, consider:
git commit --no-verify -m "refactor: bulk rename operations"

# Then run hooks manually
make pre-commit
```

## 🎯 Phase 2.3 Integration

### Gradual Typing Support
- **Respects mypy configuration**: Uses Phase 2.2 gradual typing settings
- **Progressive enforcement**: Strict for foundation modules, permissive for legacy
- **Clear migration path**: Guidance for moving from permissive to strict

### Performance Focus
- **O(N²) detection**: Prevents performance regressions
- **Query optimization**: Ensures Django ORM efficiency
- **Security first**: Blocks credential leaks and security anti-patterns

### Romanian Compliance
- **Template validation**: Ensures Romanian UI components work correctly
- **Internationalization**: Validates translation patterns
- **Business logic**: Maintains quality in Romanian-specific code

## 📚 Further Reading

- [ADR-0003: Comprehensive Type Safety Implementation](adrs/ADR-0003-comprehensive-type-safety-implementation.md)
- [Gradual Typing Configuration](GRADUAL_TYPING_CONFIGURATION.md)
- [Strategic Linting Framework](adrs/ADR-0002-strategic-linting-framework.md)
- [Pre-commit Documentation](https://pre-commit.com/)

## 💡 Best Practices

### 1. **Run Tests First**
Always run `make test` before committing to catch functional issues early.

### 2. **Fix Don't Ignore**
Use proper type annotations instead of `# type: ignore` comments.

### 3. **Strategic Linting Focus**
Address performance and security issues immediately, cosmetic issues can wait.

### 4. **Template Validation**
Always run `make check-templates` after modifying Django templates.

### 5. **Legacy Migration**
Use `--allow-legacy` flags during transition period, then remove gradually.

---

**🎯 Result**: Pre-commit hooks maintain type safety progress while providing fast developer feedback and preventing regression during the gradual typing rollout.
