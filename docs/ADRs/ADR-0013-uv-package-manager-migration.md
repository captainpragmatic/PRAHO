# ADR-0013: Migration to uv Package Manager

**Status:** Accepted
**Date:** 2026-01-03
**Authors:** Development Team
**Supersedes:** N/A

## Context

PRAHO Platform is a Django-based monorepo with two services (platform and portal) that have distinct dependency requirements. The project was using pip with requirements.txt files and a constraints.txt for version pinning.

### Current Challenges

1. **Slow CI/CD Pipelines:** Dependency installation in GitHub Actions took 45-90 seconds per job, with cache misses causing even longer waits.

2. **Inconsistent Environments:** Without a lockfile, different developers and CI runs could resolve to different package versions, leading to "works on my machine" issues.

3. **Complex Dependency Management:** Managing separate requirements files for platform (base.txt, dev.txt, prod.txt) and portal required manual coordination.

4. **No Python Version Management:** The project relied on system Python or manual pyenv setup, creating onboarding friction.

5. **Monorepo Limitations:** pip doesn't natively support workspaces, making cross-service dependency management fragile.

## Decision

We are migrating from pip + requirements.txt to **uv** (https://docs.astral.sh/uv/) using the **workspace** pattern for our monorepo architecture.

### Why uv?

#### 1. Performance (The Primary Driver)

uv is 10-100x faster than pip for package operations:

| Operation | pip | uv | Improvement |
|-----------|-----|------|-------------|
| Cold install (100 packages) | ~45s | ~2s | 22x faster |
| Cached install | ~15s | <1s | 15x+ faster |
| Dependency resolution | ~8s | <0.5s | 16x faster |
| Lock file generation | N/A | <1s | New capability |

This speed improvement directly translates to:
- Faster CI/CD pipelines (reduced GitHub Actions minutes/costs)
- Faster developer onboarding
- Quicker local environment recreation
- Reduced context switching during development

#### 2. Reproducible Builds via Lockfile

uv generates a `uv.lock` file that:
- Pins exact versions of all dependencies (direct and transitive)
- Records package hashes for integrity verification
- Ensures identical environments across all machines and CI runs
- Eliminates "works on my machine" issues

#### 3. Native Monorepo Support via Workspaces

uv workspaces provide:
- **Single lockfile** for the entire repository
- **Dependency groups** for environment-specific packages (dev, prod, platform, portal)
- **Service isolation** maintained through selective group installation
- **Shared resolution** prevents version conflicts between services

#### 4. Python Version Management

uv handles Python installation:
- `.python-version` file specifies project Python version (3.11)
- `uv python install` downloads and manages Python automatically
- No more pyenv, asdf, or manual Python installation required

#### 5. Modern Python Packaging Standards

uv uses:
- PEP 517/518 build system specification
- pyproject.toml as the single source of truth
- PEP 621 project metadata
- PEP 735 dependency groups (standardized dev dependencies)

### Alternatives Considered

#### Option 1: pip-tools (pip-compile)
- **Pros:** Familiar, generates requirements.txt lockfiles
- **Cons:** Still slow (20x slower than uv), no workspace support, manual Python management
- **Verdict:** Rejected - doesn't address performance or monorepo needs

#### Option 2: Poetry
- **Pros:** Popular, good lockfile support, project management
- **Cons:**
  - Slower than uv (5-10x slower)
  - Non-standard pyproject.toml extensions
  - No workspace support for monorepos
  - Complex dependency resolver that can be slow
- **Verdict:** Rejected - doesn't fit monorepo architecture, slower than uv

#### Option 3: PDM
- **Pros:** PEP 582 support, good performance, workspaces
- **Cons:**
  - Smaller community than Poetry/uv
  - PEP 582 adoption uncertain
  - Less CI/CD tooling support
- **Verdict:** Rejected - uv has better ecosystem support and is faster

#### Option 4: Minimal pip Migration (uv pip interface)
- **Pros:** Minimal changes, immediate speed boost
- **Cons:**
  - Doesn't leverage lockfiles
  - Still uses requirements.txt (no dependency groups)
  - Misses workspace benefits
- **Verdict:** Rejected - doesn't fully address our needs

### Implementation Strategy: UV Workspaces

We chose the "Best" option: full workspace implementation.

```
PRAHO/
├── pyproject.toml          # Workspace root with dependencies and groups
├── uv.lock                  # Single lockfile for all services
├── .python-version          # Python 3.11
├── services/
│   ├── platform/
│   │   └── pyproject.toml  # Platform service package
│   └── portal/
│       └── pyproject.toml  # Portal service package
└── Makefile                # uv-aware commands
```

**Dependency Groups:**
- `dev`: Testing, linting, type checking (pytest, ruff, mypy, etc.)
- `prod`: Production server and monitoring (gunicorn, sentry, etc.)
- `platform`: Database, auth, billing, etc. (psycopg2, django-allauth, stripe, etc.)
- `portal`: Minimal production dependencies (gunicorn only)

**Service Installation:**
```bash
# Full development environment
uv sync --all-groups

# Platform only (CI)
uv sync --group platform --group dev

# Portal only (CI) - no database drivers
uv sync --group portal --group dev
```

## Implementation

### Files Changed

1. **pyproject.toml (root):** Added dependencies, dependency-groups, and [tool.uv.workspace]
2. **services/platform/pyproject.toml:** New workspace member config
3. **services/portal/pyproject.toml:** New workspace member config
4. **.python-version:** New file specifying Python 3.11
5. **Makefile:** Updated to use `uv run` and `uv sync`
6. **.github/workflows/*.yml:** Updated to use `astral-sh/setup-uv@v4`

### Migration Commands

```bash
# Install uv
curl -LsSf https://astral.sh/uv/install.sh | sh

# Generate lockfile
uv lock

# Install all dependencies
uv sync --all-groups

# Run commands through uv
uv run python manage.py migrate
uv run pytest
uv run ruff check .
```

### Backward Compatibility

- **Legacy requirements.txt files retained:** For reference and gradual migration
- **`make install-legacy` target:** Falls back to pip for environments without uv
- **Makefile auto-detection:** Uses uv if available, falls back to .venv/bin/python

## Consequences

### Positive

1. **10-100x Faster CI/CD:** Dependency installation reduced from 45-90 seconds to <5 seconds
2. **Reproducible Builds:** `uv.lock` ensures identical environments everywhere
3. **Simplified Onboarding:** `make install` handles Python + dependencies automatically
4. **Single Source of Truth:** pyproject.toml replaces multiple requirements files
5. **Better Dependency Visibility:** `uv tree` shows full dependency graph
6. **Service Isolation Maintained:** Dependency groups preserve platform/portal separation
7. **Future-Proof:** uv is actively developed by Astral (same team as Ruff)

### Negative

1. **Learning Curve:** Team needs to learn uv commands (mitigated by Makefile wrappers)
2. **New Tooling Dependency:** uv must be installed (mitigated by install script)
3. **Lockfile Churn:** Large diffs when many packages update (normal for lockfiles)

### Risks & Mitigations

| Risk | Mitigation |
|------|------------|
| uv project abandonment | Astral is well-funded, Ruff adoption proves track record. Fallback to pip always possible. |
| Breaking changes in uv | Pin uv version in CI, test upgrades in separate branch |
| CI/CD tooling compatibility | Using official `astral-sh/setup-uv` action with caching |
| Developer adoption resistance | Makefile provides familiar interface, legacy mode available |

## Red Team Analysis

### Security Considerations

| Attack Vector | Analysis | Mitigation |
|--------------|----------|------------|
| Lockfile tampering | Attacker modifies uv.lock to inject malicious packages | uv validates package hashes automatically; review lockfile changes in PRs |
| Supply chain attack | Malicious package in dependency tree | uv verifies package integrity via hashes in lockfile |
| Service isolation break | Portal gains database access | Dependency groups enforce separation; CI validates isolation |
| CI/CD cache poisoning | Attacker poisons uv cache | Use `astral-sh/setup-uv` with `cache-dependency-glob: "uv.lock"` |
| Rollback difficulty | Can't return to pip if uv fails | Retained requirements.txt files for 30-day transition period |

## Maintenance

### Regular Tasks

- **Weekly:** Review `uv.lock` changes in PRs for unexpected additions
- **Monthly:** Run `uv lock --upgrade` to update dependencies, test thoroughly
- **Quarterly:** Review uv changelog for breaking changes before upgrading

### Useful Commands

```bash
# Update all dependencies
uv lock --upgrade

# Update specific package
uv lock --upgrade-package django

# Show dependency tree
uv tree

# Show outdated packages
uv pip list --outdated

# Export to requirements.txt (for compatibility)
uv pip compile pyproject.toml -o requirements.txt
```

## Related Decisions

- **ADR-0002:** Strategic Linting Framework (Ruff - same vendor as uv)
- **ADR-0009:** Pragmatic MyPy Strategy (development tools in pyproject.toml)

## References

- [uv Documentation](https://docs.astral.sh/uv/)
- [uv Migration Guide: pip to project](https://docs.astral.sh/uv/guides/migration/pip-to-project/)
- [uv Workspaces](https://docs.astral.sh/uv/concepts/projects/workspaces/)
- [PEP 735: Dependency Groups](https://peps.python.org/pep-0735/)
- [Astral - Company behind uv and Ruff](https://astral.sh/)

---

**Review Schedule:** Quarterly review to assess uv ecosystem evolution and update practices.

**Next Steps:**
1. Generate initial `uv.lock` file
2. Update Docker images to use uv
3. Archive requirements.txt files after 30-day parallel run
