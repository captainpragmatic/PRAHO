# Architecture Documentation Changelog

## v1.2.0 - 2026-02-21

### Added
- **App dependency graph** (`app-dependencies.mmd`) - Four-tier diagram showing inter-app import relationships across 14 business apps (hub apps omitted for clarity)
- **Entity relationship diagram** (`entity-relationships.mmd`) - ER diagram with ~20 core entities, key fields, cardinality, and domain grouping

### Changed
- Updated README.md with sections 4 (App Dependencies) and 5 (Entity Relationships)

---

## v1.1.0 - 2026-02-21

### Added
- **Mermaid diagrams** for visual architecture documentation
  - `system-overview.mmd` / `.png` - High-level service boundaries and integrations (125 KB)
  - `data-flow.mmd` / `.png` - Sequence diagram for Portal ↔ Platform communication (181 KB)
  - `deployment.mmd` / `.png` - Docker network topology and security isolation (67 KB)
- **Pre-rendered PNG images** for each diagram (via mermaid.ink API)
- **Architecture diagrams README** with viewing instructions and maintenance guide

### Changed
- **Corrected app counts** across all documentation
  - Platform: 21 apps → **17 apps** (accurate count)
  - Portal: 13 apps → **9 apps** (accurate count)
- **Clarified Portal database usage**
  - Previous: "NO database access" (misleading)
  - Updated: "SQLite for session storage only - NO business data access"
  - Added explicit security constraints explaining the distinction
- **Updated version and date** in `ARCHITECTURE.md`
  - Version: 1.0.0 → 1.1.0
  - Last Updated: September 5, 2025 → February 21, 2026
- **Added diagram references** to README.md documentation section

### Fixed
- Inaccurate architecture descriptions that overstated Portal isolation
- Missing visual documentation for onboarding developers
- Outdated metadata in ARCHITECTURE.md

---

## Changes by File

### Documentation Updates

| File | Change | Reason |
|------|--------|--------|
| `docs/ARCHITECTURE.md` | Version bump, app counts, database clarification | Accuracy & currency |
| `README.md` | App counts, diagram references | Developer onboarding |
| `CLAUDE.md` | App counts, service descriptions | AI assistant context |
| `docs/architecture/system-overview.mmd` / `.png` | New diagram + image | Visual documentation |
| `docs/architecture/data-flow.mmd` / `.png` | New diagram + image | Visual documentation |
| `docs/architecture/deployment.mmd` / `.png` | New diagram + image | Visual documentation |
| `docs/architecture/README.md` | New guide | Diagram usage instructions |
| `docs/architecture/CHANGELOG.md` | This file | Track architecture changes |

---

## Migration Notes

**No code changes required** - this is a documentation-only update.

Developers should:
1. Review the new Mermaid diagrams for system understanding
2. Note the corrected app counts when discussing architecture
3. Use accurate Portal database description (session-only SQLite, not "no database")

---

## Verification

To verify accuracy:

```bash
# Count Platform apps (should be 17)
ls services/platform/apps/ | grep -v "^__" | wc -l

# Count Portal apps (should be 9)
ls services/portal/apps/ | grep -v "^__" | wc -l

# Verify Portal database config
grep -A5 "DATABASES" services/portal/config/settings/base.py

# View diagrams
open docs/architecture/system-overview.mmd  # or use mermaid.live
```

Expected output:
- Platform apps: 17
- Portal apps: 9
- Portal database: SQLite3 (default), used for sessions only
