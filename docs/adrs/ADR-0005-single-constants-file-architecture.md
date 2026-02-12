# ADR-0005: Single Constants File Architecture for PRAHO Platform

**Status:** Accepted  
**Date:** 2025-08-26  
**Authors:** Development Team  
**Supersedes:** N/A  

## Context

PRAHO Platform required a decision on constant management strategy to address magic values and improve maintainability. The platform has Romanian-specific business rules and cross-cutting constants used across multiple Django apps, creating a need for consistent, centralized constant management.

Key considerations:
1. **Romanian Business Compliance**: VAT rates, CUI validation rules, and legal requirements change via government regulation
2. **Cross-App Usage**: Constants like VAT rates are used in `billing/`, `orders/`, `customers/`, and `audit/`
3. **AI/LLM Code Readability**: Centralized business rules improve code comprehension for AI tools
4. **Maintenance Efficiency**: Single point of change for business rule updates
5. **Architecture Consistency**: Aligns with existing `apps/common/` pattern for shared utilities

## Decision

We decided to implement a **single centralized constants file** at `apps/common/constants.py` for all cross-cutting business constants, while allowing app-specific implementation details to remain local.

### Architecture Pattern: Single Constants File

**Location:** `apps/common/constants.py`

**Rationale:**
- ✅ **Extends Proven Pattern**: Consistent with existing `apps/common/` utilities (types.py, validators.py, utils.py)
- ✅ **O(1) Maintenance**: Romanian VAT rate changes require single-file update across 4+ apps
- ✅ **Strategic Seams Alignment**: Supports ADR-0001 enhanced architecture with clear separation of concerns
- ✅ **Zero Circular Import Risk**: `common/` app has no dependencies on other apps
- ✅ **Business Rules Documentation**: Acts as self-documenting source of truth for Romanian compliance

### Categorization Strategy

```python
# ===============================================================================
# ROMANIAN COMPLIANCE 🇷🇴
# ===============================================================================
# NOTE: VAT rates are NOT constants — they have temporal validity and are
# managed via TaxService (ADR-0015). Use TaxService.get_vat_rate() instead.
CUI_MIN_LENGTH = 2                          # Used in: customers, billing
CUI_MAX_LENGTH = 10                         # Used in: customers, billing
PAYMENT_GRACE_PERIOD_DAYS = 5               # Used in: billing, tickets

# ===============================================================================
# SERVICE LIMITS ⚡
# ===============================================================================
MAX_DOMAINS_PER_PACKAGE = 100              # Used in: provisioning, domains
DEFAULT_PAGE_SIZE = 25                      # Used in: ALL list views (query budgets)
API_RATE_LIMIT_PER_HOUR = 1000             # Used in: integrations, api

# ===============================================================================
# SUPPORT SLA 🎯
# ===============================================================================
CRITICAL_TICKET_RESPONSE_HOURS = 1         # Used in: tickets, audit
STANDARD_TICKET_RESPONSE_HOURS = 24        # Used in: tickets, notifications
```

### What Stays in Apps vs. Common

**Centralized in `common/constants.py`:**
- Romanian legal requirements (VAT, CUI validation)
- Business rules that span multiple apps
- Service limits affecting user experience
- SLA commitments in support tickets
- Pagination defaults (query budget compliance)

**Remains in App-Specific Files:**
- Implementation timeouts (webhook retry delays)
- Internal technical limits (buffer sizes)
- App-specific error codes
- Local feature flags

### Rejected Alternatives

**❌ Distributed Constants (per-app files):**
- **Problem**: Romanian VAT change would require updates across 4+ apps
- **Risk**: Inconsistency when business rules drift between apps
- **Maintenance**: O(N) complexity for legal compliance updates

**❌ Database Configuration:**
- **Problem**: Adds query overhead for frequently accessed values
- **Risk**: Database dependency for basic business logic
- **Complexity**: Requires migration strategy for constant updates
- **Scope note (2026-02-12)**: This rejection applies to immutable constants only.
  Dynamic/regulatory values with runtime edits or temporal validity are governed by ADR-0015 (Configuration Resolution Order).

**❌ Environment Variables:**
- **Problem**: Poor discoverability and documentation
- **Risk**: Production deployment complexity
- **Type Safety**: Loses Python type system benefits

## Implementation Strategy

### Phase 1: File Creation & Structure
```bash
# Create centralized constants file
touch apps/common/constants.py

# Import pattern for apps
from apps.common.constants import ROMANIAN_VAT_RATE
```

### Phase 2: Automated Migration
```bash
# Use automated tool to find and replace magic values
python3 fix_plr2004_magic_values.py

# Verify all tests pass
make test
make lint
```

### Phase 3: Documentation Updates
- Update ARCHITECTURE.md with constants pattern
- Document business rule change procedures
- Create quarterly review process for Romanian compliance

## Consequences

### Positive Outcomes

- ✅ **O(1) Business Rule Updates**: Romanian VAT rate change requires single file edit
- ✅ **Self-Documenting Business Logic**: All Romanian compliance rules in one searchable location
- ✅ **AI/LLM Friendly**: Centralized constants improve code comprehension for AI tools
- ✅ **Consistent Architecture**: Extends proven `apps/common/` pattern successfully
- ✅ **Query Budget Alignment**: Centralized `DEFAULT_PAGE_SIZE` supports query optimization goals
- ✅ **Legal Compliance**: Single point of truth for Romanian business regulations

### Maintenance Benefits

**Romanian Government VAT Change Scenario:**
```python
# VAT rates are now managed via TaxService + TaxRule model (ADR-0015).
# Rate changes are handled by creating a new TaxRule with valid_from date.
# No code changes required — just a database record.
# See: apps/billing/management/commands/setup_tax_rules.py
```

**Developer Workflow:**
```bash
# Quick business rule lookup
grep -n "VAT\|CUI\|SLA" apps/common/constants.py

# Verify usage across codebase
grep -r "ROMANIAN_VAT_RATE" apps/
```

### Trade-offs Accepted

- ⚖️ **Single File Growth**: Constants file may reach 300-500 lines (manageable size)
- ⚖️ **Import Dependency**: All apps import from `common/` (already established pattern)
- ⚖️ **Merge Conflicts**: High-touch file may have conflicts (mitigated by clear categories)

### Risks & Mitigations

**Risk**: Constants file becomes too large
**Mitigation**: Clear categorization with section headers, regular review process

**Risk**: Inappropriate constants added to common
**Mitigation**: Code review guidelines distinguishing business rules from implementation details

**Risk**: Breaking changes without notice
**Mitigation**: Semantic versioning and changelog updates for business rule changes

## Success Metrics

### Short-term (1 month)
- Zero magic number violations in linting (`PLR2004`)
- All Romanian compliance constants centralized
- Documentation updated with constants usage patterns

### Medium-term (6 months)  
- Developer onboarding improved (single source for business rules)
- Zero incidents from inconsistent VAT calculations
- Positive feedback from Romanian compliance audits

### Long-term (1 year)
- Successful handling of at least one Romanian regulation change
- Constants pattern adopted for all new business rules
- Improved AI code analysis accuracy

## Related Decisions

- **ADR-0001**: Django Architecture Decision (provides strategic seams foundation)
- **ADR-0002**: Strategic Linting Framework (PLR2004 magic number detection)
- **Future ADR**: Romanian e-Factura Integration (will reference VAT constants)

## References

- [PRAHO Platform Architecture](../ARCHITECTURE.md)
- [Romanian Business Validators](../../apps/common/validators.py)
- [Django Apps Common Pattern](../../apps/common/)
- [PLR2004 Magic Values Documentation](https://docs.astral.sh/ruff/rules/magic-value-comparison/)

---

**Review Schedule:** Quarterly review recommended to ensure business rules remain current with Romanian legal requirements.

**Next Steps:** 
1. Implement automated migration of magic values
2. Update development guidelines for constant usage
3. Establish change management process for Romanian compliance updates
