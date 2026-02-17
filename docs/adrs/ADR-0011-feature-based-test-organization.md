# ADR-0011: Feature-Based Test Organization

## Status
Accepted

## Context

The PRAHO Platform has grown to include comprehensive test coverage across multiple Django apps. The `tests/billing/` directory alone contains 22 test files with 548 test methods totaling over 12,000 lines of code. Current test organization presents several challenges:

### Current Problems
1. **Monolithic test files**: `test_billing_views.py` contains 2,039 lines with 20 test classes covering different billing features
2. **Mixed concerns**: Tests for invoices, proformas, payments, and PDFs scattered across files
3. **Navigation difficulty**: Developers struggle to find tests for specific features
4. **Maintenance overhead**: Large files are harder to review and maintain
5. **Parallel development conflicts**: Teams working on different features encounter merge conflicts

### Business Context
PRAHO serves Romanian hosting providers with complex billing requirements:
- Invoice and proforma generation with sequential numbering
- Multi-currency support and VAT compliance
- Payment processing and refund handling
- PDF generation for Romanian business standards
- Webhook integrations with external payment providers

## Decision

We will adopt a **feature-based test organization** using flat file structure with descriptive naming conventions.

### New Test Structure
```
tests/billing/
├── __init__.py
├── test_invoices_models.py      # Invoice model tests
├── test_invoices_views.py       # Invoice CRUD operations
├── test_invoices_services.py    # Invoice business logic
├── test_invoices_pdf.py         # Invoice PDF generation
├── test_proformas_models.py     # Proforma model tests
├── test_proformas_views.py      # Proforma CRUD operations
├── test_proformas_services.py   # Proforma business logic
├── test_proformas_pdf.py        # Proforma PDF generation
├── test_payments_models.py      # Payment model tests
├── test_payments_views.py       # Payment processing views
├── test_payments_services.py    # Payment business logic
├── test_payments_refunds.py     # Refund handling
├── test_sequences_models.py     # Sequential numbering
├── test_sequences_concurrency.py # Race condition handling
├── test_currencies.py           # Currency support
├── test_webhooks.py             # External integrations
└── test_security.py             # Security validations
```

### Why Flat Structure Over Subdirectories
- **Django Standard**: Follows conventional `test_*.py` pattern exactly
- **Simple Discovery**: Django's test runner finds all files automatically
- **IDE Friendly**: All test files visible at same directory level
- **Easier Migration**: Renaming existing files vs. creating new directory structure
- **Import Simplicity**: No nested import complexity

## Rationale

### Business Benefits
1. **Feature Alignment**: Tests organized by business domains (invoices, payments, etc.)
2. **Team Efficiency**: Frontend/backend teams can easily find relevant tests
3. **Romanian Compliance**: Clear separation of VAT, e-Factura, and regulatory tests
4. **Maintainability**: Smaller, focused files easier to review and maintain

### Technical Benefits
1. **Discoverability**: `test_invoices_*` groups all invoice-related tests
2. **Parallel Development**: Reduced merge conflicts when teams work on different features
3. **Test Focus**: Each file has single responsibility (models, views, services, PDFs)
4. **Refactoring Safety**: Moving business logic easier when tests are feature-grouped

### Django Best Practices Alignment
- **Test Discovery**: All files follow `test_*.py` pattern for automatic discovery
- **Naming Convention**: Descriptive names indicate both feature and component
- **File Size**: Target <500 lines per file for maintainability
- **Test Isolation**: Feature boundaries prevent cross-contamination

## Implementation Plan

### Phase 1: Large File Migration
1. Split `test_billing_views.py` (2,039 lines) by feature:
   - Invoice views → `test_invoices_views.py`
   - Proforma views → `test_proformas_views.py`
   - Payment views → `test_payments_views.py`

### Phase 2: Service and Model Tests
2. Group service tests by feature:
   - `test_billing_services_*` → `test_{feature}_services.py`
3. Consolidate model tests:
   - Related models grouped by business domain

### Phase 3: Specialized Tests
4. Move specialized tests:
   - PDF generators → `test_{feature}_pdf.py`
   - Security tests → `test_security.py`
   - Webhook tests → `test_webhooks.py`

### Phase 4: Cleanup
5. Remove redundant "coverage" test files
6. Consolidate duplicate test methods
7. Update test documentation

## Testing Strategy Validation

This structure maintains all existing test functionality while improving organization:
- **Coverage**: No reduction in test coverage
- **CI/CD**: All tests discoverable by Django's test runner
- **Performance**: No impact on test execution speed
- **Romanian Compliance**: Business-critical tests clearly grouped

## Migration Safety

- **Backward Compatible**: Django test discovery unchanged
- **Incremental**: Can migrate files one at a time
- **Rollback Safe**: Original files can be preserved during migration
- **CI Protected**: All tests must pass before merge

## Success Metrics

1. **File Size**: No test file >800 lines
2. **Feature Coverage**: Each business feature has dedicated test files
3. **Developer Velocity**: Reduced time to find and run relevant tests
4. **Maintainability**: Improved PR review times for test changes

## Consequences

### Positive
- **Clear Organization**: Tests grouped by business functionality
- **Easier Navigation**: Developers can quickly locate feature tests
- **Reduced Conflicts**: Teams work on separate files
- **Better Maintainability**: Smaller, focused test files

### Neutral
- **File Count**: More files but better organization
- **Migration Effort**: One-time cost to reorganize existing tests

### Risks Mitigated
- **No Breaking Changes**: Django test discovery unchanged
- **Coverage Preserved**: All existing tests maintained
- **Team Training**: Minimal - follows intuitive feature grouping

## References

- [Django Testing Documentation](https://docs.djangoproject.com/en/5.2/topics/testing/)
- [pytest Organization Best Practices](https://pytest-with-eric.com/pytest-best-practices/pytest-organize-tests/)
- ADR-0002: Strategic Linting Framework (testing quality standards)
- PRAHO Platform Architecture (business domain boundaries)
