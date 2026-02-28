# ADR-0012: Internal App Organization with Feature-Based File Structure

## Status
**ACCEPTED** - 2025-01-02

## Context
PRAHO Platform uses Django apps to represent bounded contexts (domains like `billing`, `customers`, `users`), but individual apps have grown large with monolithic `views.py`, `models.py`, and `services.py` files. The `billing` app, for example, contains:

- **views.py**: 1,600+ lines mixing invoice, proforma, and payment views
- **models.py**: 1,250+ lines with 15+ different model classes
- **services.py**: 800+ lines with mixed business logic

This structure makes code navigation difficult, increases merge conflicts, and violates the Single Responsibility Principle at the file level.

## Decision
We will adopt **feature-based file organization within Django apps** using flat structure (no subfolders) to improve maintainability while preserving Django conventions.

### File Naming Convention
```
apps/{app_name}/
├── {feature}_views.py      # Views for specific feature
├── {feature}_models.py     # Models for specific feature domain
├── {feature}_services.py   # Business logic for specific feature
├── {domain}_models.py      # Related models grouped by domain
└── models.py               # Imports all feature models (Django requirement)
```

### Implementation Examples

#### Billing App Structure
```python
apps/billing/
├── invoice_views.py        # Invoice-specific views
├── proforma_views.py       # Proforma-specific views
├── payment_views.py        # Payment processing views
├── billing_views.py        # Main billing list, reports
├── invoice_models.py       # Invoice, InvoiceLine models
├── proforma_models.py      # ProformaInvoice, ProformaLine models
├── payment_models.py       # Payment, PaymentRefund models
├── currency_models.py      # Currency, FXRate models
├── sequence_models.py      # InvoiceSequence, ProformaSequence
├── tax_models.py          # TaxRule, VATValidation models
├── invoice_service.py      # Invoice business logic
├── proforma_service.py     # Proforma business logic
├── payment_service.py      # Payment business logic
└── models.py              # Import all feature models for Django
```

#### Customers App Structure
```python
apps/customers/
├── customer_views.py        # Customer CRUD, search views
├── profile_views.py         # Tax profile, billing profile, addresses, notes
├── membership_views.py      # Customer-user relationship views
├── customer_models.py       # Customer, SoftDeleteModel infrastructure
├── profile_models.py        # CustomerTaxProfile, CustomerBillingProfile, etc.
├── customer_service.py      # Customer business logic, analytics, credit scoring
├── profile_service.py       # Profile management business logic
├── membership_service.py    # User assignment and access control logic
└── models.py               # Import all feature models for Django
```

#### Users App Structure
```python
apps/users/
├── auth_views.py           # Login, registration, password reset views
├── mfa_views.py            # Two-factor authentication views
├── profile_views.py        # User profile, security settings views
├── user_models.py          # User, UserManager core models
├── membership_models.py    # CustomerMembership junction table
├── profile_models.py       # UserProfile, UserLoginLog models
├── auth_service.py         # Authentication, password reset business logic
├── mfa_service.py          # MFA setup, verification business logic
├── profile_service.py      # Profile management business logic
├── membership_service.py   # Customer-user relationship management
└── models.py              # Import all feature models for Django
```

#### Provisioning App Structure
```python
apps/provisioning/
├── service_models.py       # ServicePlan, Server, Service, ProvisioningTask
├── relationship_models.py  # ServiceRelationship, ServiceDomain, ServiceGroup
├── provisioning_service.py # Service activation, management business logic
└── models.py              # Import all feature models for Django
```

#### Service Layer Separation
Business logic is extracted from models and views into dedicated service classes:

```python
# invoice_service.py
class InvoiceService:
    @staticmethod
    @transaction.atomic
    def create_invoice_from_proforma(proforma: ProformaInvoice, user: User) -> Result[Invoice, str]:
        # Business logic here

    @staticmethod
    def validate_invoice_access(user: User, invoice: Invoice) -> bool:
        # Access validation logic
```

### Architectural Benefits

1. **Single Responsibility**: Each file has a clear, focused purpose
2. **Improved Navigation**: Developers can quickly locate feature-specific code
3. **Reduced Merge Conflicts**: Multiple developers can work on different features simultaneously
4. **Better Testing**: Feature-specific tests mirror file structure
5. **Service Layer**: Business logic separated from models/views for better testability
6. **Maintainable Imports**: Clear dependency relationships between files

### Django Compatibility
- **models.py**: Maintained as aggregator importing all feature models (Django requirement for migrations)
- **urls.py**: Imports from feature-specific view modules
- **admin.py**: Imports from feature-specific model modules
- **Migration system**: Continues to work normally through main models.py

### 🚨 **Critical: No Database Migrations Required**

**File reorganization does NOT require database migrations** because:

1. **Model Definitions Unchanged**: Classes remain identical - only file location changes
2. **Django Import Resolution**: Django finds models through main `models.py` file
3. **No Schema Changes**: Database table structure stays exactly the same
4. **Model Metadata Preserved**: `app_label`, `db_table`, field definitions all identical

```python
# ⚡ VERIFICATION: File reorganization is migration-safe
python manage.py makemigrations --dry-run
# Expected output: "No changes detected"

# This confirms Django sees models as unchanged after reorganization
```

**What Django Cares About vs. What It Ignores:**
```python
# ✅ Django CARES about (must remain unchanged):
# - Model class definitions and field definitions
# - Model metadata (app_label, db_table, etc.)
# - App location (still in same Django app)

# ❌ Django IGNORES (safe to change):
# - Which file contains the model class
# - Import paths within the app
# - File organization structure
```

**Views and Models Follow Same Re-Export Safety Pattern:**
```python
# Both views.py and models.py use identical safety approach:
# 1. Create feature-specific files (invoice_views.py, invoice_models.py)
# 2. Original files become re-export hubs for backward compatibility
# 3. All existing imports continue working unchanged
# 4. Django systems (migrations, admin, URLs) work normally
```

## Alternatives Considered

### Rejected: Subfolder Organization
```python
apps/billing/
├── views/
│   ├── invoice_views.py
│   └── proforma_views.py
└── models/
    ├── invoice_models.py
    └── proforma_models.py
```

**Rejection reasons:**
- Breaks Django convention expectations
- Complicates imports with nested paths
- Creates unnecessary directory depth
- Makes file discovery slower

### Rejected: Monolithic Files
Keeping large `views.py`, `models.py` files.

**Rejection reasons:**
- Violates Single Responsibility Principle
- Difficult code navigation and maintenance
- Increases merge conflicts
- Mixed concerns in single files

### Rejected: Microservices Split
Breaking apps into separate Django projects.

**Rejection reasons:**
- Over-engineering for current scale
- Breaks Django's batteries-included philosophy
- Increases deployment complexity
- Not aligned with monolith architecture

## Implementation Guidelines

### File Organization Rules
1. **Feature-based grouping**: Group related functionality (invoice, proforma, payment)
2. **Flat structure**: No subfolders within apps to maintain Django simplicity
3. **Clear naming**: Use `{feature}_{component}.py` pattern
4. **Service extraction**: Move business logic from models/views to services
5. **Import aggregation**: Main `models.py` imports all feature models

### Service Layer Principles
1. **Static methods**: Use static methods for stateless operations
2. **Result types**: Use `Result[T, str]` pattern for error handling
3. **Transaction boundaries**: Use `@transaction.atomic` for consistency
4. **Access control**: Include validation methods in services
5. **Audit logging**: Include security event logging

### Testing Alignment
Test structure mirrors app organization:
```python
tests/billing/
├── test_invoice_views.py
├── test_proforma_views.py
├── test_payment_views.py
├── test_invoice_models.py
├── test_payment_models.py
└── test_invoice_service.py
```

## Migration Safety Strategy

### Zero-Breakage Migration Approach
The key to safe migration is maintaining **100% backward compatibility** during the transition using re-export patterns. This allows gradual migration without breaking existing imports or tests.

### Re-Export Pattern for Safe Migration
```python
# ===============================================================================
# BEFORE MIGRATION: Monolithic files
# ===============================================================================
# apps/billing/services.py (1000+ lines)
class InvoiceService:
    def create_invoice(self): pass

class PaymentService:
    def process_payment(self): pass

# apps/billing/views.py (1600+ lines)
def invoice_create(request): pass
def payment_process(request): pass

# ===============================================================================
# DURING MIGRATION: Feature files + Re-export hub
# ===============================================================================

# apps/billing/invoice_service.py (NEW)
class InvoiceService:
    def create_invoice(self): pass

# apps/billing/payment_service.py (NEW)
class PaymentService:
    def process_payment(self): pass

# apps/billing/services.py (MODIFIED - Re-export hub)
"""
Backward compatibility layer for billing services.
All existing imports continue to work unchanged.
"""
from .invoice_service import InvoiceService
from .payment_service import PaymentService
from .proforma_service import ProformaService

# Re-export for backward compatibility
__all__ = [
    'InvoiceService',
    'PaymentService',
    'ProformaService',
]

# ===============================================================================
# MIGRATION VERIFICATION SCRIPT
# ===============================================================================
# scripts/verify_migration_safety.py
import importlib

def verify_all_imports_work():
    """Verify both old and new import paths work"""
    test_cases = [
        # Old imports (via re-export) - Must continue working
        ('apps.billing.services', 'InvoiceService'),
        ('apps.billing.views', 'invoice_create'),
        ('apps.billing.models', 'Invoice'),

        # New imports (direct) - Should work immediately
        ('apps.billing.invoice_service', 'InvoiceService'),
        ('apps.billing.invoice_views', 'invoice_create'),
        ('apps.billing.invoice_models', 'Invoice'),
    ]

    for module_path, item_name in test_cases:
        try:
            module = importlib.import_module(module_path)
            getattr(module, item_name)
            print(f"✅ {module_path}.{item_name}")
        except Exception as e:
            print(f"❌ {module_path}.{item_name}: {e}")
            return False
    return True
```

### Cross-App Import Analysis
Before migration, identify all cross-app dependencies:

```bash
# Find all imports that will be affected
grep -r "from apps\.billing\.services import" apps/ tests/
grep -r "from apps\.billing\.views import" apps/ tests/
grep -r "from apps\.billing\.models import" apps/ tests/

# Result shows files that need gradual updating:
# apps/customers/views.py: from apps.billing.services import InvoiceService
# apps/provisioning/services.py: from apps.billing.services import PaymentService
# tests/billing/test_invoices.py: from apps.billing.services import InvoiceService
# tests/customers/test_billing.py: from apps.billing.services import InvoiceService
```

## Implementation Phases

### Phase 1: Services Migration (Week 1-2)
**Goal**: Split monolithic `services.py` files without breaking imports

#### Sub-Phase 1A: Create Feature Service Files
```python
# For each app (billing, customers, users, etc.)
# 1. Create feature-specific service files
apps/billing/
├── invoice_service.py      # Extract InvoiceService class
├── payment_service.py      # Extract PaymentService class
├── proforma_service.py     # Extract ProformaService class
└── services.py            # Becomes re-export hub

# 2. Move business logic to feature files
# 3. Set up re-export in original services.py
# 4. Run verification script
# 5. All tests must pass unchanged
```

#### Sub-Phase 1B: Services Verification & Documentation
```python
# scripts/verify_services_migration.py
def verify_services_migration(app_name):
    """Verify service migration for specific app"""

    # Test old imports still work
    old_imports = [
        f'apps.{app_name}.services.InvoiceService',
        f'apps.{app_name}.services.PaymentService',
    ]

    # Test new imports work
    new_imports = [
        f'apps.{app_name}.invoice_service.InvoiceService',
        f'apps.{app_name}.payment_service.PaymentService',
    ]

    return verify_imports(old_imports + new_imports)

# Run for each app
for app in ['billing', 'customers', 'users', 'provisioning']:
    assert verify_services_migration(app), f"{app} services migration failed"
```

### Phase 2: Models Migration (Week 3-4)
**Goal**: Split monolithic `models.py` files while maintaining Django compatibility

#### Django Models Special Considerations
```python
# ===============================================================================
# MODELS MIGRATION PATTERN
# ===============================================================================

# apps/billing/invoice_models.py (NEW)
from django.db import models

class Invoice(models.Model):
    number = models.CharField(max_length=50)
    # ... field definitions

class InvoiceLine(models.Model):
    invoice = models.ForeignKey(Invoice, on_delete=models.CASCADE)
    # ... field definitions

# apps/billing/payment_models.py (NEW)
class Payment(models.Model):
    invoice = models.ForeignKey('invoice_models.Invoice', on_delete=models.CASCADE)
    # ... field definitions

# apps/billing/models.py (MODIFIED - Django requirement)
"""
Django requires models.py for migrations and admin.
This file imports all feature models for Django compatibility.
"""

# Import all models from feature files
from .invoice_models import Invoice, InvoiceLine
from .payment_models import Payment, PaymentAllocation
from .proforma_models import ProformaInvoice, ProformaLine
from .currency_models import Currency, FXRate
from .sequence_models import InvoiceSequence, ProformaSequence

# Django admin registration
from django.contrib import admin
from .invoice_models import Invoice
from .payment_models import Payment

admin.site.register(Invoice)
admin.site.register(Payment)

# Critical: __all__ for external imports
__all__ = [
    # Invoice models
    'Invoice', 'InvoiceLine',
    # Payment models
    'Payment', 'PaymentAllocation',
    # Proforma models
    'ProformaInvoice', 'ProformaLine',
    # Currency models
    'Currency', 'FXRate',
    # Sequence models
    'InvoiceSequence', 'ProformaSequence',
]
```

#### Models Migration Verification
```python
# scripts/verify_models_migration.py
def verify_models_migration(app_name):
    """Verify Django can find all models after migration"""

    # Test Django can import models for migrations
    from django.apps import apps
    app_config = apps.get_app_config(app_name)
    models = app_config.get_models()

    print(f"✅ Django found {len(models)} models in {app_name}")

    # Test old imports still work
    old_import = f'apps.{app_name}.models.Invoice'
    new_import = f'apps.{app_name}.invoice_models.Invoice'

    return verify_imports([old_import, new_import])

# Test migration system still works
def test_migration_system():
    """Verify Django migrations work after model split"""
    import subprocess
    result = subprocess.run(['python', 'manage.py', 'makemigrations', '--dry-run'],
                          capture_output=True, text=True)
    assert 'No changes detected' in result.stdout or 'Migrations for' in result.stdout
    print("✅ Migration system works after model split")
```

### Phase 3: Views Migration (Week 5-6)
**Goal**: Split monolithic `views.py` files while maintaining URL routing

#### Views Migration Pattern
```python
# ===============================================================================
# VIEWS MIGRATION PATTERN
# ===============================================================================

# apps/billing/invoice_views.py (NEW)
from django.shortcuts import render
from .invoice_service import InvoiceService

def invoice_create(request):
    # Move invoice-specific views here
    pass

def invoice_detail(request, pk):
    pass

# apps/billing/payment_views.py (NEW)
from .payment_service import PaymentService

def payment_process(request):
    # Move payment-specific views here
    pass

# apps/billing/views.py (MODIFIED - Re-export hub)
"""
Backward compatibility for view imports.
URL patterns can continue importing from this file.
"""

# Import from feature view files
from .invoice_views import invoice_create, invoice_detail, invoice_list
from .payment_views import payment_process, payment_detail
from .proforma_views import proforma_create, proforma_detail

# Re-export for URL patterns and external imports
__all__ = [
    # Invoice views
    'invoice_create', 'invoice_detail', 'invoice_list',
    # Payment views
    'payment_process', 'payment_detail',
    # Proforma views
    'proforma_create', 'proforma_detail',
]
```

#### URL Pattern Updates
```python
# apps/billing/urls.py (Updated gradually)
from django.urls import path

# Phase 1: Import from main views.py (works via re-export)
from .views import invoice_create, payment_process

# Phase 2: Gradually migrate to direct imports (optional)
from .invoice_views import invoice_create
from .payment_views import payment_process

urlpatterns = [
    path('invoices/create/', invoice_create, name='invoice_create'),
    path('payments/process/', payment_process, name='payment_process'),
]
```

### Phase 4: Administrative Files Migration (Week 7)
**Goal**: Update admin.py, forms.py, and other supporting files

#### Admin Registration Pattern
```python
# apps/billing/admin.py (Updated)
from django.contrib import admin

# Import from feature model files
from .invoice_models import Invoice, InvoiceLine
from .payment_models import Payment
from .proforma_models import ProformaInvoice

# Register models
@admin.register(Invoice)
class InvoiceAdmin(admin.ModelAdmin):
    list_display = ['number', 'customer', 'total_amount']

@admin.register(Payment)
class PaymentAdmin(admin.ModelAdmin):
    list_display = ['invoice', 'amount', 'payment_date']
```

### Phase 5: Cross-App Import Updates (Week 8-10)
**Goal**: Gradually update imports across apps for better dependency clarity

#### Gradual Import Updates
```python
# scripts/update_imports_gradually.py
import re
from pathlib import Path

def update_imports_for_app(app_name, feature_mappings, dry_run=True):
    """Update imports from monolithic to feature-based"""

    # Example feature mappings for billing app
    feature_mappings = {
        'InvoiceService': 'invoice_service',
        'PaymentService': 'payment_service',
        'Invoice': 'invoice_models',
        'Payment': 'payment_models',
        'invoice_create': 'invoice_views',
        'payment_process': 'payment_views',
    }

    files_to_update = []

    # Find files importing from this app
    for py_file in Path('.').rglob('*.py'):
        if should_skip_file(py_file):
            continue

        content = py_file.read_text()

        # Look for imports from this app
        if f'from apps.{app_name}.' in content:
            files_to_update.append(py_file)

    # Update imports file by file
    for file_path in files_to_update:
        update_file_imports(file_path, app_name, feature_mappings, dry_run)

def should_skip_file(file_path):
    """Skip certain files during import updates"""
    skip_patterns = ['.venv', '__pycache__', '.git', 'migrations']
    return any(pattern in str(file_path) for pattern in skip_patterns)

# Run gradually - one app at a time
update_imports_for_app('billing', billing_mappings, dry_run=True)
```

### Phase 6: Testing & Validation (Ongoing)
**Goal**: Ensure all changes maintain functionality and improve maintainability

#### Comprehensive Test Suite
```python
# scripts/validate_migration.py
def run_full_migration_validation():
    """Run comprehensive validation after each phase"""

    checks = [
        verify_all_imports_work,
        test_django_migrations,
        test_admin_interface,
        test_url_routing,
        run_test_suite,
        check_code_organization,
    ]

    for check in checks:
        try:
            check()
            print(f"✅ {check.__name__}")
        except Exception as e:
            print(f"❌ {check.__name__}: {e}")
            return False

    return True

def test_django_migrations():
    """Verify Django migrations work"""
    import subprocess
    result = subprocess.run(['python', 'manage.py', 'check'],
                          capture_output=True, text=True)
    assert result.returncode == 0, f"Django check failed: {result.stderr}"

def test_admin_interface():
    """Verify admin interface loads"""
    from django.contrib import admin
    from django.apps import apps

    for app_config in apps.get_app_configs():
        models = app_config.get_models()
        for model in models:
            if admin.site.is_registered(model):
                print(f"✅ {model.__name__} registered in admin")

def run_test_suite():
    """Verify all tests pass"""
    import subprocess
    result = subprocess.run(['python', 'manage.py', 'test'],
                          capture_output=True, text=True)
    assert result.returncode == 0, f"Tests failed: {result.stderr}"
```

## Implementation Status

### Phase 1: Services Migration ✅ COMPLETED
- ✅ **Billing App**: Created `invoice_service.py`, `payment_service.py`, `proforma_service.py`
- ✅ **Customers App**: Created `customer_service.py`, `profile_service.py`, `membership_service.py`
- ✅ **Users App**: Created `auth_service.py`, `mfa_service.py`, `profile_service.py`
- ✅ **Provisioning App**: Created `provisioning_service.py`
- ✅ **Re-export Pattern**: All apps maintain backward compatibility via `services.py`
- ✅ **Verification**: All existing imports continue working unchanged

### Phase 2: Models Migration ✅ COMPLETED
- ✅ **Billing App**: Split into `invoice_models.py`, `payment_models.py`, `currency_models.py`, `sequence_models.py`
- ✅ **Customers App**: Split into `customer_models.py`, `profile_models.py`
- ✅ **Users App**: Split into `user_models.py`, `profile_models.py`, `membership_models.py`
- ✅ **Provisioning App**: Split into `service_models.py`, `relationship_models.py`
- ✅ **Django Compatibility**: Main `models.py` imports all feature models for migrations
- ✅ **Migration System**: Verified Django migrations work correctly

### Phase 3: Views Migration ✅ COMPLETED
- ✅ **Billing App**: Split into `invoice_views.py`, `payment_views.py`, `proforma_views.py`, `billing_views.py`
- ✅ **Customers App**: Split into `customer_views.py`, `profile_views.py`, `membership_views.py`
- ✅ **Users App**: Split into `auth_views.py`, `mfa_views.py`, `profile_views.py`
- ✅ **URL Patterns**: Updated to import from feature view files
- ✅ **Backward Compatibility**: Main `views.py` re-exports for external imports

### Phase 4: Administrative Files ✅ COMPLETED
- ✅ **Admin Registration**: Updated `admin.py` files to import from feature models
- ✅ **Forms**: Updated form imports to use feature-specific models
- ✅ **URL Patterns**: Verified all URL routing works with new structure
- ✅ **Management Commands**: Updated to import from feature files

### Phase 5: Cross-App Import Updates 🔄 IN PROGRESS
- ✅ **Import Analysis**: Identified all cross-app dependencies
- ✅ **Gradual Updates**: 60% of imports updated to use feature-specific files
- 🔄 **Remaining Work**: 40% of imports still use re-export pattern (acceptable)
- ✅ **Testing**: All functionality verified during gradual updates

### Phase 6: Testing & Validation ✅ COMPLETED
- ✅ **Import Verification**: All import paths tested and working
- ✅ **Django System Checks**: No errors or warnings
- ✅ **Test Suite**: All tests pass with new structure
- ✅ **Admin Interface**: All models accessible and functional
- ✅ **Migration System**: Migrations work correctly
- ✅ **Performance**: No degradation in application performance

## Automation Scripts

### Migration Automation Tools
To ensure safe and consistent migration, several automation scripts have been developed:

#### 1. Import Discovery and Analysis
```bash
# scripts/analyze_imports.py
python scripts/analyze_imports.py --app billing --type services
# Output: Lists all files importing from billing.services with line numbers

python scripts/analyze_imports.py --app customers --type models
# Output: Cross-app dependencies on customer models

python scripts/analyze_imports.py --all-apps --generate-report
# Output: Comprehensive import dependency report
```

#### 2. Migration Safety Verification
```bash
# scripts/verify_migration_safety.py
python scripts/verify_migration_safety.py --phase services --app billing
# Verifies: Both old and new imports work correctly

python scripts/verify_migration_safety.py --phase models --app customers
# Verifies: Django migrations work, admin interface loads

python scripts/verify_migration_safety.py --all-phases --all-apps
# Comprehensive verification of entire migration
```

#### 3. Automated Import Updates
```bash
# scripts/update_imports.py
python scripts/update_imports.py --app billing --feature invoice --dry-run
# Shows what imports would be updated (safe preview)

python scripts/update_imports.py --app billing --feature invoice --execute
# Actually updates imports from services.py to invoice_service.py

python scripts/update_imports.py --app billing --all-features --batch-size 5
# Updates imports in small batches for safer deployment
```

#### 4. Rollback and Recovery
```bash
# scripts/rollback_migration.py
python scripts/rollback_migration.py --app billing --phase services
# Reverts service migration for billing app

python scripts/rollback_migration.py --app billing --phase models --backup-id 20241201_143022
# Restores models from specific backup point

# Automatic backup before each migration phase
python scripts/backup_before_migration.py --app billing --phase views
# Creates timestamped backup of current state
```

### Continuous Integration Integration
```yaml
# .github/workflows/migration-safety.yml
name: Migration Safety Checks

on: [push, pull_request]

jobs:
  verify-imports:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'

      - name: Install dependencies
        run: uv sync --all-groups

      - name: Verify all imports work
        run: python scripts/verify_migration_safety.py --all-phases --all-apps

      - name: Test Django system checks
        run: python manage.py check --deploy

      - name: Verify migrations
        run: python manage.py makemigrations --check --dry-run

      - name: Run test suite
        run: python manage.py test
```

## Risk Mitigation Strategies

### Import Breakage Prevention
1. **Re-export Pattern**: Original files become import hubs during transition
2. **Gradual Migration**: Update imports file-by-file, not all at once
3. **Verification Scripts**: Automated testing of both old and new import paths
4. **Rollback Capability**: Ability to revert changes if issues arise
5. **CI/CD Integration**: Automated verification in deployment pipeline

### Django System Compatibility
1. **Model Aggregation**: Main `models.py` imports all feature models for Django
2. **Migration Testing**: Verify `makemigrations` and `migrate` work correctly
3. **Admin Compatibility**: Ensure admin interface finds all models
4. **App Registry**: Verify Django app discovery works with new structure

### Development Workflow Protection
1. **Feature Branches**: All migration work done in feature branches
2. **Peer Review**: Minimum 2 reviewers for migration PRs
3. **Staging Deployment**: Test migration on staging before production
4. **Monitoring**: Track import errors and performance after migration
5. **Documentation**: Clear guides for developers on new structure

### Testing Safety Net
1. **Test Migration**: Update test imports gradually with code imports
2. **Coverage Verification**: Ensure no test coverage lost during migration
3. **Performance Testing**: Verify no performance degradation
4. **Integration Testing**: Test cross-app functionality after migration

## Emergency Procedures

### If Imports Break in Production
```python
# Emergency rollback procedure
# 1. Identify broken imports from logs
# 2. Restore re-export in affected files
# 3. Deploy hotfix

# apps/billing/services.py (Emergency re-export restoration)
from .invoice_service import InvoiceService
from .payment_service import PaymentService

# Add any missing re-exports found in logs
__all__ = ['InvoiceService', 'PaymentService', 'any_missing_items']
```

### If Django Migrations Fail
```bash
# 1. Check what models Django can't find
python manage.py check --deploy

# 2. Verify models.py imports all feature models
python -c "from apps.billing.models import *; print('Models imported successfully')"

# 3. Restore missing imports in main models.py
# 4. Re-run migrations
python manage.py makemigrations
python manage.py migrate
```

### If Tests Break
```bash
# 1. Identify broken test imports
python manage.py test --verbosity=2 2>&1 | grep ImportError

# 2. Update test imports or restore re-exports
# 3. Verify test coverage maintained
python manage.py test --with-coverage

# 4. Check for missing test files in new structure
find tests/ -name "*.py" | wc -l  # Should match pre-migration count
```

## Success Metrics and Monitoring

### Migration Success Criteria
- ✅ Zero ImportError exceptions in production logs
- ✅ All Django system checks pass (`python manage.py check --deploy`)
- ✅ All tests pass with new structure
- ✅ No performance degradation (response times, memory usage)
- ✅ Admin interface fully functional
- ✅ All migrations apply successfully
- ✅ Developer survey shows improved code navigation

### Ongoing Monitoring
```python
# monitoring/import_health_check.py
def monitor_import_health():
    """Monitor for import-related issues in production"""

    # Check for ImportError in logs
    import_errors = check_logs_for_import_errors()
    if import_errors:
        alert_development_team(import_errors)

    # Verify critical imports work
    critical_imports = [
        'apps.billing.services.InvoiceService',
        'apps.billing.models.Invoice',
        'apps.customers.services.CustomerService',
    ]

    for import_path in critical_imports:
        if not test_import(import_path):
            alert_critical_import_failure(import_path)

# Schedule in production monitoring
# Run every 5 minutes during migration phases
# Run hourly after migration completion
```

### Performance Impact Assessment
```python
# monitoring/migration_performance.py
def assess_migration_performance():
    """Measure performance impact of file structure changes"""

    metrics = {
        'average_import_time': measure_import_times(),
        'memory_usage': measure_memory_impact(),
        'code_navigation_speed': survey_developer_feedback(),
        'merge_conflict_frequency': analyze_git_conflicts(),
        'file_size_distribution': analyze_file_sizes(),
    }

    return metrics

# Target improvements after migration:
# - Average file size: < 500 lines (from 1000+ lines)
# - Merge conflicts: 50% reduction
# - Code navigation: 30% faster (developer survey)
# - Import times: No significant change
# - Memory usage: No significant change
```

## Team Guidelines and Best Practices

### New Development Workflow
1. **Feature Location**: Place new code in appropriate feature file
2. **Import Strategy**: Use direct imports to feature files (not re-exports)
3. **File Naming**: Follow `{feature}_{component}.py` convention
4. **Service Layer**: Put business logic in service classes, not models/views
5. **Testing**: Mirror code structure in test organization

### Code Review Checklist
- [ ] New code placed in appropriate feature file
- [ ] Imports use direct paths (not re-exports when possible)
- [ ] File size remains under 500 lines
- [ ] Business logic in service layer
- [ ] Tests follow same organizational structure
- [ ] No breaking changes to public APIs

### IDE Configuration Recommendations
```json
// VS Code settings for better navigation
{
    "python.analysis.extraPaths": [
        "./apps/billing",
        "./apps/customers",
        "./apps/users"
    ],
    "files.associations": {
        "*_service.py": "python",
        "*_views.py": "python",
        "*_models.py": "python"
    },
    "search.exclude": {
        "**/__pycache__": true,
        "**/migrations": true
    }
}
```

## Success Metrics
- Reduced average file size (target: <500 lines per file)
- Faster code navigation (measured by developer surveys)
- Reduced merge conflicts in large files
- Improved test organization and coverage
- Better separation of concerns (business logic in services)

## Related Decisions
- [ADR-0011: Feature-Based Test Organization](ADR-0011-feature-based-test-organization.md)
- Builds on existing Django app structure decisions
- Prepares for potential microservices transition if needed
