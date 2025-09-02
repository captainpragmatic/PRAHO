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

## Implementation Status

### Phase 1: Billing App ✅ COMPLETED
- ✅ Created `invoice_service.py`, `proforma_service.py`, `payment_service.py`
- ✅ Split `views.py` into `invoice_views.py`, `proforma_views.py`, `payment_views.py`, `billing_views.py`
- ✅ Split `models.py` into `invoice_models.py`, `proforma_models.py`, `payment_models.py`, etc.
- ✅ Updated imports and URL patterns

### Phase 2: Customers App ✅ COMPLETED  
- ✅ Created `customer_service.py`, `profile_service.py`, `membership_service.py`
- ✅ Split `views.py` into `customer_views.py`, `profile_views.py`, `membership_views.py`
- ✅ Split `models.py` into `customer_models.py`, `profile_models.py`
- ✅ Updated imports and URL patterns

### Phase 3: Users App ✅ COMPLETED
- ✅ Created `auth_service.py`, `mfa_service.py`, `profile_service.py`, `membership_service.py`
- ✅ Split `views.py` into `auth_views.py`, `mfa_views.py`, `profile_views.py`
- ✅ Split `models.py` into `user_models.py`, `profile_models.py`, `membership_models.py`
- ✅ Updated imports and URL patterns

### Phase 4: Provisioning App ✅ COMPLETED
- ✅ Created `provisioning_service.py` with enhanced service activation logic
- ✅ Split `models.py` into `service_models.py`, `relationship_models.py`
- ✅ Updated service layer with proper error handling and audit logging
- ✅ Updated imports and backward compatibility

### Phase 5: Cross-App Integration ✅ COMPLETED
- ✅ Updated all imports across codebase for new structures
- ✅ Verified backward compatibility through re-export patterns
- ✅ Tested import compatibility with Django system checks

## Consequences

### Positive
- **Improved Developer Experience**: Faster navigation, clearer code organization
- **Better Collaboration**: Reduced merge conflicts, clearer ownership
- **Enhanced Maintainability**: Single-purpose files, clear dependencies
- **Service-Oriented Architecture**: Proper separation of concerns
- **Testing Clarity**: Test structure mirrors code organization

### Challenges
- **Initial Migration**: Updating imports across codebase
- **Learning Curve**: Team needs to adopt new file naming conventions
- **Import Management**: Need to maintain model aggregation in main files

### Mitigation Strategies
- **Gradual Migration**: Implement feature by feature, app by app
- **Clear Documentation**: Provide examples and guidelines
- **IDE Support**: Configure IDEs for better navigation of new structure
- **Team Training**: Ensure all developers understand new patterns

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