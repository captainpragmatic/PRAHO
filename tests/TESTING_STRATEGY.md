# 🧪 Testing Strategy - PRAHO Platform

## Overview
**Hybrid testing approach** with Django test runner as default and optional pytest for production CI.

## **Test Structure** 🏗️

### **Organized by App Structure**
Tests mirror the `apps/` directory structure for clear organization:

```bash
tests/
├── users/                    # User authentication, 2FA, roles
├── billing/                  # Invoices, payments, credit ledger  
├── customers/               # Customer management
├── audit/                   # Audit logging
├── common/                  # Shared utilities
├── domains/                 # Domain management
├── integrations/            # External service integrations
├── notifications/           # Email, SMS notifications
├── orders/                  # Order processing
├── products/                # Product catalog
├── provisioning/            # Service provisioning
├── tickets/                 # Support tickets
├── ui/                      # Frontend/HTMX components
└── integration-tests/       # Cross-app workflows
```

### **Naming Convention**
- **Unit Tests**: `test_{app}_{feature}.py` (e.g., `test_users_2fa.py`)
- **Integration Tests**: `test_{workflow_name}.py` in `integration-tests/`
- **Clear Separation**: App tests vs cross-app tests

## **Current Status** ✅

### Active Test Suite
- **User Tests**: 2FA security, password reset validation
- **Billing Tests**: Complete billing cycle (6 test files)
- **Integration Tests**: Customer-user comprehensive workflows
- **Coverage**: High coverage on critical business logic
- **Performance**: Fast execution with query budget testing

## **Testing Commands** 📋

```bash
# Primary development workflow (Django + SQLite)
make test               # Run all tests - DEFAULT approach
make test-fast          # Quick smoke tests (verbosity=1)
make test-coverage      # Coverage analysis with HTML report

# App-specific testing
pytest tests/users/           # User management tests only
pytest tests/billing/         # Billing functionality only  
pytest tests/integration-tests/  # Cross-app workflows only

# Advanced testing with markers
pytest -m "integration"      # Integration tests only
pytest -m "not slow"        # Skip slow tests
pytest -m "security"        # Security-related tests
pytest -m "romanian_compliance"  # Romanian regulation tests

# Production testing
make test-prod          # pytest with PostgreSQL (auto-installs pytest if needed)
make test-all           # Run both Django and pytest suites
```

## **Architecture Decision** 🎯

### **Django Test Runner (Primary)** ✅
- **Benefits**: Fast (0.047s), reliable, no dependencies, SQLite in-memory
- **Use Cases**: Day-to-day development, CI/CD, local testing
- **Coverage**: Comprehensive business logic and integration testing

### **pytest (Secondary/Optional)** 🔧
- **Benefits**: Production-like PostgreSQL environment, advanced fixtures
- **Use Cases**: Pre-production validation, complex integration scenarios
- **Setup**: Auto-installs when using `make test-prod`

## **Test Coverage Summary** 📊

### ✅ **Comprehensive Coverage Achieved**
- Customer creation with normalized profiles
- User-customer relationships via CustomerMembership
- Soft delete with Romanian compliance preservation
- Query performance budgets (≤3-6 queries)
- GDPR consent tracking and audit trails
- CASCADE deletion behavior testing

### 🎯 **Quality Standards**
- **Query Budget**: All list/detail views tested for N+1 prevention
- **Romanian Compliance**: VAT, CUI validation, audit preservation
- **Performance**: Tests complete in <0.1s with efficient queries
- **Coverage Gates**: 85%+ on core business models

## **Migration from Legacy** 🔄

### What Was Retired
- Old monolithic Customer model tests (company_name, cui, contact_email fields)
- Direct many-to-many user relationships (now via CustomerMembership)
- Form tests using deprecated field structure

### Why This Approach
1. **Modern Architecture**: Tests match normalized model structure
2. **Maintainability**: Single comprehensive suite vs scattered legacy tests
3. **Performance**: Query budgets prevent N+1 problems
4. **Compliance**: Romanian business rules properly tested

## **Developer Workflow** 🔄

```bash
# Standard development cycle
make test           # Quick validation
make test-coverage  # Before PR submission
make test-prod      # Before deployment (optional)
```

**Result**: Robust testing infrastructure supporting both rapid development and production confidence! 🎉
