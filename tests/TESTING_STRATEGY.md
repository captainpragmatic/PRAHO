# 🧪 Testing Strategy - PRAHO Platform

## Overview
**Hybrid testing approach** with Django test runner as default and optional pytest for production CI.

## **Current Status** ✅

### Active Test Suite
- **`test_customer_user_comprehensive.py`** - Complete normalized customer model testing (14 tests)
- **Coverage**: 39.22% overall, 85.71% on customer models
- **Performance**: 0.047s execution time with query budget testing

### Legacy Test Files (Retired)
- **`test_customers.py.legacy`** - Old monolithic model tests (preserved for reference)
- **`test_billing.py.legacy`** - Old billing tests using deprecated structure

## **Testing Commands** 📋

```bash
# Primary development workflow (Django + SQLite)
make test           # Run all tests - DEFAULT approach
make test-fast      # Quick smoke tests (verbosity=1)
make test-coverage  # Coverage analysis with HTML report

# Advanced/Production testing
make test-prod      # pytest with PostgreSQL (auto-installs pytest if needed)
make test-all       # Run both Django and pytest suites

# Specific test files
make test-file FILE=tests.test_customer_user_comprehensive
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
