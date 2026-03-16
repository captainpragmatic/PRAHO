# Architecture Decision Records

This folder contains all Architecture Decision Records (ADRs) for the PRAHO platform.
ADRs document significant architectural decisions, their context, and consequences,
providing a historical record of why the system is built the way it is.

> **Platform**: PRAHO v0.25.0 · **Stack**: Django 5.2 · Python 3.13 · PostgreSQL · HTMX
> **Architecture**: Two-service split (Platform :8700 + Portal :8701)
> See also: [Architecture docs](../architecture/) for diagrams and deep-dives.

---

## How to Create a New ADR

1. Create a new file: `ADR-XXXX-short-descriptive-title.md`
2. Use the next available number (currently: **ADR-0034**)
3. Follow the standard format: Status, Date, Authors, Context, Decision, Consequences
4. Set status to **Proposed** initially, then update to **Accepted** after team review

### Status Lifecycle

| Status | Meaning |
|--------|---------|
| **Proposed** | Under discussion, not yet approved |
| **Accepted** | Approved and in effect |
| **Implemented** | Accepted and fully deployed in code |
| **Partially Superseded** | Core idea still valid; specific aspects replaced by a newer ADR |
| **Superseded** | Fully replaced by a newer ADR (kept for historical context) |
| **Historical Reference** | Pre-implementation design artifact; actual code has diverged |

---

## ADR Index

### 🟢 Active Decisions

| # | Title | Status | Date |
|---|-------|--------|------|
| [ADR-0001](ADR-0001-pytest-playwright-for-e2e-testing.md) | pytest-playwright for E2E Testing | Accepted | 2025-08-25 |
| [ADR-0002](ADR-0002-strategic-linting-framework.md) | Strategic Linting Framework | Accepted | 2025-08-25 |
| [ADR-0004](ADR-0004-custom-2fa-implementation.md) | Custom 2FA Implementation vs django-otp | Accepted | 2024-08-24 |
| [ADR-0005](ADR-0005-single-constants-file-architecture.md) | Single Constants File Architecture | Accepted | 2025-08-26 |
| [ADR-0006](ADR-0006-security-warning-configuration.md) | Security Warning Configuration Strategy | Accepted | 2025-08-26 |
| [ADR-0007](ADR-0007-function-level-cross-app-imports.md) | Function-Level Cross-App Imports | Accepted | 2025-08-26 |
| [ADR-0009](ADR-0009-pragmatic-mypy-strategy.md) | Pragmatic MyPy Configuration Strategy | Accepted | 2025-08-27 |
| [ADR-0010](ADR-0010-django-admin-type-annotations.md) | Django Admin Type Annotations Strategy | Accepted | 2025-08-28 |
| [ADR-0011](ADR-0011-feature-based-test-organization.md) | Feature-Based Test Organization | Accepted | — |
| [ADR-0012](ADR-0012-internal-app-organization.md) | Internal App Organization (Feature-Based Files) | Accepted | 2025-01-02 |
| [ADR-0013](ADR-0013-uv-package-manager-migration.md) | Migration to uv Package Manager | Accepted | 2026-01-03 |
| [ADR-0014](ADR-0014-no-test-suppression-policy.md) | No Test Suppression Policy | Accepted | 2026-02-11 |
| [ADR-0015](ADR-0015-configuration-resolution-order.md) | Configuration Resolution Order (CRO) | Accepted | 2026-02-12 |
| [ADR-0016](ADR-0016-audit-trail-enforcement.md) | Audit Trail Enforcement | Accepted | 2026-02-15 |
| [ADR-0017](ADR-0017-portal-auth-fail-open-strategy.md) | Portal Authentication Fail-Open Strategy | Accepted | 2026-02-28 |
| [ADR-0019](ADR-0019-virtualmin-automatic-provisioning.md) | VirtualMin Automatic Provisioning System | Accepted | 2025-09-04 |
| [ADR-0020](ADR-0020-async-task-processing-architecture.md) | Async Task Processing Architecture | Accepted | 2025-09-02 |
| [ADR-0021](ADR-0021-email-enumeration-prevention.md) | Email Enumeration Prevention | Implemented | 2025-01-08 |
| [ADR-0025](ADR-0025-monetary-amounts-in-cents.md) | Store Monetary Amounts in Cents | Accepted | 2025-08-19 |
| [ADR-0026](ADR-0026-portal-frontend-architecture.md) | Portal Frontend Architecture | Accepted | 2026-03-02 |
| [ADR-0027](ADR-0027-hcloud-sdk-infrastructure-provisioning.md) | Infrastructure Provisioning via hcloud Python SDK | Accepted | 2026-03-03 |
| [ADR-0028](ADR-0028-server-log-checking-e2e.md) | Server Log Checking in E2E Tests | Accepted | 2026-03-03 |
| [ADR-0029](ADR-0029-config-drift-detection.md) | Config Drift Detection & Remediation | Proposed | 2026-03-03 |
| [ADR-0030](ADR-0030-rate-limiting-architecture.md) | Rate Limiting Architecture and Single Source of Truth | Accepted | 2026-03-05 |
| [ADR-0031](ADR-0031-api-token-authentication-strategy.md) | API Token Authentication Strategy | Accepted | 2026-03-06 |
| [ADR-0033](ADR-0033-encryption-architecture-consolidation.md) | Encryption Architecture Consolidation (4→2 Systems) | Accepted | 2026-03-06 |

### 🟡 Partially Superseded

| # | Title | Status | Superseded By |
|---|-------|--------|---------------|
| [ADR-0003](ADR-0003-comprehensive-type-safety-implementation.md) | Comprehensive Type Safety Implementation | Partially Superseded | Typing strategy → [ADR-0009](ADR-0009-pragmatic-mypy-strategy.md); Romanian business types still valid |

### 🔴 Superseded / Historical

| # | Title | Status | Notes |
|---|-------|--------|-------|
| [ADR-0008](ADR-0008-mypy-removal.md) | MyPy Removal | Superseded | Replaced by [ADR-0009](ADR-0009-pragmatic-mypy-strategy.md) (pragmatic approach instead of full removal) |
| [ADR-0018](ADR-0018-django-encryption-key-management.md) | DJANGO_ENCRYPTION_KEY Management for 2FA | Superseded | Replaced by [ADR-0033](ADR-0033-encryption-architecture-consolidation.md) (AES-256-GCM consolidation) |
| [ADR-0022](ADR-0022-project-structure-strategic-seams.md) | Project Structure - Strategic Seams | Superseded | Described original single-service monolith; platform migrated to two-service split |
| [ADR-0023](ADR-0023-database-structure.md) | Database Structure — Table Naming Convention | Accepted | Canonical reference for all 119 `db_table` values and schema design decisions |
| [ADR-0024](ADR-0024-user-role-clarification.md) | User Model Design: is_staff vs admin_role | Superseded | Proposed `admin_role` rename was not implemented; actual field is `staff_role` |

---

## Cross-Reference Map

Key relationships between ADRs for quick navigation:

```
Type Safety Chain
  ADR-0003 (types) ──superseded by──▶ ADR-0009 (pragmatic mypy)
  ADR-0008 (mypy removal) ──superseded by──▶ ADR-0009
  ADR-0009 ──related──▶ ADR-0010 (admin type annotations)

Security & Auth
  ADR-0004 (custom 2FA) ──related──▶ ADR-0033 (encryption consolidation)
  ADR-0018 (encryption key mgmt) ──superseded by──▶ ADR-0033 (AES-256-GCM)
  ADR-0017 (portal fail-open) ──related──▶ ADR-0004, ADR-0033, ADR-0021
  ADR-0021 (email enumeration) ──standalone──

Configuration & Organization
  ADR-0005 (constants) ──related──▶ ADR-0015 (CRO), ADR-0016 (audit)
  ADR-0011 (test organization) ◀──mirrors──▶ ADR-0012 (app organization)
  ADR-0015 (CRO) ──related──▶ ADR-0016 (audit trail)

Infrastructure & Provisioning
  ADR-0019 (virtualmin) ──related──▶ ADR-0020 (async tasks / Django-Q2)
  ADR-0027 (hcloud SDK) ──related──▶ ADR-0029 (config drift detection)
  ADR-0013 (uv migration) ──standalone──

Platform Traffic Management
  ADR-0030 (rate limiting architecture) ──related──▶ ADR-0017 (portal fail-open)

Token & Inter-Service Auth
  ADR-0031 (API token auth) ──related──▶ ADR-0017, ADR-0024
  ADR-0032 (dual HMAC) ──related──▶ ADR-0017, ADR-0031
```

---

## Categories

### 🧪 Testing & Quality
- [ADR-0001](ADR-0001-pytest-playwright-for-e2e-testing.md) — E2E testing with Playwright
- [ADR-0002](ADR-0002-strategic-linting-framework.md) — Ruff linting strategy
- [ADR-0014](ADR-0014-no-test-suppression-policy.md) — No skipping/suppressing tests
- [ADR-0028](ADR-0028-server-log-checking-e2e.md) — Backend log verification during E2E

### 🔒 Security & Authentication
- [ADR-0004](ADR-0004-custom-2fa-implementation.md) — Custom TOTP 2FA
- [ADR-0006](ADR-0006-security-warning-configuration.md) — Security warning config
- [ADR-0017](ADR-0017-portal-auth-fail-open-strategy.md) — Portal fail-open auth
- [ADR-0018](ADR-0018-django-encryption-key-management.md) — Encryption key management (superseded by ADR-0033)
- [ADR-0033](ADR-0033-encryption-architecture-consolidation.md) — Encryption architecture consolidation
- [ADR-0021](ADR-0021-email-enumeration-prevention.md) — Email enumeration prevention
- [ADR-0030](ADR-0030-rate-limiting-architecture.md) — Throttle architecture and startup validation
- [ADR-0031](ADR-0031-api-token-authentication-strategy.md) — Token auth gaps and roadmap

### 🏗️ Architecture & Code Organization
- [ADR-0005](ADR-0005-single-constants-file-architecture.md) — Constants file pattern
- [ADR-0007](ADR-0007-function-level-cross-app-imports.md) — Circular import prevention
- [ADR-0011](ADR-0011-feature-based-test-organization.md) — Test file structure
- [ADR-0012](ADR-0012-internal-app-organization.md) — App file structure
- [ADR-0015](ADR-0015-configuration-resolution-order.md) — Configuration resolution
- [ADR-0016](ADR-0016-audit-trail-enforcement.md) — Audit trail enforcement
- [ADR-0026](ADR-0026-portal-frontend-architecture.md) — HTMX and component architecture for Portal

### 🔧 Type Safety & Tooling
- [ADR-0003](ADR-0003-comprehensive-type-safety-implementation.md) — Type safety (partially superseded)
- [ADR-0009](ADR-0009-pragmatic-mypy-strategy.md) — Pragmatic MyPy config
- [ADR-0010](ADR-0010-django-admin-type-annotations.md) — Admin type annotations
- [ADR-0013](ADR-0013-uv-package-manager-migration.md) — uv package manager

### 💰 Business & Domain
- [ADR-0019](ADR-0019-virtualmin-automatic-provisioning.md) — VirtualMin provisioning
- [ADR-0020](ADR-0020-async-task-processing-architecture.md) — Django-Q2 async tasks
- [ADR-0025](ADR-0025-monetary-amounts-in-cents.md) — Monetary amounts in cents
- [ADR-0027](ADR-0027-hcloud-sdk-infrastructure-provisioning.md) — Hetzner SDK provisioning
- [ADR-0029](ADR-0029-config-drift-detection.md) — Drift detection and remediation workflow

---

## Statistics

- **Total ADRs**: 33 (ADR-0001 through ADR-0033)
- **Active**: 27 (Accepted + Implemented)
- **Partially Superseded**: 1
- **Superseded / Historical**: 5
- **Next available**: ADR-0034
