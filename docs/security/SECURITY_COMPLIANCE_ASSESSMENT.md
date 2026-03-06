# PRAHO Security & Compliance Assessment

**Assessment Date:** 2026-03-06
**Platform Version:** 0.13.0 (alpha)
**Branch:** `feat/encryption-consolidation-plan`

---

## Executive Summary

Comprehensive assessment of PRAHO's security and compliance posture against industry standards. References use `class::method` or `ClassName` notation instead of line numbers to survive refactoring.

| Category | Coverage | Status |
|----------|----------|--------|
| Access Control & Authentication | 88% | Strong |
| Input Validation & Protection | 80% | Strong |
| Transaction Security | 80% | Strong |
| Monitoring & Logging | 85% | Strong |
| Security Testing & SAST | 78% | Good |
| Configuration & Infrastructure | 80% | Strong |
| Encryption & Secrets | 95% | Excellent |

---

## 1. Access Control & Authentication

### 1.1 Multi-Factor Authentication (MFA)

| Feature | Status | Location |
|---------|--------|----------|
| TOTP (Authenticator Apps) | Implemented | `apps/users/mfa.py` — `TOTPService` class |
| Backup Codes | Implemented | `apps/users/mfa.py` — `BackupCodeService` class |
| WebAuthn/Passkeys | Framework | `apps/users/mfa.py` — `WebAuthnService` class, `WebAuthnCredential` model |
| SMS 2FA | Not implemented | Referenced in `mfa.py` imports |
| Rate Limiting (MFA) | Implemented | `apps/users/mfa.py` — `_check_rate_limit()`, 5 attempts per 5 minutes via cache |
| Audit Logging for MFA | Implemented | Throughout `mfa.py`, 180+ audit event types in `apps/audit/models.py` |

**Implementation details:**
- TOTP with 30-second time windows and clock drift tolerance
- Argon2-hashed backup codes (8-digit, max 10 per user, via Django `make_password`) with one-time use enforcement
- Replay attack protection for TOTP tokens
- WebAuthn signature counter replay detection
- QR code generation for authenticator app setup

### 1.2 Role-Based Access Control (RBAC)

| Feature | Status | Location |
|---------|--------|----------|
| Staff Roles | Implemented | `apps/users/models.py` — `STAFF_ROLE_CHOICES`: admin, support, billing, manager |
| Role-based Decorators | Implemented | `apps/common/decorators.py` — 7 decorators (see below) |
| Customer Memberships | Implemented | `apps/users/models.py` — `CustomerMembership` model with roles: owner, billing, tech, viewer |
| Infrastructure RBAC | Implemented | `apps/infrastructure/permissions.py` |
| Formal Permission Matrix | Partial | Uses Django's basic perms + custom decorators, no ABAC |

**Security decorators** in `apps/common/decorators.py`:

| Decorator | Access Rule |
|-----------|------------|
| `staff_required` | `is_staff=True` or `staff_role` set |
| `admin_required` | `staff_role='admin'` or `is_superuser` |
| `staff_required_strict` | Same as `staff_required` but returns 403 instead of redirect |
| `billing_staff_required` | `staff_role` in `["admin", "billing", "manager"]` or `is_superuser` |
| `support_staff_required` | `staff_role` in `["admin", "support", "manager"]` or `is_superuser` |
| `customer_or_staff_required` | Staff or `is_customer_user=True` |
| `rate_limit` | Configurable requests_per_minute with per-user and anonymous blocking |

### 1.3 Account Security

| Feature | Status | Location |
|---------|--------|----------|
| Password Hashing (Argon2) | Implemented | `config/settings/base.py` — `PASSWORD_HASHERS` (Argon2 primary, PBKDF2/BCrypt fallbacks) |
| Failed Login Tracking | Implemented | `apps/users/models.py` — `failed_login_attempts`, `account_locked_until` fields |
| Progressive Account Lockout | Implemented | Lockout escalation: 5 → 15 → 30 → 60 → 120 → 240 minutes |
| Session Security | Implemented | Middleware + `SessionSecurityService` |
| Login Rate Limiting | Implemented | `apps/users/views.py` — 10/min global, 5/min per email |

### 1.4 Rate Limiting

**Location:** `apps/common/performance/rate_limiting.py`

| Throttle Class | Scope | Rate |
|---------------|-------|------|
| `CustomerRateThrottle` | Per customer tier | Basic: 100/min, Professional: 500/min, Enterprise: 2000/min |
| `BurstRateThrottle` | Global burst | 30 requests per 10 seconds |
| `SustainedRateThrottle` | Global sustained | 1000 requests per hour |
| `ServiceRateThrottle` | Token bucket | Capacity: 100, refill: 10 tokens/sec, weighted by operation cost |
| `AnonymousRateThrottle` | Unauthenticated | 20 requests per minute |
| `WriteOperationThrottle` | POST/PUT/PATCH/DELETE | 60 per minute |
| `EndpointThrottle` | Per-endpoint | login: 5/min, 2fa_verify: 10/min, provision: 10/min |

See also: [ADR-0030](../ADRs/ADR-0030-rate-limiting-architecture.md)

---

## 2. Input Validation & Protection

### 2.1 Content Security Policy (CSP)

**Location:** `apps/common/middleware.py` — `SecurityHeadersMiddleware` class

```
default-src 'self'
script-src 'self' 'unsafe-inline' 'unsafe-eval' unpkg.com cdn.tailwindcss.com
style-src 'self' 'unsafe-inline' fonts.googleapis.com cdn.tailwindcss.com
font-src 'self' fonts.gstatic.com
img-src 'self' data:
object-src 'none'
form-action 'self'
```

**Gap:** `'unsafe-inline'` and `'unsafe-eval'` should be replaced with nonces for production hardening.

### 2.2 Security Headers

**Location:** `apps/common/middleware.py` — `SecurityHeadersMiddleware`

| Header | Value | Status |
|--------|-------|--------|
| `X-Content-Type-Options` | `nosniff` | Implemented |
| `X-Frame-Options` | `DENY` | Implemented |
| `X-XSS-Protection` | `1; mode=block` | Implemented |
| `Referrer-Policy` | Set | Implemented |
| `Cross-Origin-Opener-Policy` | Set | Implemented |
| `X-Request-ID` | UUID per request | Implemented (`RequestIDMiddleware`) |

**Production hardening** in `config/settings/prod.py`:

| Setting | Value |
|---------|-------|
| `SECURE_SSL_REDIRECT` | `True` |
| `SESSION_COOKIE_SECURE` | `True` |
| `CSRF_COOKIE_SECURE` | `True` |
| `CSRF_COOKIE_HTTPONLY` | `True` (in `base.py`) |
| `SECURE_HSTS_SECONDS` | 31536000 (1 year) |
| `SECURE_HSTS_INCLUDE_SUBDOMAINS` | `True` |

### 2.3 Subresource Integrity (SRI)

**Status:** Not implemented. No SRI hashes for third-party CDN resources.

**Risk:** Third-party scripts could be modified if CDNs are compromised.

### 2.4 SQL Injection Prevention

| Feature | Status | Notes |
|---------|--------|-------|
| Django ORM | Implemented | All database access via ORM |
| Raw SQL Queries | None found | No direct SQL detected |
| Parameterized Queries | Automatic | Django ORM handles this |

### 2.5 XSS Protection

| Feature | Status |
|---------|--------|
| Security headers | Implemented (see 2.2) |
| Template auto-escaping | Implemented (Django default) |
| Suspicious pattern detection | Implemented — `apps/common/validators.py` — `SUSPICIOUS_PATTERNS` list |

**Patterns checked:** XSS (script tags, `javascript:`, event handlers), SQL injection (union/select/insert/update/delete/drop, comments), code execution (`eval()`, `exec()`), control characters.

### 2.6 CSRF Protection

| Feature | Status | Location |
|---------|--------|----------|
| CSRF Middleware | Implemented | Django default |
| `CSRF_COOKIE_HTTPONLY` | Implemented | `config/settings/base.py` |
| `CSRF_COOKIE_SECURE` | Implemented | `config/settings/prod.py` |
| `SameSite=Lax` | Implemented | `config/settings/prod.py` |

### 2.7 File Upload Validation

| Feature | Status | Location |
|---------|--------|----------|
| Max File Size | Implemented (10MB) | `config/settings/base.py` — `FILE_UPLOAD_MAX_MEMORY_SIZE` |
| File Permissions | Implemented (0o644) | `config/settings/base.py` — `FILE_UPLOAD_PERMISSIONS` |
| Max Data Upload | Implemented (10MB) | `config/settings/base.py` — `DATA_UPLOAD_MAX_MEMORY_SIZE` |
| MIME Type Validation | Not implemented | |
| Content Scanning | Not implemented | No malware scanning |
| Extension Whitelist | Not implemented | Not formalized |

---

## 3. Encryption & Secrets Management

### 3.1 Encryption at Rest

Both systems use **AES-256-GCM** (NIST SP 800-38D). For full standards mapping, see [ADR-0033](../ADRs/ADR-0033-encryption-architecture-consolidation.md).

| System | Key | Purpose |
|--------|-----|---------|
| App-level encryption | `DJANGO_ENCRYPTION_KEY` | Model field data: 2FA secrets, settings, registrar credentials, EPP codes, OAuth tokens, notifications, provisioning passwords, server management credentials |
| Credential vault | `CREDENTIAL_VAULT_MASTER_KEY` | Infrastructure identity: VirtualMin root creds, cloud provider tokens (HCloud), SSH keys, provider registration tokens |

**Wire format:** `"aes:" + base64url(NONCE[12B] + CIPHERTEXT + TAG[16B])`
**Key format:** URL-safe base64-encoded 32 random bytes
**Fail mode:** `ImproperlyConfigured` if keys missing (fail-closed)

| Feature | Status | Location |
|---------|--------|----------|
| AES-256-GCM encryption | Implemented | `apps/common/encryption.py` |
| Credential vault with audit | Implemented | `apps/common/credential_vault.py` |
| Key separation (blast radius) | Implemented | Two independent keys |
| Environment variable storage | Implemented | All secrets via env vars |
| Secret key validation | Implemented | `config/settings/base.py` — `validate_production_secret_key()` |
| Vault integrity self-test | Implemented | `CredentialVault._verify_vault_integrity()` on init |
| Credential expiration | Implemented | Default 30 days, configurable |
| Credential rotation | Implemented | `CredentialVault.rotate_credential()` with rollback |
| Credential access audit log | Implemented | `CredentialAccessLog` model, 365-day retention |
| HKDF domain key separation | Implemented | `apps/common/key_derivation.py` — RFC 5869 HKDF-SHA256 with NIST SP 800-57 §5.2 domain separation |

### 3.2 Password & Backup Code Security

| Feature | Status |
|---------|--------|
| Argon2id hashing (primary) | Implemented |
| PBKDF2/BCrypt fallbacks | Implemented |
| Backup codes: Django password hashing | Implemented |
| No plaintext secret storage | Verified (audit complete) |

---

## 4. Transaction Security

### 4.1 Database Transactions (ACID)

| Feature | Status | Location |
|---------|--------|----------|
| Django Transactions | Implemented | Used throughout |
| Atomic Operations | Implemented | `@transaction.atomic` decorators |
| Refund Service | Implemented | `apps/billing/refund_service.py` |

### 4.2 Idempotency Keys

**Location:** `apps/provisioning/security_utils.py` — `IdempotencyManager` class

- Idempotency TTL: 1 hour (`IDEMPOTENCY_KEY_TTL = 3600`)
- Methods: `generate_key()`, `check_and_set()`, `complete()`, `clear()`
- Used in provisioning and payment operations

### 4.3 Webhook Verification

**Location:** `apps/integrations/webhooks/base.py`

| Feature | Status | Method |
|---------|--------|--------|
| HMAC Signature Verification | Implemented | `verify_hmac_signature()` — SHA-256 with `hmac.compare_digest()` (timing-safe) |
| Stripe Signature Verification | Implemented | `verify_stripe_signature()` — timestamp validation (300s tolerance) + HMAC-SHA256 |
| Deduplication (in-memory) | Implemented | `_check_duplicates()` preliminary check |
| Deduplication (DB-level) | Implemented | `unique_together = (("source", "event_id"))` on `WebhookEvent` model |
| Race condition handling | Implemented | `IntegrityError` caught on concurrent inserts, treated as duplicate |
| Status Tracking | Implemented | pending / processed / failed / skipped |
| Retry Mechanism | Implemented | `next_retry_at` field with indexed retry queue |

**Webhook sources:** Stripe, PayPal, VirtualMin, cPanel, Namecheap, GoDaddy, BT Bank, BCR Bank, e-Factura, other.

### 4.4 Audit Trails for Financial Transactions

**Location:** `apps/audit/models.py` — `AuditEvent` model

- **180+ event types** across 10 categories
- Complete payment lifecycle tracking
- Refund and chargeback logging
- Invoice access and download tracking
- Tax calculation auditing

**Categories:** Authentication, Authorization, Account Management, Data Protection, Security Events, Business Operations, Compliance, System Admin, Integration, Infrastructure.

**Severity levels:** low, medium, high, critical.
**Metadata:** IP address, user agent, request ID, session key, tags, sensitivity flags.

### 4.5 Fraud Detection

| Feature | Status |
|---------|--------|
| Suspicious Activity Logging | Implemented — `brute_force_attempt`, `malicious_request` events |
| Payment Fraud Events | Implemented — `payment_fraud_detected` event type |
| Rate Limit Exceeded Events | Implemented — `rate_limit_exceeded` event type |
| IP Blocking Events | Implemented — `ip_blocked` event type |
| Anomaly Detection (ML) | Not implemented |
| Real-time Fraud Scoring | Not implemented |

---

## 5. Monitoring, Logging & Incident Response

### 5.1 Centralized Logging

| Feature | Status | Location |
|---------|--------|----------|
| Authentication Logging | Implemented | 15+ auth event types in `audit/models.py` |
| Privileged Actions | Implemented | Staff role changes, impersonation |
| Configuration Changes | Implemented | System admin event category |
| JSON Format Logging | Implemented | `config/settings/prod.py` — `SIEMJSONFormatter` |
| Request ID Tracking | Implemented | `RequestIDMiddleware` + `RequestIDFilter` in prod logging |
| Rotating File Handlers | Implemented | Prod: 50MB/10 backups (general), 100MB/90 backups (audit), 50MB/30 backups (security, error) |

### 5.2 File Integrity Monitoring (FIM)

**Location:** `apps/audit/file_integrity_service.py`

| Feature | Status |
|---------|--------|
| Cryptographic Hash Tracking | Implemented — SHA-256 |
| Critical File Monitoring | Implemented — `config/settings/*.py`, `apps/common/encryption.py`, `apps/users/mfa.py`, `apps/common/middleware.py`, `apps/users/views.py`, `apps/common/security_decorators.py` |
| Change Detection | Implemented — CREATED, MODIFIED, DELETED, PERMISSIONS_CHANGED, OWNER_CHANGED |
| Baseline Establishment | Implemented — cache-based with 30-day timeout |
| Scheduled Monitoring | Implemented — Django-Q2 tasks with 6h interval (`apps/audit/tasks.py`) |
| Alert Generation | Implemented — `AuditAlert` integration |
| Management Command | Implemented — `run_integrity_check` |
| Data Retention | Implemented — 90-day cleanup for healthy checks, retain all warnings/compromised |

**Run manually:**
```bash
python manage.py run_integrity_check --type all --period 24h
```

### 5.3 SIEM Integration

**Status: Framework ready, not operationally deployed.**

Code exists (`apps/audit/siem.py` + `apps/audit/siem_integration.py`) with support for Splunk, Elasticsearch, Datadog, Sumo Logic, and Generic Webhook providers. Includes CEF, LEEF, JSON, SYSLOG, and OCSF format export, batch/real-time modes, and HMAC webhook signing. However, no external SIEM endpoint is currently configured or deployed in production.

| Feature | Code Status | Deployed |
|---------|-------------|----------|
| Splunk provider | Ready | No |
| Elasticsearch provider | Ready | No |
| Datadog provider | Ready | No |
| Sumo Logic provider | Ready | No |
| Generic Webhook | Ready | No |
| CEF/LEEF/OCSF format export | Ready | No |
| Syslog RFC 5424 | Ready | No |
| HMAC webhook signing | Ready | No |

### 5.4 Log Retention

| Policy | Duration | Location |
|--------|----------|----------|
| Audit Logs | 10 years | `apps/common/constants.py` — `AUDIT_LOG_RETENTION_YEARS` |
| GDPR Logs | 12 months | `apps/common/constants.py` — `GDPR_LOG_RETENTION_MONTHS` |
| Failed Login Logs | 6 months | `apps/common/constants.py` — `FAILED_LOGIN_LOG_RETENTION_MONTHS` |
| Credential Access Logs | 365 days | `apps/common/credential_vault.py` — `ACCESS_LOG_RETENTION_DAYS` |
| FIM Healthy Checks | 90 days | `apps/audit/tasks.py` — `cleanup_old_integrity_checks()` |

### 5.5 Tamper-Proof Logging

| Feature | Status |
|---------|--------|
| Immutable Records | Implemented — audit events cannot be modified |
| Hash Chain | Framework exists in `siem_integration.py`, not deployed |
| Write-Once Storage (WORM) | Not implemented |
| External Replication | Not implemented |

---

## 6. Security Testing

### 6.1 Security Testing in CI/CD

**6 GitHub Actions workflows** in `.github/workflows/`:

| Workflow | Purpose | Security Relevance |
|----------|---------|-------------------|
| `platform.yml` | Platform unit tests + coverage + Ruff | Tests run on every push/PR |
| `portal.yml` | Portal tests + validates no DB drivers installed | Enforces stateless architecture |
| `integration.yml` | Cross-service integration + security isolation tests | Service boundary enforcement |
| `type-coverage.yml` | MyPy type coverage (1100 error threshold) | Type safety enforcement |
| `dco-check.yml` | Developer Certificate of Origin | Commit provenance |
| `release.yml` | Automated GitHub Releases from tags | Release automation |

### 6.2 Pre-Commit Security Hooks

**19 total hooks**, 5 security-focused. From `.pre-commit-config.yaml`:

| Hook | Purpose | Security? |
|------|---------|-----------|
| `ruff-new-violations` | Block NEW Ruff violations (tolerates historical debt) | Yes |
| `portal-isolation-check` | **CRITICAL**: validates portal cannot import platform code | Yes |
| `audit-coverage-check` | Audit logging regression detection (min-severity=high) | Yes |
| `security-credentials-check` | Ruff S105/S106/S107/S108 — hardcoded credentials | Yes |
| `prevent-type-ignore` | Block new `# type: ignore` comments | Yes (type safety) |

### 6.3 Static Application Security Testing (SAST)

| Tool | Status | Integration |
|------|--------|-------------|
| **Semgrep** | Active | `make lint-security` — `semgrep scan --config=auto --error` |
| **Custom PRAHO Scanner** | Active | `scripts/security_scanner.py` (1,052 lines) — OWASP Top 10, APT patterns, CVE checks |
| **Ruff Security Rules** | Active | S105/S106/S107/S108 in pre-commit |
| **Audit Coverage Scanner** | Active | `scripts/audit_coverage_scan.py` — validates audit decorator coverage |
| Bandit | Config exists, dormant | `.bandit` file in `services/platform/` — not in CI/CD |
| pip-audit / Safety | Framework exists | `scripts/security_scanner.py` `--include-dependencies` flag — not triggered by default |
| Snyk | Not configured | |
| Trivy | Not configured | Container scanning not integrated |

**`make lint-security` runs:**
1. Semgrep scan (auto config, excludes tests, fails on findings)
2. Hardcoded credentials check (`make lint-credentials`)
3. Custom security scanner (OWASP Top 10, APT patterns — informational, non-blocking)

**`make test-security` validates:**
1. Portal cannot import platform modules (3 explicit checks)
2. Platform uses `DatabaseCache` (not dev settings)
3. Portal has no database access
4. Import isolation guard (pytest)

### 6.4 Security Test Coverage

**26 security-focused test files** across the codebase:

| Location | Count | Examples |
|----------|-------|---------|
| `tests/security/` (root) | 2 | `test_security_comprehensive.py`, `run_security_scan.py` |
| `tests/integration/` | 1 | `test_security_hardening.py` (23K) |
| `services/platform/tests/security/` | 4 | `test_comprehensive_access_control.py`, `test_enhanced_validation.py`, `test_file_upload_security.py`, `test_simple_access_control.py` |
| `services/platform/tests/*/test_*security*` | 14 | Per-app security tests (domains, billing, users, orders, etc.) |
| `services/portal/tests/*security*` | 4 | HMAC production security, portal security, order security |
| `tests/integration_tests/` | 1 | `test_mfa_security.py` |

---

## 7. Configuration & Infrastructure

### 7.1 Infrastructure as Code (IaC)

| Tool | Status | Location |
|------|--------|----------|
| **Ansible** | Implemented | `deploy/ansible/` — 5 playbooks, 4 roles |
| **Docker** | Implemented | `deploy/platform/Dockerfile`, `deploy/portal/Dockerfile` |
| **Docker Compose** | Implemented | 7 compose configs (dev, prod, single-server, split, SSL) |
| **hcloud Python SDK** | Implemented | `apps/infrastructure/hcloud_service.py` — replaced Terraform ([ADR-0027](../ADRs/ADR-0027-hcloud-sdk-infrastructure-provisioning.md)) |
| Terraform | Exists (legacy) | `services/platform/infrastructure/terraform/` — superseded by hcloud SDK |

**Ansible playbooks** (`deploy/ansible/playbooks/`):
- `single-server.yml` — single machine Docker deployment
- `two-servers.yml` — platform + portal split deployment
- `native-single-server.yml` — systemd-based deployment (no Docker)
- `backup.yml` — database backup
- `rollback.yml` — deployment rollback

**Ansible roles:**
- `common` — security hardening (Fail2Ban jail config)
- `docker` — Docker installation and daemon config
- `praho` — Docker-based service deployment
- `praho-native` — systemd-based service deployment

**Docker security:**
- Non-root user (`django:django`) in both Dockerfiles
- Portal Dockerfile has NO `postgresql-client`, NO `libpq-dev` (enforces statelessness)
- Network isolation: portal-network separate from platform-network

### 7.2 Configuration Drift Detection

**Status: Implemented** — [ADR-0029](../ADRs/ADR-0029-config-drift-detection.md)

| Feature | Status | Location |
|---------|--------|----------|
| Drift Scanner | Implemented | `apps/infrastructure/drift_scanner.py` — scans Cloud, Network, Application layers |
| Drift Remediation | Implemented | `apps/infrastructure/drift_remediation.py` — approval workflow + rollback |
| Drift Models | Implemented | `DriftCheck`, `DriftReport`, `DriftRemediationRequest`, `DriftSnapshot` |
| Management Command | Implemented | `manage.py drift_scan` |
| Severity Classification | Implemented | CRITICAL / HIGH / MODERATE / LOW / INFO |
| Scheduled Scanning | Proposed | 15-minute polling via Django-Q2 (ADR-0029) |

### 7.3 Infrastructure Management

**Location:** `apps/infrastructure/` — 21 service files

Key services:
- `deployment_service.py` — node deployment orchestration
- `hcloud_service.py` — Hetzner Cloud management
- `ansible_service.py` — Ansible playbook orchestration
- `ssh_key_manager.py` — SSH key provisioning and rotation
- `provider_config.py` — cloud provider credentials (via credential vault)
- `validation_service.py` — node health checks
- `cost_service.py` — cloud cost tracking
- `permissions.py` — infrastructure RBAC

**Management commands** (`apps/infrastructure/management/commands/`):
- `deploy_node.py` — deploy infrastructure node
- `manage_node.py` — node lifecycle management
- `drift_scan.py` — configuration drift detection
- `store_credentials.py` — credential vault storage
- `sync_providers.py` — provider configuration sync
- `cleanup_deployments.py` — old deployment cleanup

---

## Gap Analysis Summary

### Critical Gaps (Immediate Action Required)

| Gap | Risk Level | Effort | Notes |
|-----|------------|--------|-------|
| SRI for CDN Resources | High | Low | No integrity hashes on third-party scripts |
| File Upload Content Validation | High | Medium | No MIME type validation or content scanning |
| CSP Nonce Implementation | High | Medium | `unsafe-inline` and `unsafe-eval` in CSP |

### Important Gaps (Should Address)

| Gap | Risk Level | Effort | Notes |
|-----|------------|--------|-------|
| SIEM Operational Deployment | Medium | Medium | Framework ready, needs endpoint configuration |
| Dependency Scanning in CI | Medium | Low | pip-audit/Safety code exists, not triggered automatically |
| Container Scanning (Trivy) | Medium | Low | Docker images not scanned |
| Fraud Detection Heuristics | Medium | High | No ML/velocity/geo anomaly detection |
| WebAuthn Full Implementation | Medium | Medium | Framework exists, needs completion |
| Tamper-Proof Log Storage | Medium | Medium | No WORM storage or external replication |

### Enhancement Opportunities

| Gap | Risk Level | Effort | Notes |
|-----|------------|--------|-------|
| Formal RBAC Permission Matrix | Low | Medium | Currently ad-hoc decorators |
| SMS 2FA | Low | Medium | |
| Bandit Integration in CI | Low | Low | Config exists, just needs wiring |
| Custom Scanner as CI Blocker | Low | Low | Currently `|| true` (non-blocking) |

---

## Compliance Frameworks Alignment

| Framework | Coverage | Notes |
|-----------|----------|-------|
| ISO 27001 | ~85% | Strong audit logging + credential access audit trail ([ADR-0033](../ADRs/ADR-0033-encryption-architecture-consolidation.md)); needs operational SIEM |
| NIST Cybersecurity | ~88% | AES-256-GCM (SP 800-38D), key management (SP 800-57), key separation (SP 800-57 §5.2 via HKDF), CSPRNG (SP 800-90A), RBAC (SP 800-162) — see [ADR-0033](../ADRs/ADR-0033-encryption-architecture-consolidation.md) |
| GDPR | ~94% | Encryption at rest (Art. 32), access audit logs (Art. 30), data minimization (Art. 5(1)(c) — no PII in unsubscribe URLs), comprehensive consent and data handling |
| PCI DSS | ~75% | Transaction logging, webhook verification, rate limiting; needs formal penetration testing |
| SOX | ~75% | Financial audit trails complete |
| Romanian Law 190/2018 | ~92% | Strong local compliance, encryption satisfies data protection requirement |

---

## Related Documents

- [ADR-0033: Encryption Architecture Consolidation](../ADRs/ADR-0033-encryption-architecture-consolidation.md) — standards compliance mapping
- [Security Configuration Guide](SECURITY_CONFIGURATION.md) — operational key setup and deployment
- [MFA Setup and Key Management](MFA-SETUP-AND-KEY-MANAGEMENT.md) — MFA setup and encryption key management
- [Template and CSP Security](../development/TEMPLATE-AND-CSP-SECURITY.md) — Django template security and CSP patterns
