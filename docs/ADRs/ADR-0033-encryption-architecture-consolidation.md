# ADR-0033: Encryption Architecture Consolidation (4 → 2 Systems)

## Status
**Accepted** - March 2026

## Context

PRAHO evolved four separate encryption/signing systems organically:

1. **`apps/common/encryption.py`** — Fernet (AES-128-CBC) for 2FA TOTP secrets and backup codes. Had double base64 encoding and silent empty-string return on decrypt failure.
2. **`apps/common/credential_vault.py`** — Fernet for master credential management. Had RBAC bypass (always returned `True`), stale object bug in rotation, and dict-vs-tuple integration bug.
3. **`apps/common/aes256_encryption.py`** — AES-256-GCM with good design (version bytes, PBKDF2, wire format) but zero production imports. Dead code with dangerous `SECRET_KEY` fallback.
4. **`apps/settings/encryption.py`** — Django `Signer` (HMAC signing, NOT encryption). OAuth tokens, API keys, and sensitive settings stored as signed plaintext (`base64(plaintext:signature)`).

Dual code review (Claude code-reviewer + OpenAI Codex CLI) confirmed these issues. The proliferation of systems increased attack surface and maintenance burden.

## Decision

Consolidate to **2 systems**, both using **AES-256-GCM** (NIST SP 800-38D):

1. **App-level encryption** (`apps/common/encryption.py`) — For model field data: 2FA secrets, settings values, registrar credentials (API key, API secret, webhook secret), EPP codes, e-Factura OAuth tokens, notification bodies, provisioning passwords, server management credentials.
2. **Credential vault** (`apps/common/credential_vault.py`) — For infrastructure identity credentials: VirtualMin server root creds, cloud provider API tokens (HCloud), SSH private keys, provider registration tokens.

### Boundary rationale

The split follows **ownership and blast radius**:
- **App-level encryption**: secrets owned by business entities (a Registrar, a Domain, a User, a Server) stored as model fields. Uses encrypt-on-write / decrypt-on-read via model accessor methods.
- **Credential vault**: secrets that represent the platform's own identity for connecting to external infrastructure. Uses a service-oriented API (`store_credential` / `retrieve_credential`) with its own `EncryptedCredential` model, lifecycle management, and audit trail.

Two separate keys ensure that compromising one system does not expose the other.

### Design choices

- **AES-256-GCM** — Authenticated encryption with associated data (AEAD). NIST-standardized, quantum-safe per NIST PQC guidance.
- **No PBKDF2** — Keys are 32 random bytes used directly. PBKDF2 adds CPU cost without security gain for already-random keys.
- **No legacy support** — Hard cut with data invalidation. No Fernet backward compat, no dual decrypt, no migration helpers.
- **Fail-closed in production** — Missing or invalid key raises `ImproperlyConfigured` immediately.
- **Wire format** — `"aes:" + base64url(NONCE[12B] + CIPHERTEXT + TAG[16B])`.
- **Key format** — URL-safe base64-encoded 32 random bytes.
- **Two separate keys** — `DJANGO_ENCRYPTION_KEY` (app) and `CREDENTIAL_VAULT_MASTER_KEY` (vault) for blast-radius isolation.

### Deleted

- `apps/common/aes256_encryption.py` — Dead code, zero production imports.
- `apps/settings/encryption.py` — Signing (not encryption), replaced by real encryption.

## Standards Compliance

Every design choice maps to a specific standard or RFC.

### Cryptographic standards

| Decision | Standard | Requirement satisfied |
|----------|----------|----------------------|
| AES-256-GCM algorithm | **NIST SP 800-38D** | Authoritative GCM specification; defines nonce, tag, and GHASH construction |
| AES-256 key size | **NIST SP 800-131A Rev.2** | AES-256 approved through 2031+ and beyond; quantum-resistant (Grover reduces to 128-bit effective, still above minimum) |
| AEAD construction | **RFC 5116** | Defines AES-256-GCM as an Authenticated Encryption with Associated Data algorithm |
| TLS cipher alignment | **RFC 8446 (TLS 1.3)** | `TLS_AES_256_GCM_SHA384` is mandatory; our at-rest encryption uses the same primitive as our in-transit encryption |
| 96-bit random nonce | **NIST SP 800-38D §8.2.2** | Random nonce construction; birthday bound ~2^48 encryptions before collision risk |
| 128-bit auth tag | **NIST SP 800-38D §5.2.1** | Full-length tag (NIST minimum is 96-bit; we use the recommended 128-bit) |
| No PBKDF2 for random keys | **NIST SP 800-132 §5** | KDFs are for password-derived keys; random keys used directly per spec |

### Key management

| Decision | Standard | Requirement satisfied |
|----------|----------|----------------------|
| 32 bytes from CSPRNG | **NIST SP 800-90A** | `os.urandom()` / `secrets.token_bytes()` use the OS CSPRNG |
| Key stored in env var | **12-Factor App §III** | Config in environment, not in code |
| Fail-closed on missing key | **NIST SP 800-123** | Secure by default; system refuses to start without valid key |
| Separate keys per system | **NIST SP 800-57 Part 1 §5.2** | Key separation by usage context; limits blast radius of compromise |
| Credential expiration | **NIST SP 800-57 Part 1 §5.3** | Crypto-period enforcement; vault credentials expire after configurable days |

### Key isolation (HKDF domain separation)

| Decision | Standard | Requirement satisfied |
|----------|----------|----------------------|
| HKDF-SHA256 key derivation | **RFC 5869** | Extract-then-Expand paradigm for deriving domain-specific keys from a single root |
| Domain-separated `info` parameter | **NIST SP 800-57 Part 1 §5.2** | Key separation by usage context; each domain (`mfa-backup`, `unsubscribe`, `siem-hash-chain`, `sensitive-data-hash`) gets a cryptographically independent key |
| 32-byte derived key length | **NIST SP 800-108** | KDF-derived keys meet minimum 256-bit strength for HMAC and symmetric operations |
| Optional per-domain env override | **12-Factor App §III** | Operators can supply dedicated secrets per domain; HKDF fallback provides safe defaults |
| Minimum 32-char env override | **NIST SP 800-131A Rev.2** | Rejects short secrets; `ImproperlyConfigured` on insufficient key material |

**Implementation**: `apps/common/key_derivation.py` — `derive_key(domain)` and `get_key_hex(domain)`.

### Operational and compliance

| Decision | Standard | Requirement satisfied |
|----------|----------|----------------------|
| Access audit trail | **ISO 27001 A.9.4.2** | Secure log-on; every credential access logged with user, reason, method, timestamp |
| Audit log retention (365 days) | **GDPR Article 30** | Records of processing activities; credential access logs retained 1 year |
| RBAC on credential access | **NIST SP 800-162** | Attribute-based access control; vault enforces staff/superuser checks |
| Integrity self-test on init | **FIPS 140-2 §4.9.1** | Power-up self-test; vault encrypts/decrypts test data on initialization |
| Encryption at rest for PII | **GDPR Article 32** | Appropriate technical measures; all sensitive personal data encrypted |
| Romanian compliance | **Law 190/2018** | Romanian GDPR transposition; encryption satisfies data protection requirement |

### Wire format and encoding

| Decision | Standard | Requirement satisfied |
|----------|----------|----------------------|
| Base64url encoding | **RFC 4648 §5** | URL-safe alphabet (no `+/`); safe for CharField storage without escaping |
| Self-describing prefix (`aes:`) | — | Not RFC-mandated; follows defense-in-depth for migration safety and preventing silent misinterpretation |

### FIPS 140-2/3 readiness

The implementation is **FIPS-ready** but not FIPS-certified. The `cryptography` library supports FIPS mode via OpenSSL's FIPS provider. To achieve FIPS 140-3 compliance:
1. Deploy with a FIPS-validated OpenSSL build (`cryptography` hazmat backend)
2. Enable FIPS mode in the OS/container (`/proc/sys/crypto/fips_enabled`)
3. No code changes required — all primitives (AES-256-GCM, CSPRNG) are FIPS-approved

## Consequences

### Positive
- Single encryption standard (AES-256-GCM) across the entire platform
- Real confidentiality for all sensitive data (was plaintext-signed before)
- Explicit error handling (no silent failures)
- Reduced attack surface (2 systems instead of 4)
- Fixed: RBAC bypass, plaintext fallback, stale object bug, dict-vs-tuple bug
- Full standards traceability for security audits

### Negative
- **Breaking change**: All encrypted data invalidated on deploy
- Users must re-enroll in 2FA
- Server credentials, API keys, OAuth tokens must be re-entered
- Requires coordinated maintenance window

## Related documents
- [Security Configuration Guide](../security/SECURITY_CONFIGURATION.md) — operational key setup and usage
- [Security Compliance Assessment](../security/SECURITY_COMPLIANCE_ASSESSMENT.md) — framework coverage scores

## Supersedes
- [ADR-0018: DJANGO_ENCRYPTION_KEY Management for 2FA](ADR-0018-django-encryption-key-management.md)
