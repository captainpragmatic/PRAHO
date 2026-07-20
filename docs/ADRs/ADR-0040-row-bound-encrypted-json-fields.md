# ADR-0040: Row-Bound Encrypted JSON Fields

## Status

**Accepted** - July 2026

## Context

EncryptedJSONField used AES-256-GCM v2 ciphertext with associated authenticated
data (AAD), but its row component was not verified on reads. Auto-increment
primary keys were also unavailable during the first INSERT, so new ciphertext
was commonly bound only to table:field:. A database writer could therefore
copy ciphertext between rows of the same field.

Three related weaknesses made that gap more dangerous:

- decryption, AAD, and downgrade failures returned None, allowing a later
  model save to replace forensic ciphertext with SQL NULL;
- callers could supply an expected AAD to the primitive, but v2 decryption
  ignored it;
- malformed base64 and empty AAD were accepted, and the per-key AES-GCM cache
  retained an unbounded number of rotation keys.

Customer payment bank details are the only production EncryptedJSONField.
They need row-level integrity without changing the public integer
payment-method identifier used by billing APIs and foreign keys.

## Decision

### Stable row identity

CustomerPaymentMethod has a random encryption_context_id UUID generated before
its first INSERT. Bank-details AAD is exactly:

customer_payment_methods:bank_details:<encryption_context_id>

The UUID is unique and non-editable. PostgreSQL and SQLite triggers reject
every attempt to change it after insertion. This prevents an attacker from
moving the context UUID together with copied ciphertext.

The UUID is cryptographic storage identity, not a customer-facing or billing
identifier. Existing integer primary and foreign keys remain unchanged.

### Exact read-time verification

The encrypted column's SQL select expression returns an internal JSON envelope
containing both the immutable context and ciphertext.
EncryptedJSONField.from_db_value() removes that envelope, constructs the exact
expected AAD, and supplies it to AES-GCM decryption. The behavior is identical
for model loads, values(), and values_list(); callers continue to receive the
original dictionary.

The field uses require_v2=True. Plaintext, v1 ciphertext, missing context,
malformed ciphertext, invalid decrypted JSON, and exact-AAD mismatches raise
DecryptionError. They never become a plausible None value.

Queries that need only Stripe card metadata explicitly defer bank details.
Direct bank-detail access and compliance auditing still fail loudly on
corruption.

### Primitive and maintenance hardening

- v2 decryption compares supplied and embedded AAD with hmac.compare_digest();
- empty AAD is rejected for new and existing v2 payloads;
- ciphertext uses strict RFC 4648 URL-safe base64 decoding;
- the AES-GCM instance cache is a locked, eight-entry LRU;
- reencrypt_with_aad validates exact row AAD, includes soft-deleted rows, uses
  compare-and-swap updates, and reports corrupt or changing rows instead of
  skipping them as healthy.

### Migration

Migration customers.0019:

1. adds a nullable context UUID;
2. assigns a unique UUID to every payment-method row, including soft-deleted
   rows;
3. accepts only the two known prior v2 contexts (primary-key-bound and the
   historical empty first-INSERT context), plus v1/plaintext compatibility
   inputs;
4. re-encrypts non-null bank details under the exact UUID context;
5. makes the UUID required and unique, enables v2-only field behavior, and
   installs the immutability trigger.

Unexpected AAD, unreadable ciphertext, invalid JSON, or concurrent row changes
abort the migration. Rollback re-encrypts each value under its prior
primary-key AAD before removing the UUID.

## Consequences

### Positive

- Same-field, cross-row ciphertext transplants fail on every ORM read.
- First INSERTs are fully row-bound without changing public identifiers.
- Corrupt ciphertext remains available for investigation.
- Key rotation cannot grow an unbounded in-process cipher cache.
- Existing Stripe-only workflows do not decrypt unrelated bank data.

### Negative

- Context-bound encrypted fields support only PostgreSQL and SQLite.
- Selecting the field requires a small JSON envelope expression in SQL.
- A corrupt protected value now raises and must be repaired explicitly.
- Plaintext dumpdata fixtures containing a context-bound field cannot be loaded;
  use database backups or sanitized fixtures instead.
- The migration is intentionally fail-closed and can block deployment until
  unexpected historical data is investigated.

## Threat Boundary

The design protects against ciphertext copying by a database writer that
cannot alter triggers or encrypt new values. It does not protect against a
database superuser that can disable DDL protections, or compromise of the
application encryption key.

## Rejected Alternatives

1. **Bind only to the integer primary key** - it is unavailable during the
   first auto-increment INSERT and would require an unsafe two-write window.
2. **Change payment methods to UUID primary keys** - unnecessary API and
   foreign-key migration blast radius.
3. **Store a mutable context UUID without a trigger** - an attacker could copy
   the UUID and ciphertext together.
4. **Return None on failure** - makes corruption indistinguishable from a
   legitimate null and enables destructive resaves.

## Related

- [ADR-0033](ADR-0033-encryption-architecture-consolidation.md) - AES-256-GCM
  architecture and key ownership
- GitHub issues #205, #267, and #268
