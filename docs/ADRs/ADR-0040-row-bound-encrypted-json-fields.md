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

Customer payment bank details were the first production EncryptedJSONField
(the CNP columns followed; see the second addendum). They need row-level integrity without changing the public integer
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
- The migration runs atomically, so its safe all-or-nothing rollback is bought
  with a table-level lock: PostgreSQL's `ADD COLUMN` takes `ACCESS EXCLUSIVE` and
  holds it through the entire row-by-row re-encryption. Plan a maintenance window
  proportional to the size of `customer_payment_methods`; a very large table
  warrants a staged online migration instead.

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

## Addendum (2026-10-11): the CNP of a pending registration

`PendingRegistration.cnp_encrypted` holds the CNP a registration was submitted with until its
link is confirmed. It is a plain `TextField` with hand-written accessors (`set_cnp()`, `cnp()`),
not an `EncryptedJSONField`, and binds each value to its row the same way:

    users_pending_registrations:cnp_encrypted:<id>

- **Context.** The row's UUID primary key, generated before the first INSERT, so the row is
  stored with one write.
- **Reads always pass the expected AAD.** Without it, v2 decryption accepts whatever context
  the ciphertext embeds. A ciphertext moved from another row, an unbound v1 value, and plaintext
  all raise `DecryptionError`.
- **Failure spends the link.** `confirm()` creates no account without the CNP it was registered
  with, so an unreadable value refuses with `details_unavailable` and the link is used up.
- **No immutability trigger.** The id is not editable through the ORM. A database writer who
  rewrites a row's id has replaced the row: its link token, an HMAC of the id, changes with it.
  The rows live at most a day and the column is cleared when the link is used, so the trigger
  that protects long-lived payment methods buys nothing here.
- **Key rotation.** `reencrypt_with_aad` finds only `EncryptedJSONField` columns and skips this
  one. A retired key must stay in the keyring until every pending row encrypted under it is gone:
  the link lifetime plus the cleanup margin, 25 hours.

## Addendum (2026-10-11): the CNP on tax profiles, invoices and proformas

`CustomerTaxProfile.cnp`, `Invoice.bill_to_cnp` and `ProformaInvoice.bill_to_cnp` are
`EncryptedTextField`, a subclass of `EncryptedJSONField` for short strings. Each table has its own
`encryption_context_id` (UUID, set before INSERT) and an immutability trigger, created by
`apps.common.db_triggers` (customers 0004, billing 0010), as for payment methods.

- **Python value.** Always a string, "" when there is none. The column holds NULL for "", so
  the one-fiscal-identifier constraints test `bill_to_cnp IS NULL`. Assigning None stores "",
  through a descriptor that subclasses `DeferredAttribute`, so deferred loading still works.
  A string that looks like ciphertext is refused: the Python value is always plaintext.
- **Queries.** Only `__isnull`. A custom lookup treats a Python-side "" as NULL, so
  `validate_constraints()` agrees with the database. Nothing filters, orders or searches on a
  CNP, so there is no blind index.
- **Unbound writes.** `update(field=None)` clears a value without a model instance and is
  allowed; any other unbound write is refused, as for the parent field. Issued invoices still
  refuse it through their queryset guard.
- **Readers.** The staff customer list defers the CNP and shows only whether one is on file.
  Everything else reads the decrypted string unchanged: the fiscal-identity snapshot, e-Factura,
  the ROTLD registrant data.
- **GDPR erasure.** Anonymisation clears the CNP of the individual customers the user owns
  wherever it is not a fiscal record: the tax profile, every proforma (a proforma is not a fiscal
  document, whatever its status) and every invoice not yet issued. It uses queryset updates (no
  decryption, soft-deleted profiles included) and records one audit event per cleared row without
  the value. Issued invoices keep their snapshot for the legal retention period. A proforma
  converted after erasure produces an invoice without a CNP, so e-Factura states ANAF's
  placeholder for a Romanian individual, as it does for any customer whose CNP is unknown.
  Erasure audits only the rows its update cleared. It holds against writers that load the row
  under lock: invoice issuance, proforma conversion, provider finalisation and the staff proforma
  edit. A full save of a draft invoice from a copy loaded without a lock, if it is in flight while
  the erasure commits, can write the CNP back for that one request's window; the value stays
  encrypted. A document created from a tax profile read just before the erasure commits can carry
  the CNP the same way.
- **Not covered.** The issued e-Factura XML holds the CNP in plain text, in
  `billing_efactura_documents.xml_content` and in the stored XML file. It is the legal record sent
  to ANAF and kept for the retention period.
- **Blast radius.** These rows are loaded in full on many paths (customer dropdowns, EC Sales,
  line writes, proforma conversion). An unreadable CNP raises `DecryptionError` on each of them.
  Deferring cannot protect the paths that save an invoice, because the lock guard compares the
  stored CNP. A CNP becomes unreadable only through key loss or ciphertext tampering, the threat
  this ADR already accepts for bank details; the response is to restore the key or the row.
- **SQLite rebuilds.** A migration that alters one of these tables on SQLite drops its trigger
  and must create it again, after the change. `tests/common/test_migration_db_objects.py` turns
  red when a trigger is missing.

## Related

- [ADR-0033](ADR-0033-encryption-architecture-consolidation.md) - AES-256-GCM
  architecture and key ownership
- GitHub issues #205, #267, and #268
