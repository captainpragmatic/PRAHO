# e-Factura submission and response evidence

## Purpose

PRAHO must not upload the same immutable fiscal document twice merely because two workers ran or
because an ANAF response was lost. It must also retain exactly what ANAF returned, with enough
metadata to detect later storage corruption. This document is the operational contract for issues
#351 and #352.

## Submission lifecycle

1. In a short database transaction, PRAHO locks the invoice and its `EFacturaDocument`, then
   re-reads the lifecycle state.
2. `submitted`, `processing`, and `accepted` are successful idempotent no-ops. `rejected` and
   `outcome_unknown` cannot be uploaded again.
3. PRAHO generates and validates the XML before claiming the upload. The exact XML and SHA-256
   hash are frozen once the document enters `uploading`.
4. PRAHO stores a unique owner token and ten-minute lease, commits, and only then performs the
   ANAF POST. A concurrent caller sees the committed `uploading` state and does not call ANAF.
5. The owning worker locks the document again and finalizes only if its token still owns the claim.

An explicit success becomes `submitted`. An explicit refusal, including an authentication failure
before transmission, becomes retryable `error`. An ambiguous result becomes terminal
`outcome_unknown`.

Holding a database lock during network I/O would make a slow ANAF call block database work and
still would not solve a process crash after remote acceptance but before local commit. The short
claim/finalize transactions make that unavoidable distributed-systems boundary explicit.

## Unknown outcomes

The following observations do not prove that ANAF refused the document:

- timeout or connection loss during the upload POST;
- HTTP 408 or any 5xx upload response;
- a success-shaped response without the required `index_incarcare`;
- an unexpected exception after the claim was committed;
- a worker crash that leaves the ten-minute claim lease to expire;
- an XML-integrity mismatch while finalizing a claim.

The upload client never automatically replays those POSTs. Expired claims are found by the normal
pending-submission sweep and quarantined, not reclaimed.

## Operator reconciliation

1. Filter the e-Factura dashboard by **Reconciliation Required**. Record the invoice, environment,
   immutable XML SHA-256, claim timestamps, and last error in an incident/audit case.
2. Confirm that the ANAF environment and supplier CIF match the account being searched.
3. Search authorized ANAF SPV/message history from before the claim time through any delayed
   delivery window.
4. Match supplier, buyer, invoice number, issue date, document type, currency, payable amount, and
   submitted XML where ANAF exposes it.
5. If a match exists, treat the invoice as remotely submitted and retain the identifiers and
   downloaded evidence. Do not POST it again.
6. An empty or delayed result set is not proof of refusal. Require a second-person review before
   deciding that no remote submission exists.

There is intentionally no force-retry or direct-database escape hatch. Do not change status, claim
fields, XML/hash, or ANAF identifiers manually; that would destroy the evidence needed to assess
duplicate-submission risk. A controlled reconciliation command remains separate work from the
automatic submission safety boundary.

## ANAF response archive

For accepted documents, `/descarcare` returns a ZIP containing the fiscal XML and the Ministry of
Finance `semnatura_*.xml` payload. PRAHO:

- validates the archive and both well-formed XML payloads entirely in memory;
- rejects encrypted, duplicate, oversized, or excessive members;
- never extracts archive paths to the filesystem;
- stores the exact response bytes under `efactura/responses/.../*.zip`;
- records a SHA-256 digest and completion timestamp only after validation and storage succeed;
- reuses an existing archive only when its stored digest still verifies;
- retries missing accepted-document archives through a daily recovery sweep, keeping retries below
  ANAF's per-message daily download quota.

Migration `billing.0040` renames the old `signed_pdf` field without rewriting its storage keys, so
no historical reference is discarded. A legacy value may therefore still point to
`efactura/pdf/...` and has a blank digest/timestamp because PRAHO cannot truthfully invent integrity
metadata without reading and validating the underlying object. All new writes use the ZIP field,
path, digest, and timestamp.
