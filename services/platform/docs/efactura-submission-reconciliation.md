# e-Factura submission claims and unknown-outcome reconciliation

## Purpose

PRAHO must never upload the same immutable fiscal document twice merely because two workers ran or
because an ANAF response was lost. The local database can serialize PRAHO workers, but it cannot
atomically commit ANAF's remote acceptance and PRAHO's local result in one transaction. This
runbook defines that boundary and the fail-closed operator response.

This is the operational contract for issue #351. It deliberately does not implement automated ANAF
message reconciliation, response-archive redesign, or fiscal credit-note redesign.

## Submission lifecycle

1. In one short database transaction, PRAHO locks the invoice and its `EFacturaDocument`, then
   re-reads the current lifecycle state.
2. `submitted`, `processing`, and `accepted` are successful idempotent no-ops. `rejected` and
   `outcome_unknown` are terminal and cannot be uploaded again.
3. PRAHO generates and validates XML before claiming the upload. The exact XML bytes and SHA-256
   hash are frozen once the document enters `uploading`.
4. PRAHO stores a unique claim token and a ten-minute lease, commits, and only then performs the
   ANAF POST. A concurrent caller sees the committed `uploading` state and does not call ANAF.
5. The owning worker locks the document again and finalizes only if its token still owns the claim.

An explicit success becomes `submitted`; an explicit ANAF refusal becomes retryable `error`; an
ambiguous result becomes terminal `outcome_unknown`.

The short claim/finalize transactions are intentional. Holding a database lock during an external
HTTP request would make one slow ANAF call block unrelated database work and still would not solve
the crash-after-remote-acceptance boundary.

## What becomes `outcome_unknown`

- a timeout or connection loss during the upload POST;
- HTTP 408 or any 5xx upload response, because it does not prove that ANAF rejected the document;
- a nominally successful or otherwise malformed 2xx response that does not prove both the ANAF
  outcome and its required upload index;
- an unexpected exception after the committed claim and before a trustworthy result is recorded;
- a process crash or forced termination that leaves the ten-minute `uploading` lease to expire;
- an XML integrity mismatch detected while finalizing the claimed upload.

The upload client never automatically replays an ambiguous POST. Expired claims are discovered by
the normal pending-submission sweep and quarantined; they are not reclaimed or uploaded again.

## Operator reconciliation

1. Open the e-Factura dashboard and filter for **Reconciliation Required**. The detail page exposes
   the invoice, environment, immutable XML SHA-256, timestamps, and last error. There is no retry
   button for this state.
2. Record those values in the incident/audit case. Confirm that the configured ANAF environment and
   supplier CIF match the account being searched.
3. Search the authorized ANAF SPV/message history beginning before the claim time and covering any
   delayed messages.
4. Match the immutable invoice identity: supplier, buyer, invoice number, issue date, document type,
   currency, payable amount, and the submitted XML where ANAF exposes it.
5. If a matching ANAF upload/message exists, treat the invoice as remotely submitted and retain the
   ANAF identifiers and downloaded evidence in the incident. **Do not POST it again.** The local row
   remains quarantined until an audited reconciliation capability can record that remote fact.
6. If no match is found, do not infer rejection from an empty or temporarily delayed result set.
   Escalate for a second-person review of the full ANAF message window and evidence.

This PR does not provide a manual database override or a force-retry escape hatch. Never change
`status`, claim fields, XML, XML hash, or ANAF identifiers directly in the database. Doing so
destroys the evidence needed to decide whether a duplicate fiscal submission is possible.

## Audit and alerting expectations

- `efactura_upload_claimed` records the immutable hash, claim timestamps, environment, invoice, and
  document before network I/O.
- `efactura_submitted`, `efactura_submission_failed`, and `efactura_outcome_unknown` record the
  corresponding final local observation.
- Any `outcome_unknown` count greater than zero is an operator action queue, not a retry backlog.
- An `uploading` document older than its lease indicates a crashed or stalled worker and should
  converge to `outcome_unknown` on the next pending-submission sweep.

## Verification

The implementation is proved by lifecycle tests under SQLite and by the PostgreSQL concurrency test.
The live ANAF smoke test remains separately credential-gated.
