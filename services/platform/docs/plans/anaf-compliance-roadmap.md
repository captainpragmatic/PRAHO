# ANAF e-Factura compliance roadmap — what's mandatory, what's not, how to get there

Honest framing of the compliance gaps. Romanian e-Factura is **mandatory** for invoices to Romanian
businesses (since 1 Jan 2024) and consumers (since 1 Jan 2025); non-submission carries fines. This is
Romanian law, not a product choice. BUT the work is far smaller and more gated than the gap table
suggests. (Not legal advice — confirm the exact obligation/scope with the company's accountant.)

## The single most important fact: it's gated on an ANAF account
Everything in the "submission" bucket requires, as a hard prerequisite:
1. The company's **qualified digital certificate** registered in ANAF SPV (Spațiul Privat Virtual).
2. An **OAuth2 app** registered at anaf.ro/InregOauth → `client_id` + `client_secret`.
3. **Sandbox/test** credentials (`EFACTURA_ENVIRONMENT=test`).
Until these exist, the submission code **cannot be tested end-to-end** and shouldn't be written blind.
This is an admin/business step (hours of portal paperwork), not engineering. **It is Phase 0.**

## Bucketed verdict
| Item | Verdict | Gated on ANAF account? |
|---|---|---|
| ANAF submission (cert, OAuth, /upload, /listaMesajeFactura) | **mandatory** | YES |
| B2C `/uploadb2c` | mandatory **iff we have B2C (consumer) customers** | YES |
| Working-days deadline (OUG 89/2025) | mandatory (if submitting) — **codeable + testable NOW** | no |
| Electronic seal retrieval (download sealed XML/ZIP) | mandatory (if submitting) | YES |
| Archiving/retention (10 yr) | mandatory — but plain storage, e-Factura-agnostic | no |
| **Full Schematron (Saxon)** | **NOT needed** — ANAF validates server-side; native partial suffices | n/a |
| 6 correctness bugs | just bugs (5/6 fixed) | no |
| Refund lifecycle (#196) | separate product gap | no |

## Phased plan

### Phase 0 — Obtain ANAF credentials (BLOCKER, non-engineering)
Register the digital certificate in SPV + the OAuth app; get test-environment credentials. Nothing in
the submission bucket can be verified before this. **Do this first.**

### Phase 1 — Codeable + testable NOW (no ANAF account)
- **Working-days deadline (OUG 89/2025).** New `working_days.py::add_working_days(date, n)` using the
  `holidays` lib (Romania, incl. moveable Orthodox Easter); convert `issued_at` to Romania-local date;
  load holidays across the year boundary. Wire all three calendar-day sites (`efactura/models.py:411
  submission_deadline`, `efactura/service.py:366` query window, `efactura/settings.py:745`; relabel the
  setting at `:606`). TDD: pin 2026 RO holidays. **This is real legal compliance we can ship today.**
- **The ANAF response-parsing fixes that ARE unit-testable** (#123 gaps 1/3/4) against documented
  formats + recorded fixtures: `UploadResponse.from_response()` parses XML (`index_incarcare`,
  `ExecutionStatus="0"`); `/listaMesaje`→`/listaMesajeFactura`; `upload_b2c()` POST shape. These can be
  TDD'd with sample XML/mocked HTTP even though the LIVE round-trip needs the sandbox.

### Phase 2 — Submission (after Phase 0 credentials exist)
Implement + sandbox-verify the full flow: OAuth token exchange, `/upload` (B2B) + `/uploadb2c` (B2C)
with `standard=UBL`, status polling, download + **store the ANAF-sealed XML as the legal original**.
Resolve the content-type / standard-name unknowns (#123 gaps 2/7/8) against the live sandbox. This is
the well-scoped #123 backlog — ~1–2 focused weeks once credentials exist; mostly UNVERIFIABLE before.

### Phase 3 — Retention
10-year archival of the sealed XML + a retrieval path. Storage concern; can reuse existing object
storage. Small, independent.

### Explicitly dropped
Full client-side Schematron (Saxon). Keep the native partial validator as the pre-flight. Revisit only
if rejected-submission rates justify the 40MB native dependency.

## Recommendation
1. Start the ANAF SPV account process now (Phase 0) — it's the gate and it's not our code.
2. Ship Phase 1 (working-days deadline) now — real, legal, testable today.
3. Hold Phase 2 (submission) until sandbox credentials exist; don't write the live paths blind.
4. Don't build Schematron.
