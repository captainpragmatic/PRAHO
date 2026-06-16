# Plan: complete ANAF e-Factura submission WITHOUT sandbox credentials (#123)

## The reframe (why this is possible)
The submission pipeline **already exists** and is wired end-to-end:
- **Client** (`efactura/client.py`): OAuth token exchange + caching, `upload_invoice`/`upload_credit_note` (`/upload`), `get_upload_status` (`/stareMesaj`), `download_response` (`/descarcare`), `list_messages` (`/listaMesaje`), `validate_xml`. Uses the vetted `safe_request`/`OutboundPolicy` boundary.
- **FSM** (`efactura/models.py::EFacturaStatus` + transitions): DRAFT → QUEUED → SUBMITTED → PROCESSING → ACCEPTED/REJECTED/ERROR (`mark_queued`/`mark_submitted`/`mark_processing`/`mark_accepted`/`mark_rejected`/`mark_error`).
- **Orchestration** (`efactura/service.py`): `submit_invoice`, `check_status`, `download_response`, batch workers `process_pending_submissions`/`poll_awaiting_documents`/`process_retries`.
- **Tests**: `tests/billing/efactura/test_client.py` already exists.

So #123's "8 gaps" are **defects in an existing pipeline against ANAF's documented contract**, not greenfield. The reason they were called "gated" is the *live oracle* (does ANAF accept it?) needs the account — but the *code* is verifiable against the **documented contract + recorded fixtures + mocked HTTP**. Creds then collapse to a single smoke-test pass.

## The without-creds verification strategy (the core idea)
1. **The ANAF contract is documented.** `client.py:13-14` cites the official PDFs; the response *formats* are published: upload returns an XML `<header index_incarcare="..." ExecutionStatus="0">`, `stareMesaj` returns JSON (`stare`), `descarcare` returns a ZIP (original + MF seal), `listaMesajeFactura` returns JSON, OAuth token is JSON.
2. **Hand-author recorded fixtures** from those documented formats under `tests/billing/efactura/fixtures/` (sample upload-XML-ok, upload-XML-error, stareMesaj-{nok,ok,processing}, descarcare.zip, listaMesajeFactura.json, token.json). Source bytes from ANAF's official examples during execution.
3. **Mock the HTTP boundary** (patch `safe_request`/`requests`) and assert, per operation: (a) REQUEST shape — URL, query params, headers, Content-Type, body; (b) RESPONSE parsing — correct field extraction; (c) FSM trajectory — the document advances to the right state; (d) error/timeout/retry paths.
4. **Make the genuinely-uncertain bits configurable** with documented defaults, so the live delta is a settings flip, not a code change.
5. **Defer exactly one thing to creds:** a single `@skipUnless(EFACTURA_LIVE_SMOKE)` integration test doing a real sandbox round-trip. Everything else is green now.

## Gap-by-gap doability without creds
| Gap | Sev | What | Without creds? |
|---|---|---|---|
| 1 | CRIT | Upload response parsed as JSON; ANAF returns XML | **FULLY** — rewrite parser + fixture test |
| 3 | HIGH | No `/uploadb2c` | **FULLY** — add method + request-shape test |
| 4 | HIGH | `/listaMesaje` → `/listaMesajeFactura` (+paginated) | **FULLY** — fix URL + test |
| 2 | MED | Upload Content-Type may need `text/plain` | **CODE-COMPLETE** — configurable default + shape test; live-confirm |
| 7 | MED | Standard name (UBL vs FACT1) | **CODE-COMPLETE** — configurable default UBL; live-confirm |
| 8 | LOW | Token-exchange Content-Type | **CODE-COMPLETE** — default `x-www-form-urlencoded`; live-confirm |
| 5 | — | CIUS-RO CustomizationID version | already RESOLVED (configurable, documented) |
| 6 | — | Working-days deadline | already RESOLVED (#197) |

## Phases (each its own TDD'd, lint+type-gated, PR-sized commit)

### Phase 0 — Fix the submission LIFECYCLE (CRITICAL, pre-existing, 100% local) — do FIRST
**Confirmed against code + flagged independently by two codex reviewers.** `submit_invoice` (service.py:97) creates the `EFacturaDocument` in `draft`, uploads to ANAF, then calls `mark_submitted()` whose FSM `source` is only `queued` (models.py:311) — `mark_queued` is never called on this path. So a SUCCESSFUL upload raises `TransitionNotAllowed`, falls into the generic `except Exception`, and for a first submission (`existing is None`) nothing is persisted: **ANAF received the invoice, PRAHO lost the `upload_index`, and the next retry re-sends it = double-send / fiscal-compliance risk.** It compounds with Gap 1 (the JSON parser yields `upload_index=""`).
1. Make one lifecycle: `mark_queued()` (or create directly as `queued`) BEFORE the upload call; persist the `upload_index` immediately on a successful POST, before any other fallible work.
2. Idempotency: treat `queued`/`submitted`/`processing`/`accepted` as retry-safe no-ops returning the existing document; only allow re-upload from explicitly retryable states (`error`/`rejected`); lock the `EFacturaDocument` row around the state decision (codex HIGH: submitted/processing currently re-upload).
3. Don't catch `TransitionNotAllowed` under the generic `except Exception` that swallows the upload index — handle FSM errors explicitly and never lose a known `upload_index`.
4. Fix the view crash: `views.py:2181/2207` read `result.message` but `SubmissionResult` exposes `error_message` (codex MED) → failed submit returns 500 instead of the error. Add failure-path view tests.
TDD: FSM trajectory tests with mocked HTTP — `submit` from draft → reaches `submitted` with a persisted `upload_index`; a second `submit` on a `submitted` doc is a no-op (asserts NO second `upload_invoice` call); upload-succeeds-then-local-failure never loses the index. This is the single most important fix and needs **zero credentials**.

### Phase 1 — Documented-contract defects (Gaps 1, 3, 4) — unambiguous, fully testable
1. **Gap 1 (CRIT):** rewrite `UploadResponse.from_response` to parse the XML `<header>` via lxml (`index_incarcare`, `ExecutionStatus="0"`=accepted-for-processing, `Errors/Error@errorMessage`), JSON-fallback retained for resilience. TDD against `upload-xml-ok` + `upload-xml-error` fixtures. This is the "crashes immediately" bug — highest value.
2. **Gap 3 (HIGH):** add `upload_b2c(xml, cif)` → POST `/uploadb2c?standard=UBL&cif={cui}`; wire from the existing B2C detector (`b2c.py`). Mocked-HTTP test on URL/params/body. Keep B2B `/upload` unchanged.
3. **Gap 4 (HIGH):** `list_messages` → `/listaMesajeFactura`; add `/listaMesajePaginatieFactura` paginated variant (`pagina` param). Mocked-HTTP tests for both.

### Phase 2 — Pin the uncertain bits as configurable defaults (Gaps 2, 7, 8)
Each becomes a setting with a documented default + a request-shape test + an inline `# live-verify against sandbox` marker:
- Gap 2: `EFACTURA_UPLOAD_CONTENT_TYPE` (default per docs).
- Gap 7: `standard` already a param; make the default a setting; document UBL vs FACT1/CII/RASP.
- Gap 8: `EFACTURA_TOKEN_CONTENT_TYPE` (default `application/x-www-form-urlencoded`).
The code is complete; only the *default value* is unverified — isolated and swappable.

### Phase 3 — Orchestration + seal/archival hardening against fixtures
1. **FSM trajectory tests** with mocked HTTP: `submit_invoice`→QUEUED→SUBMITTED; `check_status` PROCESSING→ACCEPTED (and →REJECTED, →ERROR/retry). Assert observable state, not mock calls (TDD Check 5).
2. **Seal retrieval:** parse the `descarcare` ZIP, extract the ANAF-sealed XML + signature, store as the legal original (begins archiving). Test against a recorded ZIP fixture.
3. **Idempotency** (addresses codex concerns): re-submitting an already-SUBMITTED doc is a no-op returning the existing `upload_index`; re-polling is safe; duplicate `index_incarcare` can't create two docs. Trajectory tests assert no double-submit.

### Phase 4 — The single creds-gated step (deferred)
One `@skipUnless(settings.EFACTURA_LIVE_SMOKE)` integration test: real OAuth token exchange + sandbox upload + poll + download. When the SPV account + OAuth app exist, run it, reconcile any contract delta (expected: only Gap-2/7/8 defaults), done. This is the ONLY irreducibly-gated item.

## What this delivers
- #123 Gaps 1, 3, 4: **fully closed**. Gaps 2, 7, 8: **code-complete, live-unverified** (one smoke test from done). Gaps 5, 6: already done.
- The submission pipeline is **provably correct against the documented contract**, green in CI, with **zero credentials**.
- When creds arrive, remaining work = run one smoke test + (likely) tweak 2-3 default strings.

## Risks + mitigations
- **Documented contract ≠ live reality** (content-type, exact XML shape). → configurable defaults, defensive parsers (tolerate namespace/attr variance), the smoke test isolates the delta to a small surface.
- **Hand-authored fixtures may not be byte-exact.** → source from ANAF's official examples; parse leniently; the smoke test is the final arbiter.
- **Over-building a path ANAF rejects.** → Phases 1/3 are pure contract+state-machine correctness (low reinterpretation risk); only Phase 2 carries live-value risk, and it's fenced to single settings.

## Process (per CLAUDE.md — touches OAuth + a submission state machine = compounding state)
- **Dual-review this plan (internal code-reviewer + codex) BEFORE execution.** Treat codex CRITICAL as a hard block.
- TDD each gap (RED against fixture first); lint + check-types every changed file incl. tests; full billing suite; per-gap commit; PR + squash-merge.
- Do NOT write the Phase-4 live paths blind beyond the single skipped smoke test.

## Out of scope (stays gated/deferred)
Live submission acceptance, real MF seal bytes, production OAuth registration (Phase 0 paperwork). Full Saxon Schematron (dropped; native validator suffices).

---

## v2 — post codex plan-review (verdict: REWORK). Corrections folded in before execution.
codex returned REWORK with CRITICAL findings (hard block per process). Verified against code; changes:

1. **Phase 0 is bigger — there are TWO FSM bugs, not one.** Besides `draft→mark_submitted(source=queued)`,
   the STATUS path is also broken: `get_awaiting_response()` (`models.py:376`) includes `SUBMITTED`, but
   `mark_accepted`/`mark_rejected` (`models.py:321/329`) only allow `PROCESSING→terminal`. If ANAF returns
   `ok`/`nok` on the FIRST poll of a `submitted` doc, `check_status()` (`service.py:210`) raises before
   persisting. Fix BOTH: allow `submitted→accepted/rejected` (or transition through `processing` inside the
   service before marking terminal). Phase 0 trajectory tests must cover the immediate-accept and
   immediate-reject first-poll cases.
2. **Add a conditional UNIQUE constraint on non-blank `anaf_upload_index`** (migration) so a lost-index retry
   can't create a second submitted row. Idempotency = no-op for `submitted/processing/accepted` returning the
   existing `upload_index`; re-upload only from `error/rejected`.
3. **Stop overclaiming.** Rename Phase outcomes: gaps are **"contract-fixture verified"**, NOT "fully closed",
   until the live smoke passes. The summary table's "FULLY" becomes "fixture-verified (live-pending)".
4. **Gap 1 is a silent-bad-state bug, not a crash.** `from_response` (`client.py:151`) treats HTTP 200 as
   success even when XML parsing fails and `upload_index` is empty. The new parser must REQUIRE
   `index_incarcare` AND a success `ExecutionStatus`; treat empty index as failure. Test matrix:
   200-XML-success, 200-XML-error, malformed-XML, empty-index, legacy-JSON-fallback.
5. **OAuth is a real auth-method bug (Gap 8 upgraded).** Per the official ANAF OAuth PDF, the token endpoint
   uses **Basic Auth** client authentication and `token_content_type=jwt` in the request body; the code sends
   `client_secret` in form data and omits `token_content_type`. Phase 2 must fix + test the auth METHOD
   (Basic Auth header + jwt content type), not just a content-type string. Phase 4 smoke needs a
   pre-authorized refresh/access token (cert-backed auth-code flow can't be automated headless).
6. **B2C is contract-sensitive, not a thin wrapper.** `B2CDetector` (`b2c.py:47`) is NOT wired into
   `submit_invoice`. Add SERVICE-level B2C routing + tests; document seller `cif` vs buyer `CNP` handling and
   the `/uploadb2c` params. Classify B2C live behavior as HIGHER risk (mark clearly).
7. **Seal archival: CUT from this plan (was over-scoped).** `download_response` (`service.py:247`) stores bytes
   as `signed_pdf`; `descarcare` returns a ZIP and there is NO sealed-XML field. Proper archival needs a new
   field + migration + retention policy + fixture provenance — its own issue. Phase 3 keeps only: parse the
   ZIP, extract the sealed XML, and ASSERT we can read it (no persistence change yet).
8. **Tests must be DB-backed, not `Mock(spec=EFacturaDocument)`.** Existing `test_service.py:137` uses mocks;
   Phase 0/3 trajectory tests use real `Invoice`+`EFacturaDocument` rows + a fake client, asserting persisted
   state (TDD Check 5), not mock call counts.
9. **Unify the config source FIRST.** `EFacturaConfig.from_settings` reads Django settings + `billing.efactura_*`
   while `efactura/settings.py` defines `efactura.*` keys. Pick one before adding content-type/standard settings.
10. **Fixture provenance required.** Each fixture records: official source URL, ANAF doc version/date, and
    whether bytes are EXACT (captured) or SYNTHESIZED (hand-authored from the spec).
11. **Drop the in-repo `CLAUDE.md` reference** (it's the operator's global file, not in this checkout); the
    dual-review discipline still applies via this codex pass.

**Net:** the thesis holds — most submission defects are fixable + fixture-verifiable without creds — but Phase 0
(the two FSM bugs) is the real headline and the riskiest local bug, and the plan must not claim "closed" without
the live smoke. Re-review after rework; execute Phase 0 first.
