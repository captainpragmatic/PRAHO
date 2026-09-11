# Registrar contracts and deferred live validation

Issue #257 implements documentation-aligned adapters and durable asynchronous
operations. Its completion criterion is reviewed code and green offline/CI tests.
The PR closes #257 on merge. **Neither adapter has been live-validated by this
work.** Keep `REGISTRAR_ADAPTERS_VERIFIED=false` until the checks below are recorded.
The flag blocks mutations, including contact creation; read-only checks remain
available. It is a global gate: validate both configured adapters before enabling
it. Never enable the global flag solely because these fixture tests pass.

## Sources and confidence

Reviewed 2026-09-11:

| Adapter | Contract | Confidence and limitations |
| --- | --- | --- |
| Gandi | [Domain API](https://api.gandi.net/docs/domains/), [reference](https://api.gandi.net/docs/reference/), [sandbox](https://api.sandbox.gandi.net/docs/sandbox/), [authentication](https://api.sandbox.gandi.net/docs/authentication/) | Public documentation; synthetic contract tests. Sandbox supports .com, .net, .org and .fr; inbound transfer is not supported in sandbox. |
| ROTLD | ROTLD-authored *REST API*, revision 1.0.2, 2013-01-09, Radu Boncea, Public; [historical PDF mirror](https://pdfcoffee.com/rotld-rest-api-documentation-pdf-free.html) | Historical REST v2 contract explicitly selected for this implementation. Current registrar-access documentation and compatibility remain unverified. The original `rest2-test.rotld.ro/rest-api/RESTAPI%20DOCUMENTATION.pdf/at_download/file` URL is unavailable. The mirror is provenance, not a current service guarantee. |

`services/platform/tests/domains/fixtures/registrar_contracts.json` contains
synthetic examples and provenance. These are not recordings from registrar
accounts. Do not overwrite their provenance with a claim of live verification.

## Protocol behavior

Gandi uses HTTPS REST v5 and Bearer PAT authentication. Configure exactly
`https://api.gandi.net/v5` or `https://api.sandbox.gandi.net/v5`; sandbox requires
separate credentials. `api_username`, when present, is the organization
`sharing_id`, not a Basic-auth username. Registration, renewal, transfer,
nameserver and lock mutations acknowledge acceptance with HTTP 202. Empty or
malformed acceptance bodies still mean accepted. HTTP 200 validation/dry-run
responses never mean a completed mutation. A bounded same-origin `Location` is
retained as a reference; the worker never follows it or invents an operations API.
Domain details, including `dates.registry_ends_at` and the registry status array,
are the source of truth. Pending, held and unknown statuses do not activate a
pending domain.

ROTLD uses form POST commands with `command`, `format=json`, `lang=en`, and HTTP
Digest authentication. The selected historical sandbox API is
`https://rest2-test.rotld.ro:6080`; `registrar2-test.rotld.ro` is a web panel.
`https://rest2.rotld.ro` (443 or 6080) is an allowed production configuration, whose
actual endpoint and availability must be verified with ROTLD before use. No
fallback changes environment, host, protocol, credentials or TLS verification.

The `error`/`result_code` envelope decides business success even under HTTP 200.
Ownership denial is not domain absence. Contact creation returns `cid`; that ID
is persisted for this registration before `domain-register` uses `c_registrant`.
A contact is never globally reused across domains. Romanian companies require
CUI and registration number, Romanian individuals require CNP; these requirements
are provider-specific and are not imposed on Gandi. Phone numbers use
`+country.number`; Romanian `+40` E.164 numbers are normalized. Other international
numbers must already provide the dot separator. Contact PII and transfer secrets
are not copied into operation parameters or fixture recordings.

ROTLD registration and renewal use `domain_period`. Nameservers are a separate
`domain-reset-ns` command, at most six comma-separated hosts. Registering glue
hosts is outside this change; existing .ro host prerequisites must be verified.
A separate nameserver operation records any setup failure without losing the
registered domain. `domain-transfer` uses `authorization_key`; no transfer ID,
EPP code or expiry is fabricated. REST v2 does not document a lock mutation, so
lock changes return unsupported without an HTTP request. Naive registrar dates
are interpreted as Europe/Bucharest and converted to UTC; DST folds/gaps are
unconfirmed, never guessed. Legacy empty expiry dates remain unconfirmed.

The common outbound transport retains DNS pinning, hostname/TLS verification,
redirect refusal and bounded timeouts during Digest challenges. Registrar
policies disable connection-error fallback: even a dropped connection can occur
after a write was applied. The application never blindly retries an uncertain
mutation.

## Durable operations and review

Registration and renewal entry points require autocommit. They commit intent
before any chargeable HTTP request; callers inside an enclosing transaction must
enqueue work after commit. Existing paid-order provisioning already does this.
The registrar is contacted outside database locks.

Renewal tokens identify one intent and are stored as SHA-256 digests under a
unique registrar/domain/type/key constraint. Replaying a token survives cache
expiry and process restart. Staff forms and order items supply explicit tokens;
a tokenless legacy caller has one stable intent per duration and must adopt
explicit tokens for subsequent intentional renewals. A different intent is
refused while another renewal is unresolved. The paid order item remains
unprocessed, visibly requiring review/retry after the earlier operation resolves;
there is no automatic queue of chargeable renewals.

A fresh registrar expiry snapshot is committed before renewal dispatch. A failed or interrupted preflight may safely resume the same
intent because no mutation was dispatched. An atomic dispatch claim prevents two
resuming workers from sending the mutation twice. An
expiry advance confirms at most one intent, including across worker runs and
webhook races. Historical overlapping submissions require review. Older reads
cannot overwrite newer expiry evidence or trigger another chargeable renewal.

`submitted_at` records the dispatch boundary, not proof of acceptance.
`accepted_at` records an accepted response, even without a reference.
`review_required_at` means staff investigation is required; it does not mean
failure or permission to resubmit. Work starts reconciling after 15 minutes, then
hourly, or daily after 72 hours. Due timestamps keep old unresolved rows from
starving newer work. A not-found read never deletes an uncertain registration.
Only explicit rejection can release a newly attempted registration's name.

Migration 0009 keeps old intent keys null, backfills acceptance from existing
references, and returns prior timeout/reference-bearing failures to submitted
review. It does not invent completion or replay any request. Legacy pending
Domain rows acquire conservative review operations on the next sweep. Pending
contact work is not automatically retried. Only a never-dispatched nameserver
setup step may resume automatically after confirmed registration.

Review is surfaced once in the existing staff audit review queue. To investigate,
inspect DomainOperation records with `review_required_at` set,
their safe parameters, timestamps and reference. Use the registrar panel and
`domain_sync --dry-run` to compare current state. A sync read updates domain
state but does not authorize replay. Record provider evidence before resolving
ambiguous operations or retrying a paid item. Do not delete pending rows or clear
intent keys as a retry mechanism. A definitive rejection may be reviewed before
creating a new staff intent; an unresolved payment/renewal requires attribution
at the provider first.

## Offline verification

- `make test-file FILE=tests.domains`: adapter wire contracts, lifecycle, order
  wiring, polling, malformed responses, contact/setup partial failure, cache
  loss, crash recovery, and webhook races.
- `make lint` plus scoped Ruff/MyPy checks for changed modules.
- `make test`: full local regression suite.
- Integration CI runs `tests.domains.test_durable_operations` with PostgreSQL 16,
  including independent connections proving an in-flight intent blocks a second
  chargeable request. SQLite cannot establish that locking guarantee.

## Later live validation checklist

Use disposable domains, funded sandbox accounts and credentials provided through
normal encrypted configuration. Keep production credentials and records separate.
Capture sanitized request shapes, response status/headers/body fields, provider
operation references, panel state and expiry before/after. Never record PATs,
Digest secrets, EPP/authorization keys, CNP/CUI, addresses or personal contacts.

1. Verify endpoint, PAT/Digest permissions, TLS chain, port, organization/account,
   domain entitlement, balance and current API revision with each registrar.
2. Read availability and details. Confirm real status arrays, date formats,
   error envelopes and ownership-denial codes against the fixtures.
3. Submit one registration. Observe acceptance, polling and activation without
   fabricated expiry. For ROTLD, verify per-domain contact requirements and the
   separate nameserver step, including existing-host/glue constraints.
4. Submit one renewal. Verify the preflight expiry, one charge, one submitted
   operation, later expiry advance and replay of the same intent without another
   request. Then test a separate intentional renewal after confirmation.
5. Verify nameserver and lock semantics where documented. Confirm unsupported
   operations fail locally. Exercise transfers only in an environment the
   provider supports; Gandi sandbox does not support transfer-in.
6. Simulate response loss safely and verify that no duplicate write occurs,
   the domain remains tracked and reconciliation/review resolves the uncertainty.
7. Record findings, correct any contract mismatches and rerun offline tests.
   Enable `REGISTRAR_ADAPTERS_VERIFIED` only after all configured adapters are
   validated. This later operational validation does not reopen #257 by default;
   create a focused follow-up issue for any discovered discrepancy.
