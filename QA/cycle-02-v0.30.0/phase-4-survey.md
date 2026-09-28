# Phase 4 survey — routes, interactions, and what the gates are hiding

**Status:** survey complete, first instrument landed. Started 2026-09-26.

The plan's Phase 4 was a route and button sweep. Measuring first changed two of its premises, which is
now the third time in this programme that the measurement was the finding.

## 1. Route coverage — the portal is fine; the platform is not

Reproduce with `manage.py show_urls` per service, compared against every test file:

| Service | Named routes | Referenced by some test | Untouched |
|---|---|---|---|
| Platform | 396 | **306 (77%)** | 90 |
| Portal | 79 | **71 (90%)** | 8 |

The plan implied the portal route sweep was the gap. It is not — 8 untouched routes, two of them
`robots.txt` and `set_language`. The remaining six are worth tests: the recurring-payment withdraw and
subscription-toggle endpoints, the invoice and ticket search APIs, and two dashboard widgets.

The platform's 90 untouched routes concentrate in `promotions` (22), `provisioning` (18),
`infrastructure` (15) and `api` (10).

**Read this number the way the settings audit taught us to.** "Referenced by a test" is the same weak
criterion as "the key is referenced in app code" — it says a name appears, not that anything is
verified. The stronger question is below.

## 2. 51 tests request a page and assert only that it returned 200

`scripts/audit_test_assertion_quality.py`, baselined in `scripts/status_only_test_baseline.txt`.

The evidence for why this matters is from this repo, two weeks ago: `reports.html` returned 200 while
rendering none of four computed aggregates, and `vat_report.html` returned 200 with two dead context
keys and a 100× VAT error. A status-only assertion passes all three.

It closes a loop back to Phase 1. Coverage was measured wrongly **and** some of the tests filling it
assert nothing. `test_gdpr_dashboard_with_consent_date` sets `gdpr_consent_date`, renders the page and
checks only `200` — delete the date from the template and it still passes. The file's own docstring
states its purpose: *"Comprehensive tests for apps/audit/views.py to maximize coverage."* A coverage
number and a verification are different things, and this is what the difference looks like.

### Three attempts to draw the boundary, because two were wrong

Recorded because the pattern keeps recurring and the intermediate numbers were each briefly believed.

| Rule | Findings | Verdict |
|---|---|---|
| Any test asserting only a status | 118 | **Wrong.** 94 were mock assertions (`converge.assert_called_once_with(...)` is a far tighter pin than any rendered string) or authentication results, where a 200 IS the behaviour |
| Exempt any class that asserts a refusal anywhere | 24 | **Wrong the other way.** One login-redirect sibling exonerated every vacuous 200 in its class, including the two known-bad ones |
| Per test: did it vary something the response should show? | **51** | Domain setup, a payload or a query string means a condition was established and then unchecked. Only logging in means the 200 is the authorisation result |

Caught by spot-reading three findings rather than trusting the count — the same practice that turned 43
inert settings into 56.

**The residual, stated rather than left to be found:** a test that only logs in and renders is exempt,
so `test_renders_empty` — which asserts nothing about the empty state it is named for — is structurally
identical to `test_bearer_scheme_authenticates`. Only the name separates them, and a name is not a
contract. This check finds status-only tests that had a reason to assert more; it does not find every
page whose rendering is unverified. That gap belongs to the route sweep proper.

## 3. Four audit gates cannot fail

`Makefile` runs these with `|| true`, so each prints findings and exits 0. A gate that cannot fail is
the same defect class as a getter nobody calls, at the CI level.

| Gate | Suppressed today | Note |
|---|---|---|
| `lint_template_components.py` | **91 blockers** (27 TMPL001, 48 TMPL002, 11 TMPL003, 5 TMPL004) plus 551 TMPL005 warnings | The tool calls them blockers and prints *"Non-zero exit: 91 blocker violation(s)"* — into a pipeline that discards it |
| `audit_accessibility.py` | **136 violations** (A11Y003: 84, A11Y002: 51, A11Y008: 49, A11Y004: 1) | |
| `audit_dark_mode.py` | **70 violations** | |
| `error_handling_scan.py` | ~~5 HIGH~~ **0 — fixed, and the gate now blocks** | See §4 |
| `code_health_scan.py` | 0 | Already clean; the `\|\| true` is harmless here |

**And the template linter is portal-only** (`PORTAL_TEMPLATES` is its sole root), so the platform's 172
templates and `shared/ui`'s 25 are unlinted entirely. The 91 blockers are portal's alone; extending the
scope will raise the count before it falls.

## What lands next, in this order

1. ~~The 5 error-handling HIGHs, then remove that `|| true`.~~ **Done — §4.**
2. **Wire `audit_test_assertion_quality.py` into `make lint`** with its own detector tests, the way
   `test_settings_lint_detectors.py` covers the settings gate. It has already been wrong twice; a gate
   that blocks builds earns tests before it gates.
3. **The six untouched portal routes**, each with a content assertion.
4. **The 91 TMPL blockers**, then extend the linter to platform and `shared/ui` and remove the
   `|| true`. Largest item; the count will rise on extension before it falls.
5. **Accessibility and dark mode**, ratcheted rather than cleared in one pass.

## What the plan proposed and this survey does not

A GET-every-route smoke test asserting rendered content for 475 routes. The measurement says the
portal does not need it and the platform's gap is 90 routes in four apps, so a bespoke sweep is the
wrong shape: it would produce 475 assertions of varying worth and no gate. The status-only ratchet plus
per-app route tests for the four untested apps is the same coverage for a fraction of the code.


---

## 4. The five error-handling HIGHs — fixed, and the gate now blocks

### It was suppressed three times over, not once

The `|| true` was the visible layer. Underneath: `lint-security` is **not part of `make lint`** at all,
and both workflows that call it use `continue-on-error: true`. So a scanner reporting five HIGH
findings could not fail anything, anywhere.

The `continue-on-error` stays — it is justified by the comment beside it, *"Non-blocking until semgrep
is a stable dependency"*, and `security_scanner.py` on the adjacent line still reports CRITICALs that
need their own triage (several look like dev-settings test secrets). Removing it would block CI on
unrelated work. Instead the error-handling scan became its own target, `lint-error-handling`, wired in
as **Phase 9 of `make lint`** — which every PR does block on. Verified by reintroducing a swallow:
`make lint` fails at Phase 9 naming the exact finding, with Phases 0-8 passing, so nothing earlier
masks it.

**Phase 6 (code health) also ran with `|| true` while already reporting zero.** That is the more
insidious shape: a gate everyone believes is working, which will stay silent on the day it finds
something. Now blocking too.

### What each of the five actually was

Two were genuinely best-effort and two were not, which is why none of them could be fixed by rule.

| Site | Was | Now |
|---|---|---|
| `common/middleware.py:753` | `suppress(Exception)` around `session.flush()` in a security fail-safe | The line above it logs CRITICAL *"invalidating session for safety"*. If the flush failed, it was **not** invalidated and the request continued with a session a security check had just rejected — and the log still claimed otherwise. Now catches `DatabaseError` (the accurate set: `SESSION_ENGINE` is the db backend and `flush()` is clear + delete, no save) and logs that the invalidation itself failed |
| `infrastructure/registration_service.py:291, 303` | `suppress(Exception)` around `server.refresh_from_db()` | Genuinely cosmetic — the comment says so. Narrowed to `ObjectDoesNotExist, DatabaseError`: a concurrent delete or a connection blip is expected, an `AttributeError` is a bug and now surfaces instead of hiding behind "cosmetic" |
| `orders/views.py:221` | `except Exception: pass` around the per-customer VAT override lookup | **The money one.** A `DatabaseError` reading the tax profile produced a `CustomerVATInfo` dict *without* `is_vat_payer`, `reverse_charge_eligible` or `custom_vat_rate`, so the order silently took the country default — a wrong VAT rate on a Romanian fiscal document, with nothing logged. Now `ObjectDoesNotExist` only, matching `apps/api/orders/views.py:71`, which builds the same structure correctly. **Two sibling implementations of one thing, one of them already right** |
| `portal/orders/views.py:1388` | `suppress(Exception)` around `cache.delete(idem_key)` in a `finally` | A surviving key blocks the customer from retrying a failed payment for the full 300s, silently. Still broad and deliberately so — the cache backend is pluggable and Django's cache API defines no common exception — but logged, because the sin was the silence, not the breadth |

Three of the four change error-path behaviour, so each has a regression test, and each was
mutation-verified: reverting the fix fails exactly the named test while its paired
quiet-path test stays green.

### Two side findings, not fixed

- **The portal uses `LocMemCache` in every environment, production included.** So the payment
  idempotency key is per-gunicorn-worker and lost on restart: two workers do not see each other's
  keys, which is the opposite of what an idempotency guard is for. The settings file documents this
  tradeoff for rate limiting (*"effective rate limits are multiplied by worker count"*) but the same
  cache now also guards against double-charging, which is a different risk class.
- **`portal/apps/users/middleware.py:107` calls `request.session.flush()` unguarded.** Found because
  it broke the first version of the idempotency test — patching `cache.delete` globally made the
  session flush raise, and the error escaped from the middleware rather than the site under test. The
  scanner does not flag it (there is no suppression to flag), but a cache failure there is a 500.
