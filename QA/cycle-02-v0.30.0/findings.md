# QA cycle 2 — findings

**Status:** in progress. Started 2026-09-26 on `fix/coverage-measurement-and-vat-timezone`; the
"Still open" ledger and the carried list were re-verified against `57e9c124` on 2026-10-06, after
32 commits had landed without this file moving. Dated corrections are inline; nothing earlier is
rewritten.
**Trigger:** one reported defect — enabling `system.maintenance_mode` on the platform produced no
maintenance experience in the portal. A logged-in customer saw no warning and found their tickets,
invoices and services simply *missing*; an anonymous visitor got the identical error to a wrong
password, with the login form fully enabled.

The brief was to bring that level of scrutiny to all 262 settings and to every button, link and
function in both services. What follows is what has been established so far, with the evidence.

## Accounting rules for this document

Cycle 1 (closed; read at `57e9c124:QA/cycle-01-v0.21.0/`) recorded "11/11 checks PASS" beside a body describing known breakage, because PASS was
doing duty for "I looked at it". This cycle uses four verdicts and never averages them:

| Verdict | Means |
|---|---|
| **PASS** | A named automated check asserts the behaviour and fails if it is reverted |
| **FAIL** | Established defect, with the evidence recorded here |
| **BLOCKED** | Cannot be checked yet, with the blocker named |
| **NOT-RUN** | Simply not attempted yet |

A finding is only PASS when the test that proves it is named. "Tests pass" is not evidence.

---

## 1. The measurement was wrong before the QA was

Coverage was broken four separate ways, each reproduced locally before being fixed
(#543).

| # | Defect | Evidence |
|---|---|---|
| 1 | Coverage loaded **no config at all** for either service. `coverage` does not walk up from `services/platform/`, and neither service's own `pyproject.toml` has a `[tool.coverage]` section, so `source`, `omit` and `branch` had never applied | `coverage debug config` reported `config_file: None` |
| 2 | `--parallel` **discarded every worker's data**. Django forks workers through multiprocessing; without `concurrency = multiprocessing` only the parent is measured, and the parent imports everything while executing almost nothing | A 16-test probe reported "No data to report" for the very module it exercises; after the fix the same probe put `apps/billing/config.py` at 55.10% |
| 3 | The nightly 88% **counted test files as covered source** — 1,931 `tests/` files against 1,044 `apps/` files, and test files are ~100% covered by construction. 153,126 statements against a true 70,261 | The `--fail-under=80` gate was not the guarantee it appeared to be |
| 4 | `omit = "*/settings/*"` **silently excluded the entire `apps/settings` app** — the subject of this whole effort. The pattern was meant for Django's `config/settings/` modules | Zero `apps/settings/` files appeared in any report |

**Result:** platform's real figure is **72.39%**, not the 28% shown on PRs nor the 88% shown
nightly. Per package: `billing` 88.44, `settings` 78.50, `users` 74.57, **`provisioning` 55.50**.
Portal's honest figure is the **union of its unit and browser suites, 72.02%** — its 63% unit
number is structurally capped, because `pytest.ini` sets `-p no:django_db`, the Makefile empties
`PYTHONPATH` so platform is unimportable, and 56 of 84 test files mock.

**A product bug fell out of the measurement work.** `vat_report` defaulted its period to
`timezone.now().date()` (UTC) while filtering on `created_at__date` (resolved in
`Europe/Bucharest`), so for three hours every night — 00:00 to 03:00 local — the Romanian VAT
compliance screen silently reported nothing for everything issued that local day, returning 200
throughout. Fixed in #543. It was caught only because those tests assert rendered figures
rather than status codes, which is this cycle's thesis demonstrated by accident.

### Root cause of the staleness, by 5 Whys

1. Why is `QA/` stale? It is a dated point-in-time report that was never re-run.
2. Why never re-run? `plan.md` is prose for a human to follow, not executable.
3. Why not made executable? Its *findings* became unit tests; the *walkthrough* did not.
4. Why not? The obvious answer is "no harness existed". **This why fails:** `scripts/e2e_stack.py`
   exists, boots both services, and performs a real signed portal→platform round trip.
5. So why did nothing migrate into it? Because the e2e suite had **no institutional standing** —
   excluded from CI by policy, reporting `--no-cov`.

**Root cause: effort invested in end-to-end QA was invisible to every gate in the project.** That
is why the walkthrough stayed manual, why it went stale, and why a setting could be "verified"
while its customer-facing consequence was untested. Fixed in #543: the browser suite runs
nightly, reports server-side coverage, and portal's floor is gated on the union.

**Correction, 2026-10-06: the sentence above was never true.** The `nightly-e2e` job #543 added
failed at its "Set up Node" step on every one of its first seven scheduled runs (2026-09-29 to
10-05), before Playwright was installed, because `actions/setup-node` with `cache: npm` and then
`npm ci` both need a `package-lock.json`, and `.gitignore` had excluded that file since the service
split — it existed on every developer machine and in no checkout. The workflow never runs on a pull
request, so its first execution was its first night, and a red scheduled job notifies nobody. The
root cause named in this section — invisible to every gate — recurred one level up, on the fix
itself. Tracked since 2026-10-06, guarded by `services/platform/tests/common/test_ci_node_lockfile.py` (red before,
green after), reproduced both ways in a Linux Node 20 container, and the suite passes locally at
`a4fab59b` (317 passed, 0 skipped, 9m25s, coverage reported). The first green nightly is the proof
this sentence lacked; `QA/README.md` now puts reading the nightly's real result before every gate.

---

## 2. Maintenance mode — FAIL, then fixed

The reported defect was one missing concept, not five bugs. `PlatformAPIError` carried
`is_rate_limited` with no `is_maintenance` sibling, and `handle_platform_error` — the single funnel
for every platform failure in every portal list view — therefore produced a template-visible flag
for exactly one status (429) and dropped 503 into `return {}`.

| Symptom | Precise cause |
|---|---|
| `/tickets/` showed "No Support Tickets Yet" | `rate_limit_feedback.py` → `tickets_table.html` `{% else %}` |
| `/billing/invoices/` was completely silent | `billing/services.py` swallowed and returned an empty page, so the view's `except` never ran |
| HTMX tab/search showed nothing at all | Three views passed no `fallback_message` |
| Login was byte-identical to a wrong password | `api_client/services.py` converted 503 to `None`, making the correct branch dead code for 503 |

Fixed in #544. **PASS** is now carried by
`tests/e2e/portal/test_maintenance_window.py`, which toggles the real setting through the
platform's own `/settings/save/` endpoint as staff and observes the portal — OFF → ON → OFF,
including that document counts survive the window.

Two paired root causes were fixed with it, because without them the defect recurs:
`config/settings/test.py` rebuilt `MIDDLEWARE` and omitted `MaintenanceModeMiddleware`, so no
Django test-client test could ever exercise the gate; and no maintenance test used an `/api/` path,
so ADR-0042's claim that maintenance mode is "enforced, not decorative" was verified only for the
staff browser surface.

### Three assertion attempts, because two were vacuous

Worth recording, since the same traps will recur. `assertContains(response, "disabled")` is
vacuous — `disabled:opacity-50` is in the markup unconditionally. Comparing total attribute counts
is also vacuous — the count rises either way, because the alert and error summary shift it. The
discriminating marker was `b" disabled>"`: 1 with the fix, 0 without.

---

## 3. Settings — 56 are editable and provably inert (54 since #589)

**This is the cycle's largest finding.** Phase 3 set out to write effect tests for settings that
had none; measuring first found something worth more.

**56 of 262 keys (21%) have no reachable production reader.** The pattern is identical in almost
all of them and is three lines long:

```python
_DEFAULT_X = 100                                                 # what the code enforces
X = _DEFAULT_X                                                   # what live logic reads
def get_x(): return SettingsService.get_integer_setting("app.x", _DEFAULT_X)   # uncalled
```

Live code compares against the module constant. The getter that would consult the operator's
configured value has no caller anywhere in production code. The existing consumer-contract check
passes on every one of them, because the key *is* referenced in app code — inside the dead getter. That is the gap between a key being present and a key having
consequences, and it is exactly how `system.maintenance_mode` shipped with nothing a customer
could see.

The full list is `scripts/settings_inert_baseline.txt`, gated by check 6 of
`scripts/lint_settings_coverage.py`. The first count was 43 and was too low for two reasons an
independent review found, both now fixed and both regression-tested in
`services/platform/tests/common/test_settings_lint_detectors.py`:

- **Name collisions.** The caller sweep matched a bare function name anywhere in the tree. Three
  modules define `get_task_time_limit()`; `customers/tasks.py` calls its own, and that call made the
  unused copies in `orders/tasks.py` and `provisioning/virtualmin_tasks.py` look live. References are
  now counted only in files that could actually import the definition. Four dead readers surfaced.
- **Tests counted as production.** The sweep included `services/platform/tests/`, so a getter called
  only from a test — or a key merely read back by a storage test — looked live.
  `audit.compliant_score_threshold` was exonerated by one `get_setting` call inside a validation
  test. Nine more surfaced once the check was scoped to production code, including
  `billing.subscription_grace_period_days`, described in the catalog as "days a customer can use
  service after payment failure", whose getter has no production caller at all. Subscriptions apply
  no grace period from that setting.

What the check can and cannot establish is now written into its docstring and its baseline header. The
criterion is static: a module-level, undecorated function, in a module with no dynamic dispatch, whose
name appears in no production file that could import it, and whose keys no other production reader
reads. A finding is "no reachable production reader found", not proof of runtime unreachability.
Decorated functions and `import_string`-style dispatch make it refuse to judge rather than guess.

The ones that matter most:

| Key | Why it matters |
|---|---|
| `security.registration_rate_limit_per_ip` | The code comment says "authoritative source is SettingsService". It is enforced nowhere |
| `orders.max_price_override_cents` | Cap on a staff manual price override. See §4 |
| `orders.max_price_override_multiplier` | Same |
| `products.max_price_cents` | Product price ceiling |
| `orders.max_payment_failures_before_fail` | Advertised "fail the order after N payment failures" |
| `users.credential_max_age_days` | Credential rotation age |
| `provisioning.ssh_timeout`, `provisioning.sudo_command_timeout` | Control-panel connection timeouts |

**Fixing one is a behaviour change, not a sweep.** Calling the getter changes what the system
accepts, so each needs its own decision and its own test. Deleting the key from the catalog is an
equally valid fix where the setting should never have been offered. This is deliberately NOT done
in this branch.

### Two measurement fixes were needed before any of it was visible

Both were the same defect as the coverage one: the detector rejected the style real code is
written in.

- **Check 4 (default drift) skipped every call site whose fallback was a named constant** — 118 of
  260, 45%. Check 2 tells you to move an inline fallback into a `_DEFAULT_*` constant, and check 4
  then stopped looking. The two checks worked against each other. Named fallbacks now resolve
  through module-level literals; 115 of 118 resolve and the 3 that do not are **counted, not
  dropped**. That surfaced **12 drifts**, 11 of them on inert getters — which is the tell: the two
  numbers drifted apart because no live path ever made them agree. `products.max_price_cents`
  reads `100_000_000` beside a catalog default of `10_000_000_000`, a factor of 100 on a price
  ceiling.
- **Check 5 (effect coverage) matched only a direct `update_setting("literal")` call.**
  `tests/settings/test_localisation_consumers.py` drives four localisation settings through
  customer forms, rendered dates and persisted addresses — about as thorough an effect test as this
  repo has — through a two-line `set_value` helper, and all four were reported untested. It also
  credited a **read** as a write, because a bare `key = "..."` pattern matches
  `get_setting(key="...")`; two keys held a false credit on that basis, one of them from a mock's
  `side_effect` comparison, which is a test that stubs the settings read — the opposite of an effect
  test. Write detection is now AST-based and resolves the helper's key *parameter position*, because
  assuming the first argument would credit `def write(value, key)` to the wrong string.

  Effect coverage was 56/262 measured wrongly, then reported as 68 and 77 — **and those were wrong
  too, in the other direction.** An independent review found the criterion combined "writes the key"
  and "reaches another app" across a whole FILE, never tying them to the same test. Eight keys held
  credit that way: `virtualmin.rate_limit_qps` was qualified by an unrelated dashboard request
  elsewhere in a settings-permissions file, and `audit.compliant_score_threshold` by a test that only
  checks validation rejects a negative score and never touches compliance classification.

  The criterion is now per test CLASS, and the observation must be of the key's **actual reader** —
  the production module that calls `SettingsService` for it, or one reachable within two import hops.
  That data was always available from `collect_settings_calls`; the check simply had not used it.
  Validated on both sides before being adopted: all eight false credits are rejected and none of the
  cycle's real effect tests is lost. The defensible figure is **56/262**, which is where this cycle
  started — the 21 keys that lost credit never had a test that drove the setting anywhere.

  What check 5 still cannot do is see assertions — strip every `assert` from a qualifying file and the
  credit survives. It measures the shape of an effect test, not its force, so the baseline is a floor
  on what has been attempted. That is written into the check and the baseline header rather than left
  for someone to discover.

**A correction, because the first version of this section was wrong.** I demoted the 12 drifts to
`low` on the reasoning that `get_setting` falls back to `DEFAULT_SETTINGS[key]`, making the caller's
inline argument unreachable for a catalog key. That is true of `get_setting` and false of the typed
wrappers. `get_integer_setting` returns the caller's `default` on `ValueError`/`TypeError`
(`services.py:475`), `get_decimal_setting` returns `default or Decimal("0")` (`:486`),
`get_list_setting` returns `default or []` (`:503`). A cached `None`, a stored value that will not
coerce, or a row written through a path that skipped validation all land on the caller's number. So a
drift is a live behavioural difference that shows up exactly when something has already gone slightly
wrong — the worst moment to also change a limit. Severity is back to **medium**, with the 12 recorded
in `scripts/settings_drift_baseline.txt`.

They are baselined rather than fixed because "align it to the catalog" is not a safe default here: the
drifting `_DEFAULT_*` constant is nearly always **also** read directly by the enforcing code through a
public alias. Aligning `products.max_price_cents` would raise a price ceiling 100×;
`provisioning.max_username_uniqueness_attempts` would cut collision retries from 1000 to 10;
`notifications.max_name_length` would start rejecting campaign names it accepts today. Each needs its
intended value established and a consumer test.

### Effect tests added

All five `critical=True` keys are now effect-tested (#545).
`integrations.smartbill_invoice_series` and `integrations.smartbill_tax_names` were merely
mentioned, never driven; each decides whether an invoice may be sent to SmartBill at all, and a
wrong tax name would put a legally incorrect VAT description on a Romanian fiscal document.
`test_smartbill_mapper.py` covers the mapper thoroughly but constructs `SmartBillAccountConfig`
directly, so it proves the mapper and cannot prove the settings. The new tests close that span:
setting → `_config_from_settings()` → `build_invoice_payload`.

**All ten `company.*` keys** now have effect tests
(`tests/settings/test_company_identity_effects.py`). Their consumer is not Python — it is
`{% setting %}` inside `templates/legal/privacy_policy.html` and `terms_of_service.html`, the pages
carrying PRAHO's legal identity for GDPR purposes — so the tests request the page and assert the
rendered text, with a paired default test and a cache test. That shape is what forced the detector fix
above: a render test imports nothing from `apps.` at all.

Writing them surfaced two more defects.

**`company.legal_name` only half-works.** The identity block of both legal pages honours the setting;
five prose sentences across the same two pages hardcode "PragmaticHost SRL" inside `{% blocktrans %}`
blocks. Change the setting and the Terms of Service names the configured company in its identity block
and a different company in the sentence saying who the agreement binds you to — a legal document
naming two entities. Not fixed here: interpolating the name rewrites five translatable msgids, which
costs the existing Romanian translations of legal prose, and that is a call for whoever owns them. The
defect is pinned by `LegalProseHardcodesTheCompanyNameTests`, which fails the day it is fixed — at
which point the test should be deleted.

The same class extends into the portal and cannot be fixed the same way: ten portal templates hardcode
`support@pragmatichost.com` or `privacy@pragmatichost.com`, and the portal has no business DB, so
`{% setting %}` does not exist there. Only 4 of 262 settings cross the HMAC boundary today (via
`/api/localisation/`). Making company identity available to the portal is a contract change, not a
template edit.

**A third variety of inert setting**, invisible to check 6. `company.email_noreply` is read by a live
method, so the getter is called — but
`getattr(settings, "DEFAULT_FROM_EMAIL", None) or SettingsService.get_setting("company.email_noreply", …)`
takes the Django setting, and every shipped settings module gives `DEFAULT_FROM_EMAIL` a non-empty
value. The left operand is never falsy, so the value is never used. Both branches are asserted in
`NoReplyAddressPrecedenceTests` rather than only the tidy one, because blanking
`DEFAULT_FROM_EMAIL` to show the setting "working" would hide the fact that no deployment reaches it.
Compare `apps/common/context_processors._maintenance_mode_active`, which gets the same precedence
right by testing `is not None` on a setting that may legitimately be unset.

---

## 4. FAIL — the staff price-override path has no validation at all (#542)

Found while triaging §3, and it is a security finding in its own right rather than a settings one.

1. `_validate_manual_price_override` in `services/platform/apps/orders/views.py` — which checks
   staff permission, a minimum, an absolute cap and a 10× multiplier bound — has **zero callers**.
2. `_process_order_item_creation` in the same file applies `manual_unit_price` **directly**: no
   permission check, no absolute cap, no multiplier bound.
3. The two settings that were meant to parameterise the caps are read only by getters nobody calls
   (§3), and the validator would not have read them anyway — it compares against module constants.

So the settings UI advertises a price-override cap, the code contains a validator for it, and
neither is connected to the path that applies the override.

**Not fixed here, deliberately.** Wiring the validator changes what a staff money path accepts, the
catalog and the code constant disagree by 2× so it is not yet established *which* cap is intended,
and the validator's own `staff_role in ["admin", "billing"]` check may duplicate or contradict the
view decorator already in place. This needs its own change with a plan review, per the money-path
rule. Tracked as **#542**, which also carries the third copy of the same policy at
`views.py:1412` that would need reconciling with the validator.

---

## 5. FAIL (minor) — a global context processor serving hardcoded identity

`romanian_business_context` is registered in `config/settings/base.py` and runs on every platform
template render. It returns 11 hardcoded values including `company_cui = "RO12345678"`, a fake CUI,
and calls `TaxService.get_vat_rate()` on every render.

Every one of those keys is read by **zero templates** across all three template roots
(`services/platform/templates`, `services/portal/templates`, `shared/`). The 15 apparent hits are
all dotted attribute access on a different object — `customer.company_name`, `order.currency.code`,
`form.company_name`.

It is therefore dead rather than wrong today, but it is one template line away from being wrong:
a future `{{ company_address }}` would silently render the hardcoded literal instead of
`company.address`. The fix is deletion, not wiring — wiring dead context keys to `SettingsService`
buys a per-render settings read for nothing.

---

## Still open

The first two columns are as written on 2026-09-28. The third is the re-verification of
2026-10-06, by the same rule: PASS names the test that fails if the fix is reverted.

| Item | 2026-09-28 | 2026-10-06 |
|---|---|---|
| Version bump to 0.30.0 | NOT-RUN | **Done** (#559). README badge reads `tests-11,000+`; still no coverage badge |
| The 56 inert settings | FAIL | **FAIL, 54.** The two `orders.max_price_override_*` keys became live in #589 and left `scripts/settings_inert_baseline.txt`; the other 54 remain, baselined and gated |
| The 12 fallback/catalog drifts | FAIL | **FAIL, 11.** `orders.max_price_override_cents` left `settings_drift_baseline.txt` in #589 |
| `company.legal_name` hardcoded in legal prose | FAIL | **FAIL.** Five `PragmaticHost SRL` literals remain in `templates/legal/` (4 ToS, 1 privacy); `LegalProseHardcodesTheCompanyNameTests` still pins it |
| Portal templates hardcoding company identity | FAIL | **FAIL.** Still ten portal templates |
| `company.email_noreply` shadowed by `DEFAULT_FROM_EMAIL` | FAIL | **FAIL.** `notifications/services.py:336-337` unchanged; `NoReplyAddressPrecedenceTests` pins it |
| Price-override path (§4) | FAIL | **PASS** (#589, 2026-10-02). `_validate_manual_price_override` is now called at `orders/views.py:242` and `:250`; `tests/orders/test_price_override_enforcement.py` (`CreatePriceOverrideTests`, `EditPriceOverrideTests`) fails if the calls are removed. #542 closed |
| `romanian_business_context` (§5) | FAIL | **FAIL.** Still registered at `config/settings/base.py:99` |
| Effect tests for the business zone | **PASS** | PASS, unchanged. The two `orders.max_price_override_*` keys now have effects and effect tests (`test_order_settings_effects.py`, extended in #589) |
| Effect tests for `integrations` (149 keys) and `advanced` (90) | NOT-RUN | **NOT-RUN.** `settings_effect_baseline.txt` still holds 56 keys. The catalog has grown since (277 `SettingDef` entries by grep at `57e9c124`), so the denominator is no longer 262 |
| Portal coverage 72.02% → 90-95% | NOT-RUN | **NOT-RUN, now 78.65%.** Union of unit (74%) and browser (56.44%) halves, computed locally at `a4fab59b` on 2026-10-06 with the nightly's own targets (`make test-e2e-coverage`, `coverage-portal`, `coverage-portal-union`, floor 70). Never yet computed in CI, because the nightly job never got that far |
| `provisioning` 55.50% → 80% | NOT-RUN | **NOT-RUN.** 56.82% on 2026-10-05 against a floor of 55 |
| Route and button sweep (398 platform + 80 portal named routes) | NOT-RUN | **Partly done.** Measured as 396 / 79 in `phase-4-survey.md` (the figures here were rounded from memory). The status-only ratchet is in `make lint` (#570, 51 baselined); #571/#572 added content-assertion tests for the two dashboard widgets and untested billing/infrastructure routes; the portal ticket-search API still has no test. TMPL blockers 73 (from 91), still behind `\|\| true`, linter still portal-only |
| Migrating `plan.md`'s 7 phases into `tests/e2e/portal/` | NOT-RUN | **Re-audited instead of migrated.** 23 of 47 checks fully asserted, 24 partly, 0 not at all — matching `plan.md`'s header. Check 1.2 is covered by `RootRedirectTests.test_authenticated_root_redirects_directly_to_dashboard` and `test_anonymous_root_redirects_to_login` (`services/portal/tests/common/test_root_redirect.py`); check 1.5 by `test_login_invalid_email_is_blocked_by_browser` (`tests/e2e/portal/test_navigation.py`) and `LoginErrorsTestCase.test_invalid_email_post_shows_field_error` (`services/portal/tests/users/test_login_errors.py`) |
| The nightly browser job (§1) | — | **Was FAIL 7/7 nights, fixed 2026-10-06** — see the correction in §1. First green run pending |
| Cycle 1 M5 — a service's Domains tab can never render | — | **FAIL, carried from cycle 1.** The portal POSTs `/services/{id}/domains/` (`portal/apps/services/services.py:332`); the platform API has never had that route, and the 404 is logged and flattened to `[]`. The browser test named for it asserts only "no Server Error", which this never produced |
| Cycle 1 L3 — currency formatting inconsistent | — | **FAIL, partly fixed.** The services list now uses `romanian_currency`; the order confirmation page and the gift-card payment partial still render period decimals, and `test_selling_currency.py` pins `10.00 EUR` on the confirmation page |
| Cycle 1 L6 — long service names truncated in the detail `<h1>` on mobile | — | **FAIL, cosmetic.** `templates/services/service_detail.html:48` still truncates; the e2e fixture name is too short to show it |
| Cycle 1 L1 — debug-toolbar console flood on unauthenticated pages | — | **FAIL by reading, dev-only.** `portal/config/settings/dev.py` still enables the toolbar for localhost and `/__debug__/` is not a public path; not re-run in a browser |

### Carried, deliberately unfixed, with reasons

Re-verified 2026-10-06; line numbers updated where the code moved.

- `portal/apps/common/decorators.py:227-236` (was cited as `common/decorators.py:77`) — a cold
  membership cache still yields a plain-text `403 Role not found`. **Still open.**
- `portal/apps/dashboard/views.py:180` (was `:149`) — `platform_available` is still never
  falsified in `dashboard_view`; degraded sections now go through `sections_unavailable` and the
  maintenance alert instead, so the flag and the red banner it gates are dead on that page.
  **Still open, cosmetic.**
- 502 and 504 share 503's response shape — **fixed in #544 itself**: `PlatformAPIError.is_maintenance`
  is now the narrower claim only the platform's gate may make, and `is_unavailable` carries 502/504
  (`api_client/services.py:116-143`). What #544 did not cover: a refused connection carries no status
  at all and still renders the list pages' empty state (see `plan.md` header). **Still open as a
  different defect.**
- Three money-critical `timezone.now().date()` sites that pick **VAT rates** by date —
  **fixed in #598** (2026-10-03): `tax_service.py` and `tax_models.py:134,145` use
  `timezone.localdate()`; `tests/common/test_tax_rate_local_date.py`
  (`RuleSelectionUsesTheLocalDateTests`, `CachedRateExpiresAtLocalMidnightTests`) fails on revert.
  **PASS.**
- `portal/apps/billing/schemas.py:135` (was `:134`) — still drives the customer-facing overdue flag
  from UTC. **Still open.**

---

## 6. Two settings that are live in code but shadowed in practice

Neither is inert by check 6's criterion — the getter is called — yet neither can take effect in a
normal deployment. Both were found by writing the effect test and watching it fail for the wrong
reason, which is the argument for writing them.

**`orders.bank_transfer_timeout_hours`.** The sweep repairs a missing proforma at `tasks.py:206`
*before* it computes the timeout at `:227`, and an offline order with a proforma anchors on
`proforma.valid_until`. So for any order with a positive total the `bank_transfer_fallback` branch is
unreachable, and the setting governs only an order whose proforma creation failed. The UI presents it
as the bank-transfer window. Both halves are pinned in
`tests/orders/test_order_settings_effects.py`: the setting does reach the deadline function, and the
sweep does create the proforma first.

**`company.email_noreply`.** Covered in §3 — `DEFAULT_FROM_EMAIL` is never falsy, so the `or` never
reaches it.

The common shape is a setting behind a precedence rule whose other side is always present. Check 6
cannot see either, because the read is reached; it is the *value* that is discarded. Worth a check 7
if a third turns up.
