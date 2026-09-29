# Staff workflows and promotions: implementation verification

Worktree: `/private/tmp/praho-staff-promotions-flows`
Branch: `fix/staff-promotions-flows`
Base: `58b9de4ee8d43f7773f3cab3aceecd4c227a21e5`

## Delivered behavior

- Staff domain management renders, combines filters, and retains them across pages.
- All eighteen promotion staff routes render. Fifteen missing templates were added.
  Campaign, coupon, batch, and automatic-offer forms validate and preserve values;
  only financial staff can change them.
- Audit Apply Filters and shared button attributes work in the browser. Attribute
  values stay escaped; arbitrary event-handler attributes remain rejected.
- Checkout uses signed, customer-bound promotion quotes and locked budget/usage
  reservations. BOGO, tiers, stacking, and original-value renewal credits share the
  same calculation path as order creation.
- Customers explicitly spend existing gift balances at checkout or on a billing
  document. Gift tender pays the tax-inclusive amount without reducing taxable value.
- Staff confirms the remaining cash payment. A stale amount cannot silently change
  the recorded payment, and a repeat submission returns the existing invoice.
- Split refunds preserve the original payment methods, resume unfinished work,
  restore gift value once, and retain confirmed provider results across local failure.
- Ledger transitions are audited, including conditional updates and the authenticated
  customer who authorized a gift reservation.

See [operation and rollout guidance](PROMOTION_OPERATIONS.md).

## Verification

Logs, browser traces, screenshots, local settings, and accounting artifacts are in
`logs/staff-promotions/`. Test databases and browser ports were isolated from the
normal development stack.

Repository checks use the canonical Make interface:

```sh
DJANGO_TEST_PROCESSES=8 make test
make lint check-types check-migrations lint-credentials
```

The PostgreSQL checks used temporary Make targets invoking `PYTHON_PLATFORM_MANAGE`
with the archived `qa_promotions_pg_settings` module and `--keepdb`. Browser scripts
used `PYTHON_SHARED` through temporary Make targets. The archived settings point only
to the disposable local QA databases. `source-manifest.json` records SHA-256 hashes
of the 111 changed code, template, configuration, and test files.

### Automated checks

| Check | Result | Evidence |
| --- | --- | --- |
| All promotions, invoice views, and audit registration on PostgreSQL | 238 tests passed | `final-review-green-complete.log` |
| Audit coverage contract | 5 tests passed | `audit-coverage-final.log` |
| Payment retries and existing gift settlement | 9 tests passed | `manual-payment-verified.log` |
| Invoice display and credit-note PDF/XML arithmetic | 30 tests passed | `invoice-display-green.log` |
| Full Platform suite | 9,653 tests run; passed with 35 skips | `full-suite-verified.log` |
| Full Portal suite | 1,258 passed, 3 skipped, 253 subtests passed | `full-suite-verified.log` |
| Counter store | 18 passed, 3 skipped, 8 subtests passed | `full-suite-verified.log` |
| Integration, deployment, and parity | 129 passed, 11 skipped, 3 subtests passed | `full-suite-verified.log` |
| Database cache | 9 passed, 1 skipped | `full-suite-verified.log` |
| Service isolation | 1 passed | `full-suite-verified.log` |
| Lint, types, and migration-state checks | Passed; 491 Platform and 85 Portal files type checked; no migration drift | `quality-verified.log` |
| Portal template comparison | 643 existing findings; no new findings | `templates-verified.log` |
| Credential checks | Passed for both services | `quality-verified.log` |
| Offline Semgrep | Seven local rules, 719 files, nine reviewed matches, no parse errors | `semgrep-local.json` |

The complete `make test` command exited **0** with all five phases successful.
The full lint/type/migration/credential command also exited **0**. A separate Ruff
invocation checked both services and the changed browser test with no violations
(`ruff-verified.log`). The Portal template baseline remains advisory debt, not a
clean strict-template result.

PostgreSQL tests include real concurrent attempts against a shared gift balance and
campaign budget, renewal settlement racing dunning, and refund settlement racing a
new payment failure. These verify the document/order/customer/subscription lock
order with real database locks. SQLite skips of PostgreSQL-only cases do not supply
that evidence; the separate PostgreSQL run does.

Regressions were observed before fixes: malformed button attributes, missing screens,
invoice line totals, refund backdrop interception, delayed local refund recovery,
missing ledger transition audits, missing customer attribution, and repeated staff
payment submission. `*-red.log` and the initial browser traces retain that evidence.

### Browser interactions

Both apps ran on ports 18700/18701 with real signed API communication and separate
customer/staff sessions. Chromium exercised:

- Campaign create, edit, pause, and reactivate; coupon restrictions persisted after
  edit; coupon batch creation; automatic-offer creation.
- Domain filters and page two; Audit Apply Filters query values.
- API-token creation, exact clipboard copy, and revocation of the local test token.
- Portal catalog, cart, coupon plus existing gift balance, checkout, and confirmation.
- Staff Record Payment using the remaining bank amount; invoice PDF download.
- Portal gift spending on an invoice and gift reservation on a proforma.
- Invoice and order refund dialog controls at desktop and mobile sizes.
- A full mixed bank/gift refund, reflected in the Portal without staff controls.
- Support staff read access, hidden edit controls, and a direct edit request denied
  with HTTP 403.

Evidence: `browser-flows.log`, `browser-settlement.log`,
`refund-modal-green.log`, `browser-final-assertions.log`,
`portal-refund-state.log`, and the corresponding `.zip` traces and `.png` images.
The refund POST returned 200 and the page reloaded to Refunded. An initial harness
attempt to read that response body after navigation failed; the follow-up browser
and database checks verified the completed operation without submitting it again.

Screenshots from the 2026-09-28 local browser run (before integrating the later
master release footer):

- [Staff promotions dashboard](screenshots/promotions/staff-dashboard.png)
- [Portal checkout with coupon and existing gift balance](screenshots/promotions/portal-checkout.png)

### Accounting checks

The browser-created order produced:

| Value | RON |
| --- | ---: |
| Gross service subtotal | 100.00 |
| Promotion discount | 10.00 |
| Taxable subtotal | 90.00 |
| VAT | 18.90 |
| Invoice total | 108.90 |
| Existing gift tender | 50.00 |
| Bank tender | 58.90 |

The order, proforma, invoice, PDF, and generated invoice XML reconcile to these
amounts. Invoice XML reports a payable amount of zero after settlement. A full refund
created exactly two completed legs for 50.00/58.90 and restored the gift balance once.
The original invoice remained unchanged. A local draft credit note and PDF contain
the opposite subtotal, discount, tax, and total. Repeating creation returns the same
credit-note record. Credit-note XML arithmetic is covered separately by the automated
tests; no accounting-provider or ANAF submission was made.

Evidence: `browser-document-evidence.log`, `browser-refund-evidence.log`,
`checkout-invoice.pdf`, `checkout-invoice.xml`, and `checkout-credit-note-draft.pdf`.

## Scope and limits

Customer gift-card purchases and their public Stripe initiation endpoints are outside
this change. They are approved for a separate follow-up alongside the configurable
selling-currency policy. Existing funding service/staff scaffolding is not a completed
public purchase flow.

The online Semgrep rule fetch was rejected by automatic approval review because it
could send repository metadata to `semgrep.dev`. An offline scan used seven explicit
local rules with metrics and version checking disabled. Its seven CSRF-exempt matches
have explicit service HMAC/signature checks; its two SQL matches use a literal table
name and bound values in an existing migration. Those matches do not establish a new
high or critical vulnerability. This limited scan does not replace the full community
ruleset. Repository heuristic scanners also include pre-existing and test-fixture
matches; their labels are not treated as verified severities.

No production deployment, firewall test, SMTP delivery, real Stripe charge/refund,
or live accounting-provider delivery was performed. Local bank refunds record staff
accounting actions; they do not move money through a banking network. Provisioning
completion used a local fixture transition, without a provider call.

Both QA servers were stopped, the temporary PostgreSQL container was removed, and
the four QA settings modules were archived outside the service source directories.
At the end of that verification session, the changes remained uncommitted in the
separate worktree. The subsequent PR preparation is recorded below.

## PR preparation: 2026-09-29

All 111 code, template, configuration and test files matched the recorded source
manifest before the local checkpoint. The commit hooks normalized formatting and two
test lint findings. Signed commit `9e4dceda` preserves that checkpoint.

Current master (`9df033f5`) was integrated using an ordinary three-way merge. The only
conflict was the parity test moved to `tests/integration/` on master; the new button
attribute parity assertion was moved with it so the integration runner collects it.
The later public API markers, proforma rollback fix, billing signal fixes, Portal
maintenance handling and checkout error translations remain in the combined tree.

Reviewing the browser evidence identified a misleading payment-balance panel on
refunded invoices and closed/expired proformas. Payment actions were already blocked;
the panel now follows the same payable-document decision. New view tests failed for
all eight closed/expired cases before the template fix. Afterward the focused Portal
module passed all five tests and ten subtests, including issued/overdue balances and
retry-key preservation (`pr-closed-balance-red.log`, `pr-closed-balance-green.log`).
