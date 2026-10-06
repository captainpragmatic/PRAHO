# PRAHO Portal QA Walkthrough Plan

> **Status: living spec, promoted from cycle 1 (2026-09-26); enforcement re-audited check by check
> on 2026-10-06.**
>
> This document is no longer a one-off walkthrough script. It is the checklist each cycle works
> against, and the table below records which automated test now enforces each phase — because the
> reason cycle 1 was never re-run is that its walkthrough stayed prose while only its *findings*
> became tests. A phase with a test beside it still needs a human for the named gaps: of the 47
> numbered checks, **21 are fully asserted** by a test, **24 partly** (the page is reached and the
> main behaviour asserted, but one or two named elements are not), and **2 not at all** — 1.2 root
> redirect and 1.5 login-form validation. Phase 4 is the only one close to needing no re-walk.
>
> | Phase | Enforced by `tests/e2e/portal/` | Asserted / partial / none |
> |---|---|---|
> | 1 — Authentication & public pages | `test_cookie_consent.py`, `test_navigation.py`, `test_rate_limit_ux.py` (1.6), `test_password_recovery_workflow.py` (1.8) | 3 / 4 / 2 |
> | 2 — Dashboard | `test_dashboard.py` | 0 / 2 / 0 |
> | 3 — Profile & account management | `test_customer_company.py`, `test_customer_users.py`, `../test_localisation.py` (3.1 timezone) | 5 / 6 / 0 |
> | 4 — Billing | `test_customer_billing.py`, `test_customer_invoices.py` | 6 / 1 / 0 |
> | 5 — Orders / product catalog | `test_signup_order_flow.py`, `test_cart_flow_regression.py`, `test_order_flow_bugs.py`, `test_order_flow_compliance.py`, `test_order_flow_ux.py` | 2 / 5 / 0 |
> | 6 — Hosting services | `test_customer_services.py`, `test_customer_provisioning.py`, `test_service_request_workflow.py` (6.5), `test_filter_tabs_portal.py` (6.2) | 1 / 4 / 0 |
> | 7 — Support tickets | `test_customer_tickets.py`, `test_navigation.py` (7.5, 7.6) | 4 / 2 / 0 |
>
> `test_maintenance_window.py` and `test_customer_addresses.py` enforce no numbered check — the plan
> has no maintenance or address check; that is a gap in the plan, not in the tests. The checks whose
> wording no longer matches the product are corrected inline below (2.1, 3.3, 3.6, 3.9, 5.4, 5.7,
> 6.4, 7.1).
>
> `make test-e2e-coverage` runs the whole `tests/e2e/` tree — portal, platform, ORM and infra — and
> the 21 `tests/e2e/portal/test_*.py` files plus `tests/e2e/test_localisation.py` are the portal's
> share of it. The whole tree passed locally at `a4fab59b` on 2026-10-06: 317 tests, 0 skipped,
> 9m25s. The nightly job meant to run it (#543, `e974d801`) **failed at Node setup on each of its
> first seven nights** — see [`README.md`](README.md) — so nothing in this file may cite a nightly
> result until one exists.
>
> **No unexpected empty state**, the check cycle 2 showed matters most, is now asserted for one
> surface: `test_maintenance_window.py` toggles the real `system.maintenance_mode` and checks
> `/billing/invoices/` keeps its rows and shows the maintenance notice instead of "No documents
> found". It is still *not* asserted for `/tickets/`, `/services/`, the dashboard, detail pages or
> the HTMX partials, and no test covers an **undeclared** outage: a refused connection raises a
> `PlatformAPIError` with no status code, only 502/503/504 count as "unavailable", so `/tickets/`
> still renders "No Support Tickets Yet" when the platform process is simply down
> (`apps/api_client/services.py:511-513`, `apps/common/rate_limit_feedback.py:159-162`). That is
> product behaviour as well as a test gap, and it is the next thing to close.
>
> Cycle evidence: [`cycle-01-v0.21.0/`](cycle-01-v0.21.0/) (v0.21.0, executed) ·
> [`cycle-02-v0.30.0/findings.md`](cycle-02-v0.30.0/findings.md) (current).

## Context

We need a full manual QA walkthrough of the Portal service (localhost:8701) using Chrome browser automation (claude-in-chrome MCP). The portal is a stateless Django frontend that proxies to the Platform service via HMAC-signed requests. This walkthrough will visit every page, test every form, click every button, take screenshots, check server logs, and document all findings in a `QA/` folder.

**Scope**: Portal only (Platform walkthrough deferred to a later run).

---

## Pre-requisites

1. **Start services**: Run `make dev` in background (platform :8700 + portal :8701). The enforcing
   tests use a *different* stack, `make dev-e2e` (own SQLite, rate limiting off, no workers), on the
   same two ports — a human walk and the suite therefore never see the same data, and the e2e stack
   refuses to start while `make dev` holds the ports.
2. **Load fixtures**: Run `make fixtures` to seed demo data (users, products, invoices, services, tickets).
   `make dev` already runs the same command at start-up.
3. **Create the cycle folder** (`QA/cycle-NN-vX.Y.Z/`; cycle folders are frozen once the cycle closes):
```
QA/
├── plan.md                     # This spec, carried forward and corrected
├── README.md
├── cycle-NN-vX.Y.Z/
│   ├── qa_report.md            # Findings, in the four verdicts
│   └── action_log.md           # Step-by-step log of every action taken
├── screenshots/<phase>/        # gitignored — evidence lives on the machine that ran the cycle
└── logs/                       # gitignored — server-log checkpoints A-D + final, console_errors.log
```

## Test Credentials

| Service | Email | Password |
|---------|-------|----------|
| Portal (primary) | `e2e-customer@test.local` | `test123` |
| Portal (fallback) | `customer@pragmatichost.com` | `testpass123` on `make dev`; `admin123` on the e2e stack (`apps/common/e2e_fixtures.py`) |

## Team Architecture

| Agent | Role | Mode |
|-------|------|------|
| **Browser Agent** (main) | Navigate pages, interact, screenshot | Sequential (Chrome MCP) |
| **Log Watcher** | Check `make dev` output for errors at checkpoints | Background, parallel |
| **QA Documenter** | Compile findings into `qa_report.md` | Runs after all phases |

---

## Screenshot Naming: `{phase}_{page}_{state}.png`

## Action Log Format (action_log.md)
```
### [TIMESTAMP] Phase X.Y - Page Name
- URL: http://localhost:8701/...
- Action: navigated / clicked / typed / submitted
- Result: SUCCESS / FAILURE / WARNING
- Screenshot: filename.png
- Console errors: none / [list]
- Server errors: none / [list]
- Findings: [observations]
```

## QA Report Entry Format (qa_report.md)
```
### [PHASE-PAGE] Page Name
- URL: `http://localhost:8701/url/`
- Status: PASS | FAIL | WARN
- Layout: OK | BROKEN | MISSING ELEMENTS
- Forms: PASS | FAIL (describe)
- HTMX: PASS | FAIL | N/A
- Console Errors: NONE | [list]
- Screenshots: [filenames]
- Notes: [findings]
- Severity: CRITICAL | HIGH | MEDIUM | LOW
```

---

## Phase 1: Authentication & Public Pages (9 checks)

### 1.1 Health Check
- **URL**: `/status/`
- **Check**: JSON `{"status": "healthy"}` renders

### 1.2 Root Redirect
- **URL**: `/`
- **Check**: Redirects to `/login/` when unauthenticated

### 1.3 Cookie Policy
- **URL**: `/cookie-policy/`
- **Check**: Dark theme renders, cookie categories listed, consent banner appears
- **Screenshots**: `01_cookie_policy_full.png`, `01_cookie_policy_bottom.png`

### 1.4 Login Page (Empty)
- **URL**: `/login/`
- **Check**: Logo renders, email/password fields, remember me checkbox, forgot password link, register link
- **Screenshot**: `01_login_empty.png`

### 1.5 Login Validation Error
- **Action**: Submit with `notanemail` / `short`
- **Check**: Validation fires, error messages shown
- **Screenshot**: `01_login_validation_error.png`

### 1.6 Login Wrong Credentials
- **Action**: Submit with `wrong@example.com` / `wrongpassword`
- **Check**: Generic error (no user enumeration), stays on `/login/`
- **Screenshot**: `01_login_invalid_credentials.png`

### 1.7 Login Success
- **Action**: Submit with `e2e-customer@test.local` / `test123`
- **Check**: Redirects to `/dashboard/`, nav bar appears with all links
- **Screenshots**: `01_login_filled.png`, `01_login_success_redirect.png`

### 1.8 Password Reset
- **URL**: `/password-reset/`
- **Check**: Form renders, submit shows success message
- **Screenshots**: `01_password_reset_empty.png`, `01_password_reset_submitted.png`

### 1.9 Registration (Inspect Only - DO NOT SUBMIT)
- **URL**: `/register/`
- **Check**: All sections visible (Personal, Company, Address, GDPR Consents), org type toggle works (SRL shows VAT, Individual shows CNP)
- **Screenshots**: `01_register_empty.png`, `01_register_company_section.png`, `01_register_consents.png`

### Log Checkpoint A
- Check `make dev` output for errors after Phase 1

---

## Phase 2: Dashboard (2 checks)

### 2.1 Main Dashboard
- **URL**: `/dashboard/`
- **Check**: Welcome greeting, 4 stat cards (Services / Open Tickets / Account Status / Next Billing — there is no invoices card; Next Billing is the literal "End of Month"), recent invoices section, recent tickets section, quick action buttons, footer version badge (hardcoded `Version 0.30.0` in `base.html`; nothing asserts it)
- **Screenshots**: `02_dashboard_full.png`, `02_dashboard_bottom.png`

### 2.2 Account Overview
- **URL**: `/dashboard/account/`
- **Check**: Email, Customer ID, Company Name, Tax ID, quick links
- **Screenshot**: `02_account_overview.png`

---

## Phase 3: Profile & Account Management (11 checks)

### 3.1 Profile Page
- **URL**: `/profile/`
- **Check**: Form fields (first/last name, email disabled, phone, language, timezone, notifications), company grid, GDPR section
- **Action**: Edit first name, save, verify success toast
- **Screenshots**: `03_profile_view.png`, `03_profile_save_result.png`

### 3.2 Company Profile (Read-Only)
- **URL**: `/company/`
- **Check**: Company details displayed, Edit button present
- **Screenshot**: `03_company_profile_view.png`

### 3.3 Company Profile Edit
- **URL**: `/company/edit/`
- **Check**: Pre-filled fields, save persists. The page no longer carries country or VAT inputs — tax identity lives at `/company/tax/` and addresses at `/company/addresses/`, neither of which this plan walks yet
- **Screenshots**: `03_company_edit_form.png`

### 3.4 Create Company (Inspect Only - DO NOT SUBMIT)
- **URL**: `/company/create/`
- **Check**: All fields render, terms checkbox required
- **Screenshot**: `03_company_create_empty.png`

### 3.5 Change Password
- **URL**: `/change-password/`
- **Check**: 3 fields render, mismatch validation works
- **Screenshots**: `03_change_password_empty.png`, `03_change_password_mismatch.png`

### 3.6 MFA Management
- **URL**: `/mfa/`
- **Check**: MFA status badge, TOTP setup link (the "last login" row was removed, not populated — cycle 1 M2)
- **Screenshot**: `03_mfa_management.png`

### 3.7 MFA TOTP Setup (Inspect Only - DO NOT ENABLE)
- **URL**: `/mfa/setup/totp/`
- **Check**: QR code renders, secret key shown, 6-digit input field
- **Screenshot**: `03_mfa_totp_setup.png`

### 3.8 MFA Backup Codes
- **URL**: `/mfa/backup-codes/`
- **Check**: Graceful empty state if MFA not enabled
- **Screenshot**: `03_mfa_backup_codes.png`

### 3.9 Privacy Dashboard
- **URL**: `/privacy/`
- **Check**: 2 read-only consent badges, data export link (the consent date renders on `/consent-history/`, not here)
- **Screenshot**: `03_privacy_dashboard.png`

### 3.10 Data Export
- **URL**: `/data-export/`
- **Check**: Export interface renders without error
- **Screenshot**: `03_data_export.png`

### 3.11 Consent History
- **URL**: `/consent-history/`
- **Check**: History table or empty state
- **Screenshot**: `03_consent_history.png`

### Log Checkpoint B
- Check `make dev` output, focus on HMAC failures and template errors

---

## Phase 4: Billing (7 checks)

### 4.1 Invoice List
- **URL**: `/billing/invoices/`
- **Check**: Header stats, filter tabs (All/Invoices/Proformas), search input, table columns, status badges, pagination
- **Screenshot**: `04_invoices_list_loaded.png`

### 4.2 Invoice Search (HTMX)
- **Action**: Type search term, verify HTMX updates in-place
- **Screenshot**: `04_invoices_search_active.png`

### 4.3 Invoice Tab Filters (HTMX)
- **Action**: Click each tab, verify results change
- **Screenshots**: `04_invoices_tab_invoices.png`, `04_invoices_tab_proformas.png`

### 4.4 Invoice Detail
- **URL**: `/billing/invoices/{number}/` (get number from list)
- **Check**: Header, bill-to, line items, tax breakdown, PDF download button, refund button (if paid)
- **Screenshots**: `04_invoice_detail_top.png`, `04_invoice_detail_line_items.png`

### 4.5 Invoice PDF Download
- **Action**: Click Download PDF, verify download initiates
- **Screenshot**: `04_invoice_pdf_triggered.png`

### 4.6 Proforma Detail
- **URL**: `/billing/proformas/{number}/`
- **Check**: Same layout as invoice, no refund button, PDF link works
- **Screenshot**: `04_proforma_detail.png`

### 4.7 Billing Sync
- **Action**: Click Sync button (if visible), verify response
- **Screenshot**: `04_billing_sync.png`

### Log Checkpoint C
- Check for PDF generation errors, HMAC failures on billing APIs

---

## Phase 5: Orders / Product Catalog (7 checks)

### 5.1 Product Catalog
- **URL**: `/order/`
- **Check**: Breadcrumb (step 1), product type tabs, product cards with pricing, cart widget, trust signals
- **Screenshots**: `05_catalog_all.png`, `05_catalog_filtered.png`

### 5.2 Product Detail
- **URL**: `/order/products/{slug}/` (click from catalog)
- **Check**: Name, description, pricing table, Add to Cart form
- **Screenshot**: `05_product_detail.png`

### 5.3 Add to Cart
- **Action**: Click Add to Cart on a product
- **Check**: Cart count updates, confirmation shown
- **Screenshot**: `05_add_to_cart_result.png`

### 5.4 Cart Review
- **URL**: `/order/cart/`
- **Check**: Breadcrumb (step 2), items list, quantity controls (HTMX), totals (subtotal + VAT 21% + total), "Continue to checkout" button
- **Screenshots**: `05_cart_review.png`, `05_cart_quantity_updated.png`

### 5.5 Mini Cart Widget
- **Action**: Click cart icon in nav on catalog page
- **Check**: Dropdown opens with HTMX content, shows items + links
- **Screenshot**: `05_mini_cart_open.png`

### 5.6 Checkout
- **URL**: `/order/checkout/`
- **Check**: Breadcrumb (step 3), preflight validation, order summary, terms checkbox
- **Screenshot**: `05_checkout_page.png`
- **Note**: DO NOT complete payment

### 5.7 Service Plans
- **URL**: `/services/plans/`
- **Check**: Plans grid, pricing, order CTA buttons. Known gap: the "Upgrade Plan" button has no href or handler (`templates/services/plans_list.html:159-161`), and the test asserts headings only
- **Screenshot**: `05_service_plans.png`

### Log Checkpoint D
- Check for cart/order errors, HMAC price sealing issues

---

## Phase 6: Hosting Services (5 checks)

### 6.1 Service List
- **URL**: `/services/`
- **Check**: Header stats, status filter tabs, search, table columns, status badges
- **Screenshot**: `06_services_list.png`

### 6.2 Service Search & Tabs (HTMX)
- **Action**: Search + tab filter
- **Screenshots**: `06_services_search.png`, `06_services_tab_active.png`

### 6.3 Service Detail
- **URL**: `/services/{id}/` (click from list)
- **Check**: Hero section with icon, service info, server details, usage section, action buttons
- **Screenshots**: `06_service_detail_hero.png`, `06_service_detail_usage.png`

### 6.4 Service Usage Chart (HTMX)
- **Check**: the inline Usage tab renders current recorded usage ("Usage charts will be available soon" is the honest placeholder for history). The `/services/{id}/usage/` route resolves but no template or script references it; it is covered by unit tests only
- **Screenshot**: `06_service_usage_chart.png`

### 6.5 Service Action Request (Inspect Only)
- **URL**: `/services/{id}/request-action/`
- **Check**: Radio cards for each action, description textarea, service info sidebar
- **Screenshot**: `06_service_action_form.png`

---

## Phase 7: Support Tickets & Final Checks (6 checks)

### 7.1 Ticket List
- **URL**: `/tickets/`
- **Check**: Header stats, status tabs, search, table (columns are Ticket / Subject / Status / Created — no priority column)
- **Screenshot**: `07_tickets_list.png`

### 7.2 Ticket Search & Tabs (HTMX)
- **Action**: Search + tab filters
- **Screenshots**: `07_tickets_search.png`, `07_tickets_tab_open.png`

### 7.3 Create Ticket
- **URL**: `/tickets/create/`
- **Action**: Fill category, priority, title, description. Submit.
- **Check**: Form fields render, redirects to detail on success
- **Screenshots**: `07_ticket_create_empty.png`, `07_ticket_create_filled.png`, `07_ticket_create_submitted.png`

### 7.4 Ticket Detail + Reply
- **URL**: `/tickets/{id}/` (from 7.3)
- **Action**: View thread, type reply, submit via HTMX
- **Check**: Thread renders, reply appears without reload, character counter works
- **Screenshots**: `07_ticket_detail.png`, `07_ticket_detail_after_reply.png`

### 7.5 Navigation Audit
- **Action**: Click each nav link, verify correct page loads
- **Check**: Dashboard, Invoices, Services, Tickets, Profile all resolve correctly
- **Screenshot**: `07_nav_audit.png`

### 7.6 Logout
- **Action**: Click Logout
- **Check**: Session cleared, redirects to `/login/`, accessing `/dashboard/` requires re-login
- **Screenshot**: `07_logout_result.png`

### Final Log Check
- Comprehensive scan of all `make dev` output for errors/tracebacks
- Save full server logs to `QA/logs/server_log_final.txt`

---

## Key Risk Areas (highest bug probability)

1. **HTMX skeleton loaders** — `#tickets-skeleton` has custom CSS override; watch for layout shifts
2. **Romanian currency formatting** — `cents_to_currency` + `romanian_currency` filter chain; raw integers = bug
3. **SVG icon system** — `{% icon "name" %}` renders blank if icon missing from registry
4. **Platform availability banner** — the dashboard's red banner markup is unreachable: `dashboard_view` never sets `platform_available` to false, so a 502/503/504 shows the blue maintenance alert and a refused connection shows nothing (only `/dashboard/account/` can render the red one)
5. **Cart HMAC price sealing** — `cart_version` hidden field must match on checkout
6. **GDPR consent date** — Must not display `None` raw
7. **MFA pages without TOTP** — Backup codes page with MFA disabled must not 500

## Execution Notes

- Dismiss cookie consent banner with "Essential Only" on first page load
- All POST forms use `{% csrf_token %}` — submit via page interaction, not manual requests
- Wait for HTMX indicators to clear before taking screenshots
- Get dynamic IDs (invoice numbers, service IDs, ticket IDs) from list pages before visiting detail URLs
- DO NOT: submit registration form, enable MFA, complete payment, delete anything

---

## Verification

After all phases:
1. All ~55 screenshots saved in `QA/screenshots/` subfolders
2. `action_log.md` has entry for every action taken
3. `qa_report.md` has severity-rated findings for every page
4. Server logs saved at each checkpoint in `QA/logs/`
5. Any CRITICAL/HIGH issues flagged prominently in report summary
