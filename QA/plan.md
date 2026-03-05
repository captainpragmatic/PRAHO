# PRAHO Portal QA Walkthrough Plan

## Context

We need a full manual QA walkthrough of the Portal service (localhost:8701) using Chrome browser automation (claude-in-chrome MCP). The portal is a stateless Django frontend that proxies to the Platform service via HMAC-signed requests. This walkthrough will visit every page, test every form, click every button, take screenshots, check server logs, and document all findings in a `QA/` folder.

**Scope**: Portal only (Platform walkthrough deferred to a later run).

---

## Pre-requisites

1. **Start services**: Run `make dev` in background (platform :8700 + portal :8701)
2. **Load fixtures**: Run `make fixtures` to seed demo data (users, products, invoices, services, tickets)
3. **Create QA folder structure**:
```
QA/
├── plan.md                     # This plan (copied here)
├── screenshots/
│   ├── 01_auth/
│   ├── 02_dashboard/
│   ├── 03_profile/
│   ├── 04_billing/
│   ├── 05_orders/
│   ├── 06_services/
│   └── 07_tickets/
├── logs/
│   ├── server_log_checkpoint_A.txt
│   ├── server_log_checkpoint_B.txt
│   ├── server_log_checkpoint_C.txt
│   ├── server_log_checkpoint_D.txt
│   ├── server_log_final.txt
│   └── console_errors.log
├── action_log.md               # Step-by-step log of every action taken
└── qa_report.md                # Master findings report
```

## Test Credentials

| Service | Email | Password |
|---------|-------|----------|
| Portal (primary) | `e2e-customer@test.local` | `test123` |
| Portal (fallback) | `customer@pragmatichost.com` | `testpass123` |

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
- **Check**: Welcome greeting, 4 stat cards (services/tickets/invoices/status), recent invoices section, recent tickets section, quick action buttons, footer version badge
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
- **Check**: Pre-filled fields, country readonly (RO), VAT validation
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
- **Check**: MFA status badge, TOTP setup link, last login date
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
- **Check**: 3 consent toggles, GDPR consent date, data export link
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

## Phase 5: Orders / Product Catalog (8 checks)

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
- **Check**: Breadcrumb (step 2), items list, quantity controls (HTMX), totals (subtotal + VAT 21% + total), Proceed to Checkout button
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
- **Check**: Plans grid, pricing, order CTA buttons
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
- **Check**: `/services/{id}/usage/` loads, bars render
- **Screenshot**: `06_service_usage_chart.png`

### 6.5 Service Action Request (Inspect Only)
- **URL**: `/services/{id}/request-action/`
- **Check**: Radio cards for each action, description textarea, service info sidebar
- **Screenshot**: `06_service_action_form.png`

---

## Phase 7: Support Tickets & Final Checks (6 checks)

### 7.1 Ticket List
- **URL**: `/tickets/`
- **Check**: Header stats, status tabs, search, table, priority badges
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
4. **Platform availability banner** — Dashboard shows red banner if platform down
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
