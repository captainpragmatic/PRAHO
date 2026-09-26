# PRAHO Portal QA Report

**Date**: 2026-03-03
**Version**: v0.21.0
**Service**: Portal (localhost:8701)
**Platform**: localhost:8700
**Tester**: Claude Code (automated browser walkthrough — 3 sessions: 2 desktop + 1 mobile)
**Browser**: Chrome (MacBook Pro)
**Test Account**: e2e-customer@test.local / test123

---

## Executive Summary

The Portal is **functional and visually polished** across a wide range of user flows. Authentication (when credentials are correct), navigation, HTMX interactions, support tickets, service detail views, and GDPR compliance pages all work well. However, there are **two completely blocked core flows** (cart checkout and user registration) and **three HIGH-severity data display failures** affecting invoices, login UX, and a missing template. Data mapping issues between Portal and Platform APIs account for the majority of MEDIUM findings.

---

## Severity Summary

| Severity | Count | Description |
|----------|-------|-------------|
| CRITICAL | 2     | Blocks a core user flow entirely |
| HIGH     | 3     | Significant failures, broken page, or missing UX |
| MEDIUM   | 9     | Incorrect or missing data, UX gaps, HTMX failures |
| LOW      | 6     | Cosmetic, dev-only, or minor inconsistencies |
| PASS     | 25+   | Features working correctly |

---

## Findings

### CRITICAL

#### C1: Cart Order Summary fails — product_id UUID mismatch
- **Page**: `/orders/cart/` (Cart Review)
- **Symptom**: Order Summary panel shows skeleton loader indefinitely. No "Proceed to Checkout" button appears.
- **Root Cause**: Portal sends `POST /order/cart/calculate/` to Platform. Platform returns `400: {'items': [{'product_id': ['Must be a valid UUID.']}]}`. The cart stores product IDs as integers but the Platform API validates them as UUIDs.
- **Impact**: Checkout flow is completely blocked. Users can add items to cart but cannot proceed to payment.
- **Server Log**: `⚠️ [OrderProxy] Calculate order failed: {'items': [{'product_id': ['Must be a valid UUID.']}]}`

#### C2: Registration flow completely blocked — terms_accepted missing + Platform API rejection
- **Page**: `/register/`
- **Symptom (1)**: The registration form template does not render the `terms_accepted` checkbox, but the field is required for submission. Users cannot complete registration without accepting terms.
- **Symptom (2)**: Even if terms were accepted, the Platform API also rejects the registration request.
- **Impact**: New user registration is completely non-functional end-to-end.

---

### HIGH

#### H1: Invoice Detail — Customer N/A, Status empty, Issue Date empty, No invoice lines found
- **Page**: `/billing/invoices/<id>/`
- **Symptom**: Customer shows "N/A", Status shows empty (no badge), Issue Date is empty, Invoice Lines section shows "No invoice lines found" despite totals being present (Subtotal 29.99 RON, VAT 6.30 RON, Total 36.29 RON).
- **Root Cause**: Template field names do not match the API response structure. The list view renders status badges correctly, but the detail template uses different or stale variable names.
- **Impact**: Users cannot see full invoice details — critical for Romanian tax and billing compliance.

#### H2: Login form — no error feedback on wrong credentials
- **Page**: `/login/`
- **Symptom**: Submitting wrong email/password silently re-renders the form. Email is retained, password cleared, but no error message appears ("Invalid email or password" or similar).
- **Root Cause**: No error elements rendered in the DOM after a failed login. The view likely does not pass error context to the template on authentication failure.
- **Impact**: Users have no way to know whether their login failed or the form just did not submit. Security best practice requires a generic error message.

#### H3: Service Plans page — 500 error (TemplateDoesNotExist)
- **Page**: `/services/plans/` (or equivalent plans list route)
- **Symptom**: The page returns a 500 server error due to `TemplateDoesNotExist: services/plans_list.html`.
- **Root Cause**: The view is wired in `urls.py` but the corresponding template was never created.
- **Impact**: The Service Plans discovery page is completely inaccessible.

---

### MEDIUM

#### M1: Company Profile — Company Name shows "Not specified"
- **Page**: `/profile/company/<id>/`
- **Symptom**: Company Name field shows "Not specified" despite "Test Company SRL" appearing correctly on the dashboard and profile overview page.
- **Root Cause**: Template likely references the wrong field name (e.g., `company_name` vs `name` vs `display_name`).

#### M2: Profile — "Last Login: Never" and "Member Since: N/A"
- **Page**: `/profile/`
- **Symptom**: Both fields show placeholder values despite the user being actively logged in with an existing account.
- **Root Cause**: Platform API may not return `last_login` and `date_joined` fields, or the Portal template does not map them correctly.
- **Also affects**: MFA Management page ("Last Login: Never")

#### M3: Service Detail — "Next Bill" and "Uptime" stuck on "Calculating..."
- **Page**: `/services/<id>/`
- **Symptom**: Two stat cards permanently show "Calculating..." — the HTMX async load never resolves.
- **Root Cause**: Likely depends on Platform API endpoints that do not exist or return an unexpected format.

#### M4: Service Detail — "Active Since" date missing in AGE card
- **Page**: `/services/<id>/`
- **Symptom**: The AGE stat card shows the "Active Since" label but no date value.
- **Root Cause**: Same datetime field mapping issue as M2.

#### M5: Service Detail — domain retrieval error (KeyError 'results')
- **Page**: `/services/<id>/`
- **Server Log**: `ERROR [ServiceProxy] Error retrieving domains for service 43: 'results'`
- **Root Cause**: API response structure mismatch — code expects `response['results']` but Platform returns a different key.

#### M6: Account Overview page sparse
- **Page**: `/profile/account/`
- **Symptom**: Only shows Email and Customer ID. Dashboard shows Company Name and VAT Number, but the dedicated account page does not pull this data.
- **Impact**: Minor — data exists on other pages.

#### M7: TOTP setup fails — redirects with "Failed to initialize MFA setup"
- **Page**: `/mfa/setup/totp/`
- **Symptom**: Navigating to the TOTP setup page redirects to `/mfa/` with an error flash: "Failed to initialize MFA setup". No QR code or secret is shown.
- **Root Cause**: MFA setup initialization call to Platform API likely fails silently.

#### M8: Company Edit page — Billing Address section empty
- **Page**: `/profile/company/<id>/edit/`
- **Symptom**: The Billing Address section renders no form fields. The Company Create page includes billing address fields, but the Edit page does not.
- **Root Cause**: Billing address fields are either excluded from the edit form or the section template is not rendering its fields.

#### M9: Product Detail page — sparse layout, empty fields, mixed languages
- **Page**: `/orders/products/<slug>/`
- **Symptom**: Billing period dropdown is empty, no product description shown, no pricing info displayed. UI mixes Romanian and English labels ("Perioadă de facturare" vs "Quantity") in the same form.
- **Root Cause**: Product detail API response likely missing description and pricing data; i18n not consistent across the template.

---

### LOW

#### L1: Django Debug Toolbar console error flood (dev-only)
- **Page**: All unauthenticated pages
- **Symptom**: Approximately 90 console exceptions from `debug_toolbar/js/utils.js`. Debug toolbar AJAX sidebar requests hit auth middleware, get redirected to `/login/`, and fail JSON parsing.
- **Impact**: Dev-only noise. Not present in production (debug toolbar disabled).

#### L2: Product price dropdown text truncation
- **Page**: `/orders/products/`
- **Symptom**: Billing cycle dropdowns show truncated text ("199.99 RON/mor", "99.99 RON/mont").
- **Fix**: Widen the `<select>` element or use shorter labels.

#### L3: Currency formatting inconsistency
- **Page**: `/services/` vs `/billing/invoices/`
- **Symptom**: Services page uses period decimal (199.99 RON) while Billing page uses Romanian comma format (129,24 RON).
- **Fix**: Standardize to Romanian locale format (comma decimal) across all pages.

#### L4: Ticket subjects include status prefix in fixtures
- **Page**: `/tickets/`
- **Symptom**: Ticket subjects show "[IN_PROGRESS]", "[OPEN]", "[CLOSED]" as part of the subject text.
- **Root Cause**: Fixture data includes status in the subject string. Not a template bug.

#### L5: Proforma detail VAT column shows "0.2%" instead of "21%"
- **Page**: `/billing/proformas/<id>/`
- **Symptom**: The VAT rate column displays "0.2%" instead of "21%". The calculated VAT amount appears correct, so this is a display/formatting bug only.
- **Root Cause**: Rate stored as decimal (`0.21`) rendered directly without percentage conversion.

#### L6: Service detail title truncated on mobile viewport
- **Page**: `/services/<id>/` (at 390px width)
- **Symptom**: Service name "Web Hosting Professional" truncates to "Web Hosting Profession..." on mobile viewport (390x844).
- **Root Cause**: CSS `text-overflow: ellipsis` or `overflow: hidden` on the heading element at narrow widths.
- **Impact**: Minor — service type badge below the title still identifies the service. Only affects long service names.
- **Mobile-only**: Not visible on desktop.

---

## Mobile Responsive Assessment

**Date**: 2026-03-04 | **Viewport**: 390x844 (iPhone 14 Pro) | **Pages tested**: 14

The Portal's responsive design is **excellent overall**. Tailwind CSS utility classes produce clean mobile layouts:

| Aspect | Assessment |
|--------|-----------|
| **Form layouts** | PASS — All inputs go full-width, labels above fields |
| **Navigation** | PASS — Hamburger menu, all links accessible |
| **Card stacking** | PASS — Multi-column grids collapse to single column |
| **Tab bars** | PASS — Horizontally scrollable on narrow viewports |
| **Stat cards** | PASS — 2-column grid maintained, readable |
| **Badges/buttons** | PASS — Properly sized, no overlapping |
| **Tables** | PASS — Switch to card layout on mobile |
| **Breadcrumbs** | WARN — Order stepper step 3 slightly cut off at edge |
| **Long titles** | WARN — Service detail title truncated (L6) |

**Only 1 new mobile-specific finding** (L6). All desktop findings (C1-C2, H1-H3, M1-M9, L1-L5) are equally visible on mobile — no additional data/functional bugs surfaced at mobile width.

---

## Passing Features (30+)

| # | Feature | Page | Notes |
|---|---------|------|-------|
| 1 | Health check | `/health/` | Returns JSON `{"status": "healthy"}` |
| 2 | Root redirect | `/` | Redirects to `/login/` |
| 3 | Cookie consent banner | `/login/` | Shows banner, "Essential Only" dismisses it |
| 4 | Login page rendering | `/login/` | Logo, fields, links, remember me — all present |
| 5 | Login success | `/login/` | Correct credentials redirect to `/dashboard/` |
| 6 | Dashboard | `/dashboard/` | Alert banner, stats, invoices, tickets, quick actions, account info |
| 7 | Navigation bar | All pages | All links work: Dashboard, Invoices, Services, Tickets, Profile, Logout |
| 8 | Invoice list | `/billing/invoices/` | Stats, search, status filters, Romanian currency formatting |
| 9 | Invoice HTMX tab filters | `/billing/invoices/` | Invoices/Proformas tabs swap content without reload |
| 10 | Billing Sync button | `/billing/` | "Successfully synced 10 invoices" confirmation |
| 11 | Product catalog | `/orders/products/` | Product cards, trust signals, pricing, domain inputs |
| 12 | Product catalog type filters | `/orders/products/` | Category filter tabs work correctly |
| 13 | Add to cart | `/orders/products/` | Confirmation toast appears, cart badge updates, selected product highlighted |
| 14 | Registration form rendering | `/register/` | All sections render (org type toggle works), only submission is broken (see C2) |
| 15 | Service list | `/services/` | Status badges, search, filter tabs |
| 16 | Service list Active filter | `/services/` | HTMX filter to Active tab works |
| 17 | Service detail hero | `/services/<id>/` | Badges, domain, action buttons, access details |
| 18 | Service detail tabs | `/services/<id>/` | Overview, Usage, and Performance tabs all render rich content |
| 19 | Service Action Request form | `/services/<id>/action/` | 4 action types with radio cards, form submits |
| 20 | Ticket list | `/tickets/` | Status badges, search, filter tabs, stats |
| 21 | Ticket creation | `/tickets/create/` | Form with category, priority, guidelines — submits and redirects with toast |
| 22 | Ticket detail | `/tickets/<id>/` | Metadata, conversation thread, reply form |
| 23 | Ticket reply (HTMX) | `/tickets/<id>/` | Reply appears instantly without reload, reply counter updates |
| 24 | Profile page | `/profile/` | Personal info, preferences, company cards, GDPR section |
| 25 | Change password form | `/profile/change-password/` | 3-field form with security tips |
| 26 | MFA management | `/mfa/` | Security status, authenticator app and passkeys options |
| 27 | Privacy dashboard | `/privacy/` | Full GDPR compliance dashboard renders |
| 28 | Data export | `/privacy/export/` | Export flow works |
| 29 | Consent history | `/privacy/consent/` | Consent history renders |
| 30 | Logout | Logout button | Session cleared, protected pages redirect to login, no back-button access |

---

## Pages Not Tested / Blocked

| Page | Reason |
|------|--------|
| Checkout (`/orders/checkout/`) | Blocked by C1 (cart summary fails) |
| Registration submission | Blocked by C2 (terms_accepted missing + API rejection) |
| Password Reset (`/forgot-password/`) | Not in walkthrough scope |
| PDF Download | Not tested (would trigger download) |
| TOTP QR code scan | Blocked by M7 (setup fails); also requires authenticator app |
| Passkey setup | Requires WebAuthn hardware |

---

## Server Log Analysis

- **HMAC Authentication**: All Portal-to-Platform API calls authenticate successfully (no auth failures)
- **Template Rendering**: No template errors or missing variable warnings in logs (except H3 plans_list.html)
- **Cart API**: `POST /order/cart/calculate/` returns 400 (UUID validation — see C1)
- **Domain API**: Service detail domain retrieval fails with KeyError `'results'` (see M5)
- **MFA API**: TOTP setup initialization fails, triggers redirect (see M7)
- **Debug Toolbar**: Excessive 302 redirects on unauthenticated pages (see L1)

---

## Recommendations (Priority Order)

1. **Fix C1** — Convert product_id to UUID in cart session storage, or accept integer IDs in the Platform calculate endpoint
2. **Fix C2** — Add `terms_accepted` checkbox to registration template and fix Platform API registration rejection
3. **Fix H1** — Audit invoice detail template field names against Platform API response
4. **Fix H2** — Add error message to login template on authentication failure
5. **Fix H3** — Create `services/plans_list.html` template
6. **Fix M7** — Investigate MFA TOTP setup API call and fix initialization failure
7. **Fix M8** — Add billing address fields to the company edit form
8. **Fix M9** — Fix product detail page: populate billing period dropdown, description, pricing, and standardize i18n
9. **Fix M1-M2** — Audit field name mappings for company profile and user metadata (last_login, date_joined, name)
10. **Fix M3-M5** — Investigate service detail HTMX endpoints and domain API response structure
11. **Fix L5** — Convert VAT rate from decimal to percentage before rendering (multiply by 100)
12. **Fix L2-L3** — CSS width for dropdowns, standardize locale formatting

---

*Report generated by automated browser walkthrough across 2 QA sessions. All findings verified against live Portal (v0.21.0) with fixture data.*
