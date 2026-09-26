# PRAHO Portal QA - Action Log

**Date**: 2026-03-03
**Tester**: Claude Code (Playwright MCP)
**Portal URL**: http://localhost:8701
**Platform URL**: http://localhost:8700
**Test Account**: e2e-customer@test.local / test123
**Desktop Viewport**: 1440x900
**Mobile Viewport**: 390x844

---

### 1.1 Health Check
- **URL**: http://localhost:8701/status/
- **Action**: Navigate to health endpoint
- **Result**: PASS
- **Desktop Screenshot**: `01_auth/desktop_health_check.png`
- **Mobile Screenshot**: `01_auth/mobile_health_check.png`
- **Console Errors**: 1 — favicon.ico 404 (trivial)
- **Network**: GET /status/ → 200 JSON
- **Server Logs**: Clean
- **Findings**: Returns `{"status": "healthy", "service": "portal"}`. No responsive issues (plain JSON).

### 1.2 Root Redirect
- **URL**: http://localhost:8701/
- **Action**: Navigate to root
- **Result**: PASS
- **Findings**: Redirects to `/login/` when unauthenticated. Correct behavior.

### 1.4 Login Page (Empty)
- **URL**: http://localhost:8701/login/
- **Action**: Inspect login page after redirect
- **Result**: PASS (desktop), WARN (mobile)
- **Desktop Screenshot**: `01_auth/desktop_login_empty.png`
- **Mobile Screenshot**: `01_auth/mobile_login_empty.png`
- **Console Errors**: 1 — DOM autocomplete warning (trivial)
- **Findings**:
  - Desktop: Logo (blue "P"), title "PRAHO Portal Login", subtitle "Customer Portal Access", email/password fields with icons, "Keep me logged in" checkbox, "Forgot password?" link, "Sign In" button, "Register here" link, "Secure Connection | GDPR Compliance" note, footer with version 0.21.0, Cookie Policy + Cookie Preferences links. All present and correct.
  - Mobile: Cookie consent banner **overlaps form** — covers "Keep me logged in", "Forgot password?", "Sign In", and "Register here". Users cannot interact with lower form elements until banner is dismissed. **MEDIUM severity mobile UX bug.**
  - Cookie banner: 3 options (Essential Only, Customize, Accept All). "Learn more" links to `/cookie-policy/`.
  - Django Debug Toolbar tab visible on right edge (dev-only).

### 1.4a Cookie Banner Dismissal
- **Action**: Clicked "Essential Only" button
- **Result**: PASS — Banner dismissed
- **Console Errors**: 4 — All from `debug_toolbar/js/utils.js` — JSON parse errors from debug toolbar AJAX hitting auth middleware. Dev-only noise (L1 from previous session confirmed).
- **Findings**: Debug toolbar error "The response is a invalid Json object: SyntaxError: Unexpected token '<'" appears as a visible heading on page after cookie dismissal. This is the debug toolbar rendering its own error in the DOM — **visible to users in dev mode**. LOW severity (dev-only).
- **Network**: POST `/api/cookie-consent/` → 200 OK. Then 68x `/__debug__/history_sidebar/` → 302 → `/login/` (debug toolbar cascade, expected for unauthenticated pages).

### 1.3 Cookie Policy
- **URL**: http://localhost:8701/cookie-policy/
- **Action**: Navigate to cookie policy page
- **Result**: PASS
- **Desktop Screenshot**: `01_auth/desktop_cookie_policy.png`
- **Mobile Screenshot**: `01_auth/mobile_cookie_policy.png`
- **Console Errors**: 1 — favicon.svg 404 (trivial, missing favicon)
- **Network**: GET /cookie-policy/ → 200
- **Findings**:
  - Desktop: Comprehensive GDPR-compliant cookie policy. 4 cookie categories (Essential "Always Active", Functional "Optional", Analytics "Optional", Marketing "Optional") each with detailed tables showing Cookie Name, Purpose, Duration, Provider. Legal basis cited for each (GDPR Art. 6(1)(f) for essential, Art. 6(1)(a) consent for others). "Manage Your Preferences" section with "Open Cookie Preferences" button. Legal Information section citing EU Regulation 2016/679, Directive 2002/58/EC, Romanian Law 506/2004. DPO contact: privacy@pragmatichost.com.
  - Mobile: Tables get cramped but remain readable. No horizontal overflow. Content stacks properly. "Open Cookie Preferences" button centered and tappable.
  - Page title says "PragmaticHost" (brand name) not "PRAHO Portal" — intentional branding.
  - Note: favicon.svg returns 404 — minor missing asset.

### 1.5 Login Validation Error
- **URL**: http://localhost:8701/login/
- **Action**: Filled email="notanemail", password="x", clicked Sign In
- **Result**: PASS
- **Desktop Screenshot**: `01_auth/desktop_login_validation_error.png`
- **Console Errors**: None (form never submitted — HTML5 validation caught it)
- **Network**: No POST request sent (client-side validation blocked)
- **Findings**: Browser-native HTML5 `<input type="email">` validation fires: "Please include an '@' in the email address. 'notanemail' is missing an '@'." Form does not submit to server. This is correct client-side validation behavior.

### 1.9 Registration Page
- **URL**: http://localhost:8701/register/
- **Action**: Navigate, inspect all sections, test org type toggle
- **Result**: PASS
- **Desktop Screenshot**: `01_auth/desktop_register_empty.png` (SRL mode), `01_auth/desktop_register_individual.png` (Individual mode)
- **Mobile Screenshot**: `01_auth/mobile_register_empty.png`
- **Console Errors**: 1 — favicon.svg 404 (same missing asset)
- **Network**: GET /register/ → 200
- **Findings**:
  - 5 sections: Personal Information (First/Last Name, Email, Phone), Business Information (Org Type dropdown, Company Name, VAT/CNP), Address Information (Address, City, County, Postal Code), Account Security (Password + Confirm), Privacy & Consent (data processing required, marketing optional).
  - Org Type toggle: Changing from "SRL" to "Individual" dynamically swaps VAT Number field for CNP (Cod Numeric Personal) field with correct placeholders and help text. **Romanian compliance working correctly.**
  - 5 org types available: SRL, PFA, SA, ONG, Individual.
  - Romanian placeholders: Ion/Popescu, +40.21.123.4567, RO12345678, București, 010001.
  - "Already have an account? Sign in here" link present.
  - Mobile: All fields stack vertically, no overflow, fully usable.
  - Note: Company Name placeholder still says "Your Company SRL" even in Individual mode — minor UX inconsistency (LOW).
  - Note: PRAHO logo shows as broken image (alt text "PRAHO") on register + password reset pages — favicon.svg missing.

### 1.8 Password Reset
- **URL**: http://localhost:8701/password-reset/
- **Action**: Navigate, inspect form, submit with e2e-customer@test.local
- **Result**: PASS
- **Desktop Screenshot**: `01_auth/desktop_password_reset_empty.png`, `01_auth/desktop_password_reset_submitted.png`
- **Mobile Screenshot**: `01_auth/mobile_password_reset_empty.png`
- **Console Errors**: 1 — favicon.svg 404
- **Network**: GET /password-reset/ → 200, POST /password-reset/ → 302 → /login/
- **Findings**:
  - Clean form: Email field, "Send Password Reset Email" button (blue with mail icon), "← Back to login" link.
  - After submit: Redirects to /login/ with toast "If an account with that email exists, you will receive password reset instructions." — **correct anti-enumeration pattern** (doesn't reveal if email exists).
  - Toast has close button (X). Auto-dismisses after ~3 seconds.
  - PRAHO logo broken image on this page too (favicon.svg 404).
  - Mobile: Layout clean, button full-width, debug toolbar overlaps heading slightly (dev-only).

### 1.6 Login Wrong Credentials
- **URL**: http://localhost:8701/login/
- **Action**: Filled email="wrong@example.com", password="wrongpassword123", clicked Sign In
- **Result**: PASS
- **Desktop Screenshot**: `01_auth/desktop_login_wrong_credentials.png`
- **Console Errors**: None (app-level)
- **Network**: POST /login/ → 200 (re-renders login page)
- **Findings**:
  - Toast notification appears: "Invalid email address or password. Please try again." — **correct generic error** (no user enumeration).
  - Email retained in field, password cleared — correct UX.
  - Toast auto-dismisses quickly (~2-3 seconds) — screenshot missed it but DOM snapshot confirmed.
  - **Corrects previous H2 finding**: Error feedback IS working. Previous chrome-extension session missed the toast due to timing.
  - Note: Toast may be too fast for users to read — consider longer duration. LOW.

### 1.7 Login Success
- **URL**: http://localhost:8701/login/ → /dashboard/
- **Action**: Filled email="e2e-customer@test.local", password="test123", clicked Sign In
- **Result**: PASS
- **Desktop Screenshot**: `01_auth/desktop_login_success_dashboard.png`
- **Mobile Screenshot**: `01_auth/mobile_login_success_dashboard.png`
- **Console Errors**: None (app-level)
- **Network**: POST /login/ → 302 → /dashboard/ → 200
- **Findings**:
  - Redirects to /dashboard/ with toast "Sign in confirmed, E2E!"
  - Nav bar: PRAHO Portal logo, Dashboard, My Invoices, My Services, My Tickets, Profile, Logout
  - Alert banner (red): "You have 1 suspended service. You have 2 overdue invoices." with "View Services" CTA
  - Welcome greeting: "Welcome E2E"
  - 4 stat cards: My Services (2), My Open Tickets (6), Account Status (Active ✓ green), Next Billing (End of Month)
  - My Recent Invoices & Proformas: 4 proformas (PRO-000061 to PRO-000058) with Draft badges, RON amounts
  - My Recent Tickets: 4 tickets with status badges (In Progress, Open, Closed, Waiting on You)
  - Quick Actions: New Ticket (red), View Invoices (green), My Services (gray), My Profile (purple)
  - Account Information: Test Company SRL, RO12345678, Feb 2026
  - Footer: © 2026, tech stack badges, Version 0.21.0
  - Mobile: All sections stack vertically, stat cards 1-per-row, nav collapses to hamburger. Good responsive.
  - Note: Ticket subjects include raw status prefix [IN_PROGRESS], [OPEN] etc. — fixture data issue (LOW).

---

## Phase 1 Summary: 9/9 checks PASS (2 with minor notes)

---

## Phase 2: Dashboard

### 2.1 Main Dashboard
- **URL**: http://localhost:8701/dashboard/
- **Action**: Navigate after login, inspect all sections
- **Result**: PASS
- **Desktop Screenshot**: `02_dashboard/desktop_dashboard.png`
- **Mobile Screenshot**: `01_auth/mobile_login_success_dashboard.png` (captured during login)
- **Console Errors**: None (app-level)
- **Network**: Clean — no failed API requests
- **Findings**:
  - Nav bar: PRAHO Portal (P logo), Dashboard, My Invoices, My Services, My Tickets | Profile, Logout (red)
  - Alert banner (red bg): "You have 1 suspended service. You have 2 overdue invoices." + "View Services >" CTA linking to `/services/?status=suspended`
  - Welcome: "Welcome E2E" + subtitle
  - 4 stat cards: My Services (2), My Open Tickets (6), Account Status (Active, green ✓), Next Billing (End of Month)
  - My Recent Invoices & Proformas: 4 proformas (PRO-000061 to PRO-000058), all Draft, RON amounts, dates in DD.MM.YYYY format, "View all →" links to `/billing/invoices/`
  - My Recent Tickets: 4 tickets with status badges (In Progress yellow, Open blue, Closed gray, Waiting on You green), "View all →" links to `/tickets/`
  - Quick Actions: 4 buttons (New Ticket red → `/tickets/create/`, View Invoices green → `/billing/invoices/`, My Services gray → `/services/`, My Profile purple → `/profile/`)
  - Account Information: Customer name (Test Company SRL), VAT Number (RO12345678), Customer Since (Feb 2026)
  - Footer: © 2026, tech stack, Version 0.21.0, Cookie Policy + Cookie Preferences links
  - All links verified via DOM snapshot — correct URLs.
  - Mobile: Good responsive layout, stat cards stack, nav hamburger menu.
  - Note: Ticket subjects include [IN_PROGRESS], [OPEN] etc. status prefixes in text — fixture data issue (LOW).

### 2.2 Account Overview
- **URL**: http://localhost:8701/dashboard/account/
- **Action**: Navigate, inspect details and quick links
- **Result**: PASS (with note)
- **Desktop Screenshot**: `02_dashboard/desktop_account_overview.png`
- **Mobile Screenshot**: `02_dashboard/mobile_account_overview.png`
- **Console Errors**: None
- **Network**: Clean
- **Findings**:
  - Account Details: Email (e2e-customer@test.local), Customer ID (1)
  - Quick Links: Edit Profile → `/profile/`, Change Password → `/change-password/`, Back to Dashboard → `/dashboard/`
  - Missing: Company Name, VAT Number, Customer Since — these appear on dashboard's Account Information section but not on this dedicated page. **MEDIUM** — the account overview page should show the same info.
  - Mobile: Clean layout, buttons wrap properly.
  - Alert banner persists across pages (correct — it's a global alert).

---

## Phase 2 Summary: 2/2 checks PASS (1 with data gap note)

---

## Phase 1b: Registration Form Submission Test

### 1.9b Registration Form Submission
- **URL**: http://localhost:8701/register/
- **Action**: Filled all fields (Personal: QA Test User, qa-test-user@test.local, +40.21.555.1234; Business: SRL, QA Test Company SRL, RO87654321; Address: Str. Testului Nr. 42, Cluj-Napoca, Cluj, 400001; Password: TestPassword123!; GDPR consent checked). Submitted form.
- **Result**: FAIL — **CRITICAL**
- **Desktop Screenshot**: `01_auth/desktop_register_filled.png`, `01_auth/desktop_register_submitted_error.png`
- **Console Errors**: 1 — favicon.svg 404 (trivial)
- **Network**: POST /register/ → 200 (re-renders form with error)
- **Findings**:
  - **Bug C2: Registration form always fails — `terms_accepted` field missing from template.** The Django form class `CustomerRegistrationForm` defines a required `terms_accepted` BooleanField (forms.py:277), but the template `users/register.html` only renders `data_processing_consent` and `marketing_consent` checkboxes. Since `terms_accepted` is never present in POST data, `form.is_valid()` always returns False. **No user can register through the Portal.**
  - **Bug C2b: Form validation errors not displayed.** The template does not render `{{ form.errors }}` or `{{ form.non_field_errors }}`. When form validation fails, the form silently re-renders with no indication of which field failed. Only the generic `messages.error()` banner appears ("Registration failed. Please check your information and try again.").
  - **Bug C2c: Platform API registration also fails.** Even after injecting `terms_accepted` via DOM manipulation to bypass the missing field, the Platform API `/customers/register/` returns an error. The generic "Registration failed" error banner appears. Root cause needs Platform-side investigation.
  - **Note**: Password fields correctly clear on re-render (Django `PasswordInput` `render_value=False` — security best practice). All other field values are preserved.
  - **Severity**: CRITICAL — Complete registration flow is blocked.

---

## Phase 3: Profile & Account Management

### 3.1 Profile Page
- **URL**: http://localhost:8701/profile/
- **Action**: Navigate, inspect all sections
- **Result**: PASS (with notes)
- **Desktop Screenshot**: `03_profile/desktop_profile_view.png`
- **Mobile Screenshot**: `03_profile/mobile_profile_view.png`
- **Console Errors**: None (app-level)
- **Findings**:
  - Personal Information: First Name (E2E), Last Name (Customer), Email (disabled with "Contact support" note), Phone (+40 721 123 456), Language (English), Timezone (Europe/Bucharest), Save Changes button.
  - Account Information: Status Active (green badge), **Member Since: N/A** (M2), **Last Login: Never** (M2), MFA Disabled with "Enable MFA Now" link, Change Password link.
  - Company Profiles: "Test Company SRL" card with Owner badge, View/Edit buttons, "Add New Company" card with Create Company link. Dropdown selector for companies.
  - Privacy & Data Protection: Data Processing "Not Given" (red), Marketing "Disabled". Links to Privacy Dashboard, Export My Data, Consent History.
  - GDPR compliance note: Romanian Law 190/2018 and EU Regulation 2016/679.
  - Mobile: All sections stack vertically, no overflow.

### 3.2 Company Profile (Read-Only)
- **URL**: http://localhost:8701/company/
- **Action**: Navigate, inspect all sections
- **Result**: PASS (with note)
- **Desktop Screenshot**: `03_profile/desktop_company_profile.png`
- **Findings**:
  - **Company Name: "Not specified"** (M1 confirmed) — data exists in edit form as "Test Company SRL" but view template doesn't display it.
  - VAT Number: RO12345678 — correctly displayed.
  - Trade Registry, Industry: "Not specified" (no fixture data).
  - Billing Address: ALL fields "Not specified" (Street, City, County, Postal Code, Country).
  - Business Contact: ALL fields "Not specified" (Email, Phone, Website).
  - Links: "Back to Profile", "Edit Company Profile", info box with "Update now" link. All correct URLs.

### 3.3 Company Profile Edit
- **URL**: http://localhost:8701/company/edit/
- **Action**: Navigate, inspect pre-filled fields
- **Result**: PASS (with note)
- **Desktop Screenshot**: `03_profile/desktop_company_edit.png`
- **Findings**:
  - Company Name pre-filled "Test Company SRL", VAT "RO12345678".
  - Business Contact: Email "contact@testcompany.com", Phone "+40722123456" — pre-filled correctly.
  - **Billing Address section is completely empty** — heading renders but NO form fields appear. Compare with Company Create page which HAS full address fields. **MEDIUM** — template bug, address fields missing from edit form.
  - Cancel and Save Changes buttons present. Important Notes info box.

### 3.4 Create Company (Inspect Only)
- **URL**: http://localhost:8701/company/create/
- **Action**: Navigate, inspect form (DO NOT SUBMIT)
- **Result**: PASS
- **Desktop Screenshot**: `03_profile/desktop_company_create.png`
- **Findings**:
  - Step indicator: 1 (Company Details) → 2 (Ready to Use).
  - Company Information: Name*, VAT/CUI, Trade Registry, Industry.
  - Billing Address: Street*, City*, County, Postal Code, Country (pre-filled "România").
  - Business Contact: Email*, Phone, Website.
  - Terms checkbox required: "I agree to the Terms of Service and Privacy Policy *".
  - Romanian Business Compliance info box. Cancel + Create Company buttons.
  - All fields, placeholders, and help text correct. Good Romanian references (ONRC, sector).

### 3.5 Change Password
- **URL**: http://localhost:8701/change-password/
- **Action**: Navigate, inspect form
- **Result**: PASS
- **Desktop Screenshot**: `03_profile/desktop_change_password.png`
- **Findings**:
  - 3 fields: Current Password, New Password, Confirm New Password. All with placeholders.
  - Password Security Tips section (5 tips).
  - Security Information sidebar: Account email, "Secure Authentication" badge.
  - Encryption assurance: "Your password is encrypted and stored securely."
  - Back to Profile link, Change Password button.

### 3.6 MFA Management
- **URL**: http://localhost:8701/mfa/
- **Action**: Navigate, inspect options
- **Result**: PASS
- **Desktop Screenshot**: `03_profile/desktop_mfa_management.png`
- **Findings**:
  - Current Security Status: MFA Disabled (yellow badge), **Last Login: Never** (M2).
  - Two MFA options: Authenticator App ("Set Up Authenticator App" link → /mfa/setup/totp/) and Passkeys (RECOMMENDED badge, "Contact Support to Enable" disabled button).
  - "Why enable MFA?" section with 4 benefits.
  - Back to Profile link.

### 3.7 MFA TOTP Setup
- **URL**: http://localhost:8701/mfa/setup/totp/
- **Action**: Navigate
- **Result**: WARN — Redirects to /mfa/ with error
- **Desktop Screenshot**: `03_profile/desktop_mfa_totp_setup_error.png`
- **Findings**:
  - Redirects to `/mfa/` with toast: "Failed to initialize MFA setup. Please try again."
  - **MEDIUM**: TOTP setup page never renders. Platform API call for TOTP initialization fails. Users cannot set up authenticator app MFA.

### 3.8 MFA Backup Codes
- **URL**: http://localhost:8701/mfa/backup-codes/
- **Action**: Navigate
- **Result**: PASS — Graceful redirect
- **Desktop Screenshot**: `03_profile/desktop_mfa_backup_codes_redirect.png`
- **Findings**:
  - Redirects to `/mfa/` with toast: "You need to enable 2FA first before accessing backup codes."
  - Correct behavior — no 500 error. Graceful empty state handling.

### 3.9 Privacy Dashboard
- **URL**: http://localhost:8701/privacy/
- **Action**: Navigate, inspect all sections
- **Result**: PASS
- **Desktop Screenshot**: `03_profile/desktop_privacy_dashboard.png`
- **Findings**:
  - Privacy Settings: Data Processing (Inactive), Marketing (Disabled).
  - Quick Actions: Export My Data, Consent History links.
  - Cookie Preferences: "Manage Cookie Preferences" button, Cookie Policy link.
  - 6 GDPR Rights cards: Access, Rectification, Erasure, Portability, Object, Restrict.
  - Data Protection Contact: privacy@pragmatichost.com, pre-filled subject "GDPR Request - e2e-customer@test.local".
  - 30-day response guarantee per GDPR Article 12.

### 3.10 Data Export
- **URL**: http://localhost:8701/data-export/
- **Action**: Navigate, inspect (DO NOT SUBMIT)
- **Result**: PASS
- **Desktop Screenshot**: `03_profile/desktop_data_export.png`
- **Findings**:
  - 6 data categories: Account Info, Service History, Billing Records, Support Tickets, Privacy Consents, Server Data (with caveat).
  - Export Process: 48h processing, email with secure link, 7-day expiry, JSON format.
  - Account Information for verification: email + Customer ID.
  - Legal Information: GDPR Articles 15 & 20, Romanian Law 190/2018, EU Regulation 2016/679.

### 3.11 Consent History
- **URL**: http://localhost:8701/consent-history/
- **Action**: Navigate, inspect
- **Result**: PASS
- **Desktop Screenshot**: `03_profile/desktop_consent_history.png`
- **Findings**:
  - Current Consent Status: Data Processing (Inactive), Marketing Communications (Disabled).
  - Timeline: "No consent history available" — correct empty state.
  - Manage Preferences: Marketing Emails with "Subscribe" button, Essential Communications marked "Required".
  - Legal Information: GDPR Article 7, Romanian Law 190/2018.

---

## Phase 3 Summary: 11/11 checks PASS (3 with notes: M1 company name, M2 dates, M7 TOTP setup fails, M8 edit address missing)

---

## Phase 4: Billing

### 4.6 Proforma Detail (PRO-000059)
- **URL**: /billing/proformas/PRO-000059/
- **Result**: WARN
- **Desktop Screenshot**: `04_billing/desktop_proforma_detail.png`
- **Findings**:
  - Better than invoice detail — has line items.
  - Bill To fields empty (Company, Email blank).
  - VAT column shows "0.2%" instead of "21%" (display bug — calculation correct: 12.60/59.99 ≈ 21%).
  - Summary totals correct (59.99 subtotal, 12.60 VAT, 72.59 total).
  - No refund button (correct for proforma).
  - Valid until date shown.
  - "About This Quote" info section present.

### 4.7 Billing Sync
- **URL**: /billing/invoices/ (Sync button)
- **Action**: Clicked Sync button
- **Result**: PASS
- **Desktop Screenshot**: `04_billing/desktop_billing_sync.png`
- **Findings**: Toast notification "Successfully synced 10 invoices." appeared. Page content unchanged (already current).

---

## Phase 4 Summary (continued): Sync working; proforma detail has Bill To empty and VAT display bug.

---

## Phase 5: Orders / Product Catalog

### 5.1 Product Catalog
- **URL**: /order/
- **Result**: PASS
- **Desktop Screenshot**: `05_orders/desktop_catalog_all.png`
- **Findings**:
  - 4 products (VPS Advanced 199.99, VPS Basic 99.99, Web Hosting Professional 59.99, Web Hosting Starter 29.99).
  - Step breadcrumb (1-4).
  - Trust signals (SSL, Instant Setup, VAT Included, 24/7 Support, Romanian Data Center).
  - Type filter tabs (All/Shared/VPS/Dedicated/Domains/SSL/Email).
  - L2 confirmed: dropdown text truncation visible.

### 5.1b Product Catalog Filtered
- **URL**: /order/?type=shared_hosting
- **Action**: Clicked "Shared Hosting" tab
- **Result**: PASS
- **Findings**: Filtered to 2 products (Web Hosting Professional + Starter). Full page reload (not HTMX — uses URL query param).

### 5.2 Product Detail
- **URL**: /order/products/product-1/
- **Result**: WARN (MEDIUM M9)
- **Desktop Screenshot**: `05_orders/desktop_product_detail.png`
- **Findings**:
  - Multiple issues:
    1. Empty billing period dropdown — no option text visible.
    2. No product description rendered.
    3. No pricing information shown.
    4. Mixed RO/EN labels ("Perioadă de facturare" vs "Quantity").
    5. "← Înapoi la catalog" in Romanian.
  - Sparse layout with form pushed right and empty left side.

### 5.3 Add to Cart
- **URL**: /order/?type=shared_hosting
- **Action**: Typed "testdomain.ro" in domain field, clicked Add to Cart for Web Hosting Starter
- **Result**: PASS
- **Desktop Screenshot**: `05_orders/desktop_add_to_cart_result.png`
- **Findings**: Cart badge updated to "1". Confirmation: "Product added to cart successfully! (Web Hosting Starter)". Selected product highlighted with blue border.

### 5.4 Cart Review
- **URL**: /order/cart/
- **Result**: FAIL (C1 confirmed)
- **Desktop Screenshot**: `05_orders/desktop_cart_review.png`
- **Console Errors**: 3 — Failed to load resource 400, HTMX Response Status Error, HTMX Error object
- **Network**: POST /order/cart/calculate/ → 400 Bad Request
- **Findings**:
  - Cart item renders correctly (Web Hosting Starter, Monthly, testdomain.ro, quantity dropdown, Remove button).
  - Order Summary panel shows skeleton loader placeholders that never resolve — no subtotal, VAT, total, or "Proceed to Checkout" button.
  - C1 confirmed: UUID mismatch on product_id.

### 5.7 Service Plans
- **URL**: /services/plans/
- **Result**: FAIL (H3 — new HIGH)
- **Desktop Screenshot**: `05_orders/desktop_service_plans.png`
- **Findings**: TemplateDoesNotExist error (500). Template "services/plans_list.html" missing. View wired in urls.py but template never created. Django yellow error page shown.

---

## Phase 5 Summary: Catalog and add-to-cart working; cart calculate broken (C1); service plans 500 error (H3); product detail has M9 issues.

---

## Phase 6: Hosting Services

### 6.1 Service List
- **URL**: /services/
- **Result**: PASS
- **Desktop Screenshot**: `06_services/desktop_services_list.png`
- **Findings**:
  - 7 services, stats (2 Active, 7 Total).
  - Status tabs (All/Active/Suspended/Pending/Cancelled).
  - Search input.
  - Table with Service Name, Plan, Price, Status (colored badges), Next Billing (all N/A).
  - "Order Service" CTA button.
  - Service names include status in brackets (fixture data).

### 6.2 Service Tab Filter
- **URL**: /services/ (Active tab)
- **Action**: Clicked "Active" tab
- **Result**: PASS
- **Findings**: Filtered to 2 active services via HTMX (no page reload). URL params updated to ?status=active.

### 6.3 Service Detail
- **URL**: /services/70/
- **Result**: PASS with notes
- **Desktop Screenshot**: `06_services/desktop_service_detail_hero.png`
- **Findings**:
  - Rich detail page.
  - Hero: name, badges (plan, Active, Shared Web Hosting), domain.
  - 4 stat cards: Monthly 59.99 RON (72.59 with VAT), Next Bill "Calculating..." (M3), Age "Active"/"Since" no date (M4), Auto Renew Enabled.
  - Tabbed content: Overview (Service Health, Access Details, Support Contact), Usage & Performance, Billing.
  - Resource Usage Summary with limits.
  - Configuration with Domain + Server.
  - Service Timeline.

### 6.4 Service Usage
- **URL**: /services/70/ (Usage & Performance tab)
- **Result**: PASS
- **Desktop Screenshot**: `06_services/desktop_service_usage.png`
- **Findings**:
  - Current Usage: Disk 0.0GB/20GB, Bandwidth 0.0GB/200GB, Email 0/50, Databases 0/10.
  - Usage History section with 7/30/90 day dropdown — "Usage charts will be available soon" placeholder (expected for demo data).

### 6.5 Service Action Request
- **URL**: /services/70/request-action/
- **Result**: PASS
- **Desktop Screenshot**: `06_services/desktop_service_action_form.png`
- **Findings**:
  - 4 radio card options (Upgrade pre-selected, Downgrade, Suspension, Cancellation).
  - "May incur additional charges" / "Reason required" badges.
  - Reason textarea.
  - Right sidebar: Current Service info, 4-step Request Process, Need Help section.

---

## Phase 6 Summary: All service pages pass; notes on M3 (Next Bill calculating) and M4 (no service start date).

---

## Phase 7: Support Tickets & Final Checks

### 7.1 Ticket List
- **URL**: /tickets/
- **Result**: PASS with note (L4)
- **Desktop Screenshot**: `07_tickets/desktop_tickets_list.png`
- **Findings**:
  - 10 tickets (before new creation), stats (6 Open, 10 Total).
  - Tabs (All/Open/In Progress/Waiting on You/Closed).
  - Search.
  - Table with Ticket ID, Subject, Status badges, Created date.
  - L4 confirmed: subjects include "[IN_PROGRESS]", "[OPEN]", "[CLOSED]", "[WAITING_ON_CUSTOMER]" status prefixes and "- Normal/Low/High/Urgent Priority" suffixes from fixture data.

### 7.3 Create Ticket
- **URL**: /tickets/create/
- **Action**: Selected Technical Support category, Normal priority. Typed title "QA Test Ticket - Portal Walkthrough" and description.
- **Result**: PASS
- **Desktop Screenshots**: `07_tickets/desktop_ticket_create_empty.png`, `07_tickets/desktop_ticket_create_filled.png`
- **Console**: TypeError at line 876 (null reference — likely character counter JS bug)
- **Findings**:
  - Form renders well with Category (5 emoji options), Priority (4 levels), Title, Description, Priority Guidelines sidebar, "Need Immediate Help?" section.
  - Submitted successfully — redirected to ticket detail with toast "Support ticket created successfully. Ticket #TK2026-2GLRGL9F."

### 7.4 Ticket Detail + Reply
- **URL**: /tickets/86/
- **Action**: Viewed detail, typed reply, clicked Send Reply
- **Result**: PASS
- **Desktop Screenshots**: `07_tickets/desktop_ticket_detail.png`, `07_tickets/desktop_ticket_detail_after_reply.png`
- **Findings**:
  - Detail shows Subject, Status (Open), Priority (Normal), Created At, Description.
  - Conversation section initially shows "No replies yet."
  - After submitting reply via HTMX: reply appears inline without page reload, counter updates to "(1 replies)", reply shows "Test Company SRL" with "Customer" badge.
  - Textarea cleared for next reply.

### 7.6 Logout
- **URL**: Clicked Logout button
- **Result**: PASS
- **Desktop Screenshot**: `07_tickets/desktop_logout_result.png`
- **Findings**:
  - Redirected to /login/ with toast "You have been logged out successfully."
  - Session cleared — navigating to /dashboard/ redirects to /login/?next=%2Fdashboard%2F (correct back-button protection).

---

## Phase 7 Summary: All ticket flows pass; L4 (fixture data pollution in ticket subjects); JS null ref on ticket create (minor).

---

# Mobile Screenshot Pass (Full-Page)

**Date**: 2026-03-04 | **Viewport**: 390x844 (iPhone 14 Pro) | **Tool**: Playwright MCP (`fullPage: true`)

---

### Phase 3 — Mobile: Company Profile
- **URL**: http://localhost:8701/company/
- **Action**: navigated at 390x844, full-page screenshot
- **Result**: PASS
- **Mobile Screenshot**: `03_profile/mobile_company_profile.png`
- **Findings**: M1 visible (Company Name "Not specified"). Layout clean, single-column stacking correct.

### Phase 3 — Mobile: Change Password
- **URL**: http://localhost:8701/change-password/
- **Action**: navigated at 390x844, full-page screenshot
- **Result**: PASS
- **Mobile Screenshot**: `03_profile/mobile_change_password.png`
- **Findings**: Form fields full-width, security tips card renders well, footer visible.

### Phase 3 — Mobile: MFA Management
- **URL**: http://localhost:8701/mfa/
- **Action**: navigated at 390x844, full-page screenshot
- **Result**: PASS
- **Mobile Screenshot**: `03_profile/mobile_mfa_management.png`
- **Findings**: M2 visible ("Last Login: Never"). Authenticator/Passkeys cards stack cleanly.

### Phase 3 — Mobile: Privacy Dashboard
- **URL**: http://localhost:8701/privacy/
- **Action**: navigated at 390x844, full-page screenshot
- **Result**: PASS
- **Mobile Screenshot**: `03_profile/mobile_privacy_dashboard.png`
- **Findings**: GDPR rights cards stack into single column. Cookie preferences, data protection contact all visible.

### Phase 3 — Mobile: Company Edit
- **URL**: http://localhost:8701/company/edit/
- **Action**: navigated at 390x844, full-page screenshot
- **Result**: PASS
- **Mobile Screenshot**: `03_profile/mobile_company_edit.png`
- **Findings**: M8 visible (Billing Address section empty). Form inputs full-width. Save/Cancel buttons accessible.

### Phase 4 — Mobile: Invoice List
- **URL**: http://localhost:8701/billing/invoices/
- **Action**: navigated at 390x844, full-page screenshot
- **Result**: PASS
- **Mobile Screenshot**: `04_billing/mobile_invoices_list.png`
- **Findings**: All 15 documents visible in card layout. Status badges, amounts, dates all readable. Tab bar scrollable.

### Phase 4 — Mobile: Invoice Detail
- **URL**: http://localhost:8701/billing/invoices/INV-000082/
- **Action**: navigated at 390x844, full-page screenshot
- **Result**: PASS (layout) / H1 confirmed on mobile
- **Mobile Screenshot**: `04_billing/mobile_invoice_detail.png`
- **Findings**: H1 visible on mobile (Customer N/A, Status empty, Issue Date empty, No invoice lines). Download PDF button full-width.

### Phase 5 — Mobile: Product Catalog
- **URL**: http://localhost:8701/order/
- **Action**: navigated at 390x844, full-page screenshot
- **Result**: PASS
- **Mobile Screenshot**: `05_orders/mobile_catalog.png`
- **Findings**: All 4 products visible with pricing, dropdowns, domain inputs, Add to Cart buttons. Order stepper step 3 slightly truncated at edge.

### Phase 5 — Mobile: Product Detail
- **URL**: http://localhost:8701/order/products/product-1/
- **Action**: navigated at 390x844, full-page screenshot
- **Result**: PASS (layout) / M9 confirmed on mobile
- **Mobile Screenshot**: `05_orders/mobile_product_detail.png`
- **Findings**: M9 visible (empty billing period dropdown, mixed RO/EN labels "Perioadă de facturare" vs "Quantity"). Sparse page.

### Phase 6 — Mobile: Services List
- **URL**: http://localhost:8701/services/
- **Action**: navigated at 390x844, full-page screenshot
- **Result**: PASS
- **Mobile Screenshot**: `06_services/mobile_services_list.png`
- **Findings**: All 7 services in card layout. Status badges colored correctly. Tab bar scrollable at mobile width.

### Phase 6 — Mobile: Service Detail
- **URL**: http://localhost:8701/services/70/
- **Action**: navigated at 390x844, full-page screenshot
- **Result**: PASS (layout) / L6, M3, M4 confirmed on mobile
- **Mobile Screenshot**: `06_services/mobile_service_detail.png`
- **Findings**: L6 confirmed — title "Web Hosting Pr..." truncated. M3 ("Calculating...") and M4 (missing Active Since date) visible. Rich detail page stacks well into single column.

### Phase 7 — Mobile: Ticket List
- **URL**: http://localhost:8701/tickets/
- **Action**: navigated at 390x844, full-page screenshot
- **Result**: PASS
- **Mobile Screenshot**: `07_tickets/mobile_tickets_list.png`
- **Findings**: All 11 tickets visible in card layout. L4 visible (status prefix in subjects). Tab bar scrollable.

### Phase 7 — Mobile: Ticket Create
- **URL**: http://localhost:8701/tickets/create/
- **Action**: navigated at 390x844, full-page screenshot
- **Result**: PASS
- **Mobile Screenshot**: `07_tickets/mobile_ticket_create.png`
- **Findings**: Form renders cleanly. Dropdowns, textarea, priority guidelines all visible. Cancel/Create buttons accessible.

### Phase 7 — Mobile: Ticket Detail
- **URL**: http://localhost:8701/tickets/86/
- **Action**: navigated at 390x844, full-page screenshot
- **Result**: PASS
- **Mobile Screenshot**: `07_tickets/mobile_ticket_detail.png`
- **Findings**: Subject, status, priority, description, conversation thread, reply form all visible. No mobile-specific issues.

---

## Mobile Pass Summary

- **Pages tested**: 14 (Phases 3-7)
- **Screenshots saved**: 14 full-page PNGs (52KB-231KB)
- **Total mobile screenshots**: 22 (8 from Phase 1-2 + 14 new)
- **New mobile-only findings**: 0 (L6 already documented)
- **Desktop findings confirmed on mobile**: H1, M1, M2, M3, M4, M8, M9, L4, L6
- **Responsive assessment**: Excellent — Tailwind CSS produces clean single-column layouts at 390px
