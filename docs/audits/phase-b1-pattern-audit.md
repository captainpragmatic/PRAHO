# Phase B.1 — Portal Template Pattern Audit

> **Date**: 2026-03-05
> **Scope**: `services/portal/templates/` (all subdirectories)
> **Purpose**: Identify all repeated page-header, section-card, stat-tile, empty-state, and raw-badge patterns to inform the `page_header`, `section_card`, `stat_tile`, and `empty_state` component extractions planned in Phase B.1.

---

## Summary

| Pattern | Occurrences | Unique files | Status |
|---------|-------------|-------------|--------|
| **Page header** (title + subtitle + actions) | 22 | 20 | 3 use `list_page_header.html`; 19 are ad-hoc |
| **Section card** (`bg-slate-800` card with titled section) | 31 | 14 | All ad-hoc |
| **Section card title** (`h3` with `border-b border-slate-600`) | 6 | 1 (`proforma_detail.html`) | All ad-hoc |
| **Stat tile** (label + value metric in grid) | 8 grids / 24 tiles | 5 | All ad-hoc |
| **Empty state** (icon + title + message + CTA) | 14 | 11 | All ad-hoc |
| **Raw status badges** (`bg-*-100 text-*-800`) | 60+ | 10 | Outside `badge.html` internals |

---

## 1. Page Header Pattern

Pages that render a page-level heading (h1), optional subtitle (p), and optional action buttons area.

### Already Using `list_page_header.html` Component (3 pages)

| File | Line | Notes |
|------|------|-------|
| `billing/invoices_list.html` | L10 | `{% include "components/list_page_header.html" with ... %}` |
| `services/service_list.html` | L10 | Same pattern |
| `tickets/ticket_list.html` | L10 | Same pattern |

### Ad-Hoc Page Headers — `sm:flex sm:items-center` Pattern (2 pages)

| File | Line(s) | Description |
|------|---------|-------------|
| `billing/invoice_detail.html` | L11-28 | `<div class="sm:flex sm:items-center">` with h1 + subtitle + PDF/refund action buttons |
| `billing/proforma_detail.html` | L11-36 | `<div class="sm:flex sm:items-center mb-6">` with h1 + subtitle + PDF/back buttons |

### Ad-Hoc Page Headers — Simple `<h1>` with Subtitle (17 pages)

| File | Line(s) | H1 class | Has subtitle | Has actions |
|------|---------|----------|--------------|-------------|
| `dashboard/dashboard.html` | L23-31 | `text-3xl font-bold text-white` | ✅ (p tag) | ❌ |
| `dashboard/account_overview.html` | L20-21 | `text-3xl font-bold text-white` | ✅ | ❌ |
| `users/profile.html` | L11 | `text-2xl font-bold text-white romanian-flag` | ❌ | ❌ |
| `users/mfa_management.html` | L11 | `text-2xl font-bold text-white romanian-flag` | ❌ | ❌ |
| `users/mfa_setup_totp.html` | L11 | `text-2xl font-bold text-white romanian-flag` | ❌ | ❌ |
| `users/mfa_backup_codes.html` | L11 | `text-2xl font-bold text-white romanian-flag` | ❌ | ❌ |
| `users/change_password.html` | L12 | `text-2xl font-bold text-white romanian-flag` | ❌ | ❌ |
| `users/data_export.html` | L11 | `text-2xl font-bold text-white romanian-flag` | ❌ | ❌ |
| `users/privacy_dashboard.html` | L11 | `text-2xl font-bold text-white romanian-flag` | ❌ | ❌ |
| `users/consent_history.html` | L11 | `text-2xl font-bold text-white romanian-flag` | ❌ | ❌ |
| `users/company_profile.html` | L13 | `text-3xl font-bold text-white` | ❌ | ❌ |
| `users/company_profile_edit.html` | L13 | `text-3xl font-bold text-white` | ❌ | ❌ |
| `users/create_company.html` | L21 | `text-3xl font-bold text-white` | ❌ | ❌ |
| `orders/product_catalog.html` | L16 | `text-2xl sm:text-3xl font-bold text-white` | ✅ | ❌ |
| `orders/cart_review.html` | L14 | `text-3xl font-bold text-white` | ✅ | ❌ |
| `orders/checkout.html` | L15 | `text-3xl font-bold text-white` | ✅ | ❌ |
| `orders/order_confirmation.html` | L16 | `text-3xl font-bold text-green-400` | ✅ | ❌ |
| `services/service_detail.html` | L48 | `text-2xl sm:text-3xl font-bold text-white truncate` | ✅ (complex) | ✅ (action buttons) |
| `services/service_request_action.html` | L25 | `text-2xl font-bold text-white` | ❌ | ❌ |
| `services/plans_list.html` | L12 | `text-3xl font-bold text-white` | ✅ | ❌ |
| `services/service_usage.html` | L13 | `text-3xl font-bold text-gray-900 dark:text-white` | ✅ | ❌ |
| `tickets/ticket_create.html` | L15 | `text-2xl font-bold text-white mt-4 romanian-flag` | ✅ | ❌ |
| `tickets/ticket_detail.html` | L15 | `text-3xl font-bold text-white` | ❌ | ❌ |
| `billing/invoice_not_found.html` | L12 | `text-3xl font-bold text-white` | ❌ | ❌ |
| `billing/proforma_not_found.html` | L12 | `text-3xl font-bold text-white` | ❌ | ❌ |
| `legal/cookie_policy.html` | L10 | `text-2xl font-bold text-white` | ❌ | ❌ |

### Key Inconsistencies

- **Font sizes**: Mix of `text-2xl`, `text-3xl`, `text-2xl sm:text-3xl` — no single canonical size.
- **Romanian flag**: 8 `users/` pages add `romanian-flag` class; no other section uses it.
- **Subtitle presence**: ~12 pages have subtitles, ~10 don't — no consistent pattern.
- **Action buttons**: Only 3 pages (`invoice_detail`, `proforma_detail`, `service_detail`) have header actions, all hand-crafted differently.

---

## 2. Section Card Pattern

Templates using `bg-slate-800 rounded-lg border border-slate-700` as container cards.

| File | Line(s) | Padding | Has titled header | Notes |
|------|---------|---------|-------------------|-------|
| `billing/proforma_detail.html` | L54 | `p-6` | ✅ h3 `border-b border-slate-600 pb-3 mb-4` | Client Details |
| `billing/proforma_detail.html` | L102 | `p-4 sm:p-6` | ✅ h3 `border-b border-slate-600 pb-3 mb-4` | Line Items |
| `billing/proforma_detail.html` | L193 | `p-6` | ✅ h3 `border-b border-slate-600 pb-3 mb-4` | Proforma Details |
| `billing/proforma_detail.html` | L209 | `p-6 sticky top-4` | ✅ h3 `border-b border-slate-600 pb-3 mb-4` | Payment Summary |
| `billing/proforma_detail.html` | L254 | `p-6` | ✅ h3 `border-b border-slate-600 pb-3 mb-4` | Actions |
| `billing/proforma_detail.html` | L280 | `p-6` | ✅ h3 `border-b border-slate-600 pb-3 mb-4` | Need Help? |
| `billing/invoice_not_found.html` | L18 | `p-8 text-center` | ❌ | Error page card |
| `billing/proforma_not_found.html` | L18 | `p-8 text-center` | ❌ | Error page card |
| `dashboard/dashboard.html` | L93 | None (inner `p-6`) | ✅ h3 `text-lg font-medium text-white mb-4` | Recent Invoices |
| `dashboard/dashboard.html` | L147 | None (inner `p-6`) | ✅ h3 `text-lg font-medium text-white mb-4` | Recent Tickets |
| `dashboard/dashboard.html` | L201 | None (inner `p-6`) | ✅ h3 `text-lg font-medium text-white mb-4` | Quick Actions |
| `dashboard/dashboard.html` | L225 | None (inner `p-6`) | ✅ h3 `text-lg font-medium text-white` | Account Information |
| `dashboard/account_overview.html` | L25 | `p-6 mb-6` | ✅ h2 `text-xl font-semibold` | Account Details |
| `dashboard/account_overview.html` | L52 | `p-6` | ✅ h2 (assumed) | Customer Details |
| `orders/cart_review.html` | L23 | None | ❌ | Cart items container |
| `orders/cart_review.html` | L149 | `sticky top-8` | ❌ | Order summary sidebar |
| `orders/checkout.html` | L26 | None | ❌ | Checkout form container |
| `orders/checkout.html` | L229 | `sticky top-8` | ❌ | Order summary sidebar |
| `orders/product_catalog.html` | L77 | None | ❌ | Product cards (with hover) |
| `orders/order_confirmation.html` | L25 | None | ❌ | Confirmation card |
| `services/service_detail.html` | L229 | None | ❌ | Tabbed content wrapper |
| `services/service_request_action.html` | L35 | `p-6` | ✅ | Service info card |
| `services/service_request_action.html` | L197 | `p-6` | ✅ | Request form card |
| `services/service_request_action.html` | L234 | `p-6` | ✅ | How it works card |
| `services/service_request_action.html` | L281 | `p-6` | ✅ | Need help card |
| `services/plans_list.html` | L52 | None | ❌ | Plan cards (with hover) |
| `tickets/ticket_create.html` | L24 | None | ❌ | Create form card |
| `tickets/ticket_create.html` | L153 | `p-6` | ✅ | Tips & Guidelines card |
| `tickets/partials/status_and_comments.html` | L82 | None | ❌ | Replies section |

### Section Card Title Variants

Two distinct title styles exist:

1. **Proforma style** (6 occurrences, 1 file): `<h3 class="text-lg font-semibold text-white border-b border-slate-600 pb-3 mb-4">`
2. **Dashboard style** (4 occurrences, 1 file): `<h3 class="text-lg font-medium text-white mb-4">` (no border)

### Key Inconsistencies

- **Padding**: Mix of `p-6`, `p-4 sm:p-6`, `p-8`, and "no padding with inner p-6".
- **Title element**: Mix of `h2` and `h3`.
- **Title weight**: `font-semibold` (proforma) vs `font-medium` (dashboard) — no standard.
- **Title border**: Only `proforma_detail.html` uses `border-b border-slate-600 pb-3`.
- **Modifier classes**: Some add `sticky top-8`, `text-center`, hover effects — no systematic variant system.

---

## 3. Stat Tile Pattern

Templates displaying key metrics in a grid layout (label + value pairs).

### Dashboard Stat Cards

| File | Line(s) | Grid | Tiles | Tile structure |
|------|---------|------|-------|----------------|
| `dashboard/dashboard.html` | L36-89 | `grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6` | 4 | `bg-slate-800 p-6 border-slate-700` card → icon + label (`text-sm text-slate-400`) + value (`text-2xl font-semibold text-white`) |

### Service Detail Stat Tiles

| File | Line(s) | Grid | Tiles | Tile structure |
|------|---------|------|-------|----------------|
| `services/service_detail.html` | L134-220 | `grid-cols-2 lg:grid-cols-4 gap-3 sm:gap-4` | 4 | `bg-slate-700/50 p-4 border-slate-600/50` card → icon + label (`text-xs text-slate-400 uppercase`) + value (`text-xl font-bold text-white`) + meta sub-line |

### Service Detail Resource Stats

| File | Line(s) | Grid | Tiles | Tile structure |
|------|---------|------|-------|----------------|
| `services/service_detail.html` | L390-430 | `grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4` | 4 | `bg-slate-700/50 p-4` → value (`text-2xl font-bold text-*-400`) + meta (`text-sm text-slate-400`) — usage bars |

### Usage Chart Stats

| File | Line(s) | Grid | Tiles | Tile structure |
|------|---------|------|-------|----------------|
| `services/partials/usage_chart.html` | L15-105 | `grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4` | 4 | `bg-white dark:bg-gray-800 p-4` → value (`text-2xl font-bold text-*-400`) + label (`text-xs text-slate-400`) |

### Service Usage Page Stats

| File | Line(s) | Grid | Tiles | Tile structure |
|------|---------|------|-------|----------------|
| `services/service_usage.html` | L73-120 | `grid-cols-1 md:grid-cols-3 gap-6` | 3 | `bg-white dark:bg-gray-800 p-6` → value (`text-3xl font-bold`) + sub-labels |

### Dashboard Quick Actions Grid

| File | Line(s) | Grid | Tiles | Tile structure |
|------|---------|------|-------|----------------|
| `dashboard/dashboard.html` | L207-220 | `grid-cols-2 gap-3` | 4 | Action buttons in grid — not stat tiles per se |

### List Page Header Inline Stats

| File | Line(s) | Grid | Description |
|------|---------|------|-------------|
| `components/list_page_header.html` | L59-63 | `grid-cols-{{ stats\|length }}` | Inline stat counters in header (already componentized) |

### Key Inconsistencies

- **Background colors**: `bg-slate-800` (dashboard) vs `bg-slate-700/50` (service detail) vs `bg-white dark:bg-gray-800` (usage).
- **Value sizes**: `text-2xl font-semibold` (dashboard) vs `text-xl font-bold` (service detail) vs `text-3xl font-bold` (usage).
- **Label sizes**: `text-sm font-medium` (dashboard) vs `text-xs uppercase tracking-wide` (service detail) vs `text-xs` (usage chart).
- **Color scheme**: Some stat values are colored (`text-green-400`, `text-blue-400`); others are `text-white`.
- **Icon placement**: Dashboard puts icon before all text; service detail puts icon inline with label; usage chart has no icon.

---

## 4. Empty State Pattern

Templates showing "no data" messages with icon, title, description, and optional CTA.

### Full Empty State Blocks (icon + title + body + CTA)

| File | Line(s) | Icon | Title | Has CTA | Notes |
|------|---------|------|-------|---------|-------|
| `services/partials/services_table.html` | L156-168 | `{% icon "server" %}` | "No services found" | ✅ (Browse plans + Contact support) | `bg-slate-800/50 border-slate-700` container |
| `tickets/partials/tickets_table.html` | L173-209 | `{% icon "chat" %}` | "No Support Tickets Yet" | ✅ (Create ticket + common reasons list) | `bg-slate-800/50 border-slate-700` container, most elaborate |
| `billing/partials/invoices_table.html` | L146-163 | `{% icon "document" %}` | "No documents found" | ✅ (Browse plans) | `bg-slate-800/50 border-slate-700` container |
| `orders/product_catalog.html` | L210-228 | `{% icon "orders" %}` | "No products found" / "No products available" | ✅ (View all products) | No container card — bare `text-center py-16` |
| `services/plans_list.html` | L165-183 | `{% icon "document" %}` | "No Plans Available" | ✅ (Back to Services) | `flex flex-col items-center py-12` — no card container |

### Inline Empty State Blocks (text only, inside `{% empty %}`)

| File | Line(s) | Message | Notes |
|------|---------|---------|-------|
| `dashboard/dashboard.html` | L131-133 | "No recent documents found" | Simple `<p class="text-slate-400 text-center py-4">` |
| `dashboard/dashboard.html` | L185-187 | "No recent support tickets" | Same simple pattern |
| `billing/proforma_detail.html` | L148-151 | "No items found" | Inside line-items `{% for %}` |
| `billing/proforma_detail.html` | L183-185 | "No items found" | Inside summary section `{% for %}` |
| `billing/invoice_detail.html` | L149-152 | "No invoice lines found" | Inside items table |
| `billing/invoice_detail.html` | L209-211 | "No invoice lines found" | Inside mobile card view |
| `orders/cart_review.html` | L121-134 | "Your cart is empty" | Inside `{% for %}` — has icon + CTA |
| `tickets/partials/replies_list.html` | L68-71 | "No replies yet. Be the first to respond!" | Simple inline |
| `users/profile.html` | L350-356 | "No company profiles found" | Inside `{% for %}` |
| `users/consent_history.html` | L113 | (inside `{% empty %}`) | Likely similar pattern |
| `components/customer_selector.html` | L86 | (inside `{% empty %}`) | Dropdown empty state |

### Key Inconsistencies

- **Container**: 3 use `bg-slate-800/50 border-slate-700 rounded-lg`; 2 have no card container; rest are inline `<p>` tags.
- **Icon size**: Mix of `size="xl"`, `size="2xl"` — no standard.
- **Icon container**: Table empties use `h-16 w-16 bg-slate-700 rounded-full`; others have bare icon.
- **Title element**: Mix of `<h3 class="text-lg font-medium">` and `<h3 class="text-xl font-medium">`.
- **CTA style**: Each page builds its own button classes — no shared empty-state action button pattern.
- **Elaborateness**: `tickets_table.html` has a 40-line empty state with tag pills; `dashboard.html` has a 1-line `<p>`.

---

## 5. Raw Status Badge Patterns (Outside `badge.html`)

Templates using raw `bg-*-100 text-*-800` (or `bg-*-900 text-*-200`) patterns instead of the `{% badge %}` component.

### services/partials/services_table.html — **18 raw badges**

| Line(s) | Colors | Status |
|---------|--------|--------|
| L46 | `bg-green-100 text-green-800` | Active |
| L50 | `bg-red-100 text-red-800` | Suspended |
| L54 | `bg-yellow-100 text-yellow-800` | Pending |
| L58 | `bg-blue-100 text-blue-800` | Provisioning |
| L62 | `bg-red-100 text-red-800` | Cancelled |
| L66-74 | `bg-gray-100 text-gray-800` | Expired / Terminated / Default |
| L102-130 | (Same 9 repeated for mobile view) | Duplicate of desktop status badges |

### tickets/partials/tickets_table.html — **12 raw badges**

| Line(s) | Colors | Status |
|---------|--------|--------|
| L61 | `bg-blue-100 text-blue-800` | Open |
| L65 | `bg-purple-100 text-purple-800` | In Progress |
| L69 | `bg-yellow-100 text-yellow-800` | Waiting |
| L73, L82 | `bg-gray-100 text-gray-800` | Closed / Default |
| L89 | `bg-green-100 text-green-800` | SLA compliant |
| L121-149 | (Same repeated for mobile view) | Duplicate of desktop status badges |

### services/service_detail.html — **5 raw badges**

| Line(s) | Colors | Status |
|---------|--------|--------|
| L543 | `bg-green-100 text-green-800` | Healthy |
| L548 | `bg-yellow-100 text-yellow-800` | Warning |
| L553 | `bg-gray-100 text-gray-800` | Unknown |
| L936 | `bg-green-100 text-green-800` | Active (addon) |
| L940 | `bg-gray-100 text-gray-800` | Inactive (addon) |

### users/privacy_dashboard.html — **4 raw badges**

| Line(s) | Colors | Status |
|---------|--------|--------|
| L42 | `bg-green-100 text-green-800` | Consented |
| L46 | `bg-red-100 text-red-800` | Not consented |
| L62 | `bg-blue-100 text-blue-800` | Active retention |
| L66 | `bg-gray-100 text-gray-800` | Default |

### users/consent_history.html — **4 raw badges**

| Line(s) | Colors | Status |
|---------|--------|--------|
| L35 | `bg-green-100 text-green-800` | Granted |
| L39 | `bg-red-100 text-red-800` | Revoked |
| L58 | `bg-blue-100 text-blue-800` | ? |
| L62 | `bg-gray-100 text-gray-800` | Default |

### users/data_export.html — **4 raw badges**

| Line(s) | Colors | Status |
|---------|--------|--------|
| L169 | `bg-green-100 text-green-800` | Completed |
| L170 | `bg-yellow-100 text-yellow-800` | Processing |
| L171 | `bg-blue-100 text-blue-800` | Pending |
| L172 | `bg-red-100 text-red-800` | Error/other |

### users/change_password.html — **1 raw badge**

| Line(s) | Colors | Status |
|---------|--------|--------|
| L75 | `bg-green-100 text-green-800` | 2FA enabled |

### orders/product_catalog.html — **1 raw badge**

| Line(s) | Colors | Status |
|---------|--------|--------|
| L82 | `bg-green-100 text-green-800` | In stock / available |

### tickets/partials/replies_list.html — **4 raw badges**

| Line(s) | Colors | Status |
|---------|--------|--------|
| L10 | `bg-blue-100 text-blue-800` / `bg-green-100 text-green-800` | Staff vs Customer reply |
| L26 | `bg-blue-100 text-blue-800` | Staff badge |
| L31 | `bg-green-100 text-green-800` | Customer badge |

### tickets/partials/status_and_comments.html — **1 raw badge**

| Line(s) | Colors | Status |
|---------|--------|--------|
| L33 | `bg-green-100 text-green-800` | Resolved |

### components/nav_dropdown.html — **3 raw badges (dark variant)**

| Line(s) | Colors | Status |
|---------|--------|--------|
| L48 | `bg-green-900 text-green-200` | Active |
| L52 | `bg-yellow-900 text-yellow-200` | Warning |
| L56 | `bg-red-900 text-red-200` | Error |

### services/service_usage.html — **6 raw color classes (toggle buttons, not badges)**

| Line(s) | Colors | Notes |
|---------|--------|-------|
| L35, L38, L41 | `bg-blue-100 text-blue-800` / `bg-gray-100 text-gray-800` | Period toggle buttons (24h/7d/30d), not status badges |
| L182-184 | Same in JS | Dynamic class swapping for active state |

---

## Recommendations for Phase B.1 Implementation

### Priority Order

1. **`page_header` component** — 22 ad-hoc headers. Standardize to a single `{% page_header %}` tag wrapping title, subtitle, `romanian-flag` class, and actions slot.

2. **`section_card` component** — 31 card containers. Standardize the card wrapper + optional titled header with `border-b` separator.

3. **`empty_state` component** — 14 empty states. Standardize icon + title + body + optional CTA into a single `{% empty_state %}` tag.

4. **`stat_tile` component** — 24 tiles across 5 pages. Standardize icon + label + value + meta into `{% stat_tile %}` tag with size/color variants.

5. **Raw badge migration** — 57+ raw badges across 10 files. Migrate to `{% badge variant=... %}` after adding `status_variant` template tag (planned in B.3).

### Highest-Impact Files

| File | Patterns contained | Est. line reduction |
|------|-------------------|---------------------|
| `services/service_detail.html` (976L) | page_header + stat_tiles (8) + section_cards (5+) + raw badges (5) | ~200-300 lines |
| `billing/proforma_detail.html` (307L) | page_header + section_cards (6) + empty states (2) | ~80-100 lines |
| `services/partials/services_table.html` (170L) | raw badges (18) + empty state (1) | ~60-80 lines |
| `tickets/partials/tickets_table.html` (209L) | raw badges (12) + empty state (1) | ~60-80 lines |
| `dashboard/dashboard.html` (261L) | stat_tiles (4) + section_cards (4) + empty states (2) | ~60-80 lines |
