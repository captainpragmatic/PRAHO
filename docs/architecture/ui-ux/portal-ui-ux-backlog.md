# Portal UI/UX Implementation Backlog

> **Status**: Active roadmap
> **Owner**: PRAHO Platform Team
> **Last updated**: 2026-03-04
> **Companion**: [portal-design-system.md](portal-design-system.md) (specification)
> **Estimated total**: ~8-10 weeks across 4 phases

---

## Scope

- **Service**: `services/portal` (customer-facing)
- **Goal**: Migrate from ad-hoc shared styles → enforceable design system with consistent spacing, typography, feedback, HTMX states, and responsive behavior.
- **Guiding principle**: Work outward from highest-traffic, highest-trust pages first.

---

## Current Reuse Snapshot

### Existing Reusable Layer
- **Template tag API**: `services/portal/apps/ui/templatetags/ui_components.py` (16 tags, 937 lines)
- **Component templates**: `services/portal/templates/components/*.html` (25 templates)
- **List-page pattern** (good baseline, already used in 3+ pages):
  - `components/list_page_header.html`
  - `components/list_page_filters.html`
  - `components/list_page_skeleton.html`

### Highest-Leverage Refactor Targets (by template size)
| Template | Lines | Impact |
|----------|-------|--------|
| `services/service_detail.html` | 976 | Most complex customer page |
| `users/profile.html` | 545 | Profile management hub |
| `orders/order_confirmation.html` | 500 | Post-purchase experience |
| `orders/checkout.html` | 429 | Revenue-critical flow |
| `services/service_request_action.html` | 425 | Service management |
| `billing/invoice_detail.html` | 398 | Billing trust signals |

### Known Issues (from audit)
| # | Severity | Issue |
|---|----------|-------|
| 1 | 🔴 High | Toast: `base.html` has ~110 lines inline toast ignoring `{% toast %}` component |
| 2 | 🔴 High | Zero test coverage for all 16 UI template tags |
| 3 | 🟡 Medium | Duplicate `.brand-gradient` in `base.html` (lines 41-47) |
| 4 | 🟡 Medium | Dead code: `portal_mobile_header.html` (249 lines, never included) |
| 5 | 🟡 Medium | Inline `<style>` in 4 components (mobile_header, portal_mobile_header, button, cookie_consent) |
| 6 | 🟡 Medium | Inline `<script>` in 5 components (bypasses caching, fragile with multiple instances) |
| 7 | 🟡 Medium | Scrollbar styles duplicated between `base.html` and `mobile_header.html` |
| 8 | 🟢 Low | `modal.html` JS duplicated if multiple modals on same page |

---

## Phase A — Foundation & Trust (2 weeks)

> **Goal**: Fix what's broken, remove duplication, establish component-first patterns on the highest-traffic pages (auth flow + billing).

### A.1 Unify Auth Form Patterns
**Priority**: P0 | **Effort**: 3-4 days | **Risk**: Low

**Problem**: `login.html` and `register.html` manually style fields/errors, bypassing `input_field`, `checkbox_field`, `button`. Error UX differs across pages (toast-only vs. inline).

**Files to modify**:
- `services/portal/templates/users/login.html`
- `services/portal/templates/users/register.html`
- `services/portal/templates/users/password_reset.html`
- `services/portal/templates/users/change_password.html`
- `services/portal/templates/components/input.html` (minor — ensure error binding)
- `services/portal/templates/components/checkbox.html` (minor)
- `services/portal/templates/components/alert.html` (minor)
- `services/portal/templates/base.html` (add `aria-live` region)

**Deliverables**:
1. Replace all raw `<input>` / `<button>` elements with `{% input_field %}` / `{% button %}` tags.
2. Create `form_error_summary` component — `aria-live="assertive"` top-of-form error list.
3. Create `form_actions` component — standardized submit/cancel row with consistent alignment.
4. Add shared HTMX async error region in `base.html` (`aria-live="polite"`).
5. Ensure all four auth pages render identically: label → input → field error → summary.

**Acceptance criteria**:
- All auth forms use `{% input_field %}`, `{% checkbox_field %}`, `{% button %}`.
- Server-side validation errors appear both inline per-field AND in top summary.
- No raw `<input>`, `<select>`, `<button>` elements in auth templates.
- Screen reader announces form errors on submit.

---

### A.2 Normalize Billing Detail & Status Components
**Priority**: P0 | **Effort**: 2-3 days | **Risk**: Low

**Problem**: `invoice_detail.html` duplicates badge logic and table/card patterns. Detail page formatting diverges from list page style.

**Files to modify**:
- `services/portal/templates/billing/invoice_detail.html`
- `services/portal/templates/billing/proforma_detail.html`
- `services/portal/templates/components/badge.html`
- `services/portal/apps/billing/views.py` (status → variant mapping)

**Deliverables**:
1. Switch all status pills to `{% badge variant=status_variant %}` across invoice/proforma details.
2. Extract shared "document header meta row" partial component.
3. Extract shared "line-items table/card" partial component.
4. Ensure all money fields use consistent filter (`|format_currency`).
5. Ensure all date fields use consistent filter (`|format_date`).
6. Add missing-data placeholders (`—`) instead of blank cells.

**Acceptance criteria**:
- Invoice detail and proforma detail use identical layout structure.
- Zero raw `bg-*-100 text-*-800` badge classes in billing templates.
- Amount/date formatting matches across all billing pages.

---

### A.3 Remove Duplicated Global Style Sources
**Priority**: P0 | **Effort**: 2-3 days | **Risk**: Medium (visual regression)

**Problem**: Brand tokens/gradients defined in both `assets/css/input.css` AND inline in `base.html`. Multiple components have inline `<style>` blocks bypassing Tailwind build.

**Files to modify**:
- `services/portal/templates/base.html` (remove inline styles, toast HTML/JS)
- `services/portal/templates/components/button.html` (extract inline `<style>`)
- `services/portal/templates/components/mobile_header.html` (extract ~80 lines `<style>`)
- `assets/css/input.css` (absorb extracted styles)

**Deliverables**:
1. Remove duplicate `.brand-gradient` declaration from `base.html`.
2. Move `base.html` inline `<style>` block (48 lines) into `assets/css/input.css`.
3. Move `button.html` loading indicator styles (~20 lines) into CSS.
4. Move `mobile_header.html` styles (~80 lines) into CSS.
5. Remove scrollbar style duplication between `base.html` and `mobile_header.html`.
6. **Replace base.html inline toast** (~110 lines HTML + 30 lines JS) with `{% toast %}` component tag.
7. Rebuild Tailwind CSS and verify no visual regressions.

**Acceptance criteria**:
- `base.html` has zero inline `<style>` blocks.
- `button.html` has zero inline `<style>` blocks.
- `mobile_header.html` has zero inline `<style>` blocks.
- Toast rendering uses the `{% toast %}` component tag exclusively.
- `make build-css` succeeds and all pages render correctly.
- `grep -r '<style' services/portal/templates/` returns only `[x-cloak]` (1-liners).

---

### A.4 Canonicalize Mobile Header & Cookie Banner
**Priority**: P0 | **Effort**: 1-2 days | **Risk**: Low

**Problem**: Two mobile header implementations exist (`mobile_header.html` 355L and `portal_mobile_header.html` 249L). Cookie consent can obstruct primary controls on auth pages.

**Files to modify**:
- `services/portal/templates/components/mobile_header.html` (keep, clean up)
- `services/portal/templates/components/portal_mobile_header.html` (DELETE)
- `services/portal/templates/components/cookie_consent_banner.html`
- `services/portal/templates/base.html`

**Deliverables**:
1. Delete `portal_mobile_header.html` (confirmed dead code — not included anywhere).
2. Refactor `mobile_header.html`: extract inline JS to `static/js/mobile-nav.js`.
3. Refactor `cookie_consent_banner.html`: ensure non-obstructive bottom-sheet behavior with `max-height`, `overflow-y: auto`, and z-index below modal overlay.
4. Add CSS rule: cookie banner hidden on auth pages via body class.

**Acceptance criteria**:
- Only one mobile header component exists.
- `portal_mobile_header.html` is deleted.
- Cookie banner does not overlap form controls on login/register.
- Mobile nav JS is in a static file, not inline.

---

### A.5 Icon Standardization Pass
**Priority**: P0 | **Effort**: 1 day | **Risk**: Low

**Problem**: 11 emoji characters in 2 portal templates (`ticket_create.html`, `invoice_detail.html`) and 1 emoji default in Python (`empty_icon: str = "📋"` in `ui_components.py`). Some feature templates contain raw `<svg>` markup instead of using `{% icon %}` tag.

**Files to modify**:
- `services/portal/templates/tickets/ticket_create.html` (4 emojis in `<option>` tags)
- `services/portal/templates/billing/invoice_detail.html` (7 emojis in `<option>` tags)
- `services/portal/apps/ui/templatetags/ui_components.py` (line ~155, emoji default)
- Feature templates with raw `<svg>` elements (audit list from `grep -rl '<svg' services/portal/templates/` excluding `components/`)

**Deliverables**:
1. Replace emoji characters in `<option>` dropdown labels with text-only labels.
2. Change `empty_icon: str = "📋"` to `icon_name: str = "clipboard"` and render via `{% icon %}` in `empty_state.html`.
3. Audit feature templates for raw `<svg>` — migrate to `{% icon "name" %}` wherever a matching Heroicon exists.
4. Add any missing icons to `ICON_SVGS` dict in `ui_components.py`.

**Acceptance criteria**:
- `grep -rP '[\x{1F300}-\x{1FAFF}]' services/portal/templates/` returns 0 matches.
- `grep -P '[\x{1F300}-\x{1FAFF}]' services/portal/apps/ui/templatetags/ui_components.py` returns 0 matches.
- Feature templates (outside `components/`) have zero raw `<svg>` — all use `{% icon %}` tag.

---

### Phase A — Definition of Done

| Evidence artifact | Command / check |
|------------------|-----------------|
| No inline `<style>` blocks | `grep '<style' services/portal/templates/` returns ≤ 2 results (x-cloak only) |
| No dead mobile header | `grep -c 'portal_mobile_header' services/portal/templates/**/*.html` returns 0 |
| Toast uses component | `grep 'toast' services/portal/templates/base.html` shows `{% toast %}` tag |
| No emoji in UI | `grep -rP '[\x{1F300}-\x{1FAFF}]' services/portal/templates/` returns 0 |
| Auth forms use tags | Zero `<input>` / `<button>` in `users/login.html`, `register.html`, etc. |
| CSS builds clean | `make build-css` exits 0 |
| All tests pass | `make test-portal` exits 0 |
| E2E tests pass | `make test-e2e` exits 0 (update selectors if needed) |

### Phase A — E2E Test Maintenance

Phase A modifies **auth pages** and **billing detail** — these are covered by Playwright E2E tests.

| E2E test file | Risk area | Action |
|--------------|-----------|--------|
| `tests/e2e/test_portal_login_e2e.py` | Login form structure changes | Update selectors if `<input>` → `{% input_field %}` changes HTML structure |
| `tests/e2e/test_portal_register_e2e.py` | Register form structure | Same — verify `name=` and `id=` attrs preserved by component |
| `tests/e2e/test_portal_auth_e2e.py` | Auth flow selectors | Spot-check all `page.locator()` / `page.fill()` calls |
| `tests/e2e/test_portal_billing_e2e.py` | Invoice detail layout | Verify badge/status selectors after `{% badge %}` migration |
| `tests/e2e/test_portal_password_reset_e2e.py` | Password reset form | Update if form structure changes |

**Rule**: Every template file modified in Phase A must have its E2E selectors audited. If E2E tests break, fix them in the same PR — never merge with red E2E.

### Phase A Verification Checklist
- [ ] All auth pages use component tags exclusively.
- [ ] `grep '<style' services/portal/templates/` returns ≤ 2 results (x-cloak only).
- [ ] `grep -c 'portal_mobile_header' services/portal/templates/**/*.html` returns 0.
- [ ] Base.html toast uses `{% toast %}` component.
- [ ] No emoji characters in portal templates or Python tag defaults.
- [ ] Feature templates have zero raw `<svg>` — all migrated to `{% icon %}` tag.
- [ ] `make build-css && make test-portal` passes.
- [ ] `make test-e2e` passes (selectors updated as needed).
- [ ] Manual QA: login, register, password-reset, change-password, invoice-detail on mobile (375px).

---

## Phase B — Systematize (2-3 weeks)

> **Goal**: Create reusable layout primitives, formalize token conventions, migrate the largest templates.

### B.1 Create Page-Shell Primitives
**Priority**: P1 | **Effort**: 3-4 days | **Risk**: Low

**Problem**: Large pages manually recreate spacing/hierarchy with inconsistent padding, heading sizes, and section structure.

**Files to create**:
- `services/portal/templates/components/page_header.html`
- `services/portal/templates/components/section_card.html`
- `services/portal/templates/components/stat_tile.html`
- `services/portal/templates/components/empty_state.html`
- `services/portal/apps/ui/templatetags/ui_components.py` (add 4 new tags)

**Component APIs**:

```python
# page_header: title, subtitle, breadcrumbs, actions, stats
{% page_header title="Factura #INV-2024-0001" subtitle="Client: SC Example SRL" %}
  {% slot actions %}{% button "Descarcă PDF" variant="primary" %}{% endslot %}
{% end_page_header %}

# section_card: title, collapsible, variant
{% section_card title="Detalii factură" collapsible=True %}
  ...content...
{% end_section_card %}

# stat_tile: label, value, meta, trend, variant
{% stat_tile label="Total datorat" value="1.234,56 RON" meta="Scadent: 15.03.2026" variant="warning" %}

# empty_state: icon, title, body, action_url, action_text
{% empty_state icon="inbox" title="Nicio factură" body="Nu aveți facturi emise încă." action_url="/billing/" action_text="Vezi produse" %}
```

**Pages to migrate** (use new primitives):
- `services/portal/templates/users/profile.html` (545L)
- `services/portal/templates/users/company_profile.html`
- `services/portal/templates/users/company_profile_edit.html`
- `services/portal/templates/services/service_detail.html` (976L)
- `services/portal/templates/services/service_request_action.html` (425L)
- `services/portal/templates/orders/product_catalog.html`
- `services/portal/templates/orders/product_detail.html`

**Acceptance criteria**:
- All 4 primitives registered as template tags with dataclass configs.
- Each migrated page reduces line count by ≥ 20%.
- Consistent page-level spacing (page gutter, section stack) across all migrated pages.

---

### B.2 Establish Typography & Spacing Token Conventions
**Priority**: P1 | **Effort**: 2 days | **Risk**: Medium (visual changes)

**Problem**: Headings and body text use mixed size/weight classes across modules. No systematic spacing scale.

**Files to modify**:
- `assets/css/input.css` (define CSS custom properties and utility classes)
- `services/portal/tailwind.config.js` (extend theme with token references)
- `services/portal/templates/base.html` (apply token classes to body/main)

**Deliverables**:
1. Define all typography tokens as CSS custom properties in `input.css`.
2. Create named utility classes:
   - `.text-page-title`, `.text-section-title`, `.text-body`, `.text-meta`, `.text-caption`
   - `.space-page-gutter`, `.space-section-stack`, `.space-card-padding`, `.space-field-stack`
3. Extend Tailwind config `theme.extend.fontSize` and `theme.extend.spacing` to reference tokens.
4. Apply token classes in `base.html` main content area.
5. Document mapping in design system spec.

**Acceptance criteria**:
- Token CSS variables defined and used by utility classes.
- Tailwind config references tokens for consistency.
- At least auth pages + billing pages use token-based typography.

---

### B.3 Consolidate Status Semantics & Color Mapping
**Priority**: P1 | **Effort**: 2-3 days | **Risk**: Low

**Problem**: Some pages use raw `bg-*-100 text-*-800` pills instead of `{% badge %}` with semantic variants. Status-to-color mapping is duplicated across templates.

**Files to modify**:
- `services/portal/apps/ui/templatetags/ui_components.py` (add status mapping helper)
- `services/portal/templates/components/badge.html` (ensure all variants work)
- `services/portal/templates/services/service_detail.html`
- `services/portal/templates/billing/invoice_detail.html`
- `services/portal/templates/users/consent_history.html`

**Deliverables**:
1. Create `status_to_variant()` utility function:
   ```python
   STATUS_VARIANT_MAP: dict[str, str] = {
       "active": "success", "paid": "success", "healthy": "success",
       "pending": "warning", "draft": "info", "processing": "info",
       "overdue": "danger", "cancelled": "danger", "suspended": "danger",
   }

   @register.simple_tag
   def status_variant(status: str) -> str:
       return STATUS_VARIANT_MAP.get(status.lower(), "default")
   ```
2. Replace all inline status branching in templates with `{% badge variant=service.status|status_variant %}`.
3. Remove duplicated color-class conditionals from feature templates.

**Acceptance criteria**:
- Zero `{% if status == "active" %}bg-green-100 text-green-800{% endif %}` patterns in templates.
- All status rendering goes through `{% badge %}` + variant mapping.
- Status variant map covers all known statuses across billing, services, orders, tickets.

---

### Phase B — Definition of Done

| Evidence artifact | Command / check |
|------------------|-----------------|
| Layout primitives registered | `grep -c 'register.inclusion_tag' services/portal/apps/ui/templatetags/ui_components.py` increases by 4 |
| Token CSS vars exist | `grep -c 'var(--' assets/css/input.css` ≥ 20 |
| No raw status colors | `grep -r 'bg-green-100\|bg-red-100\|bg-yellow-100' services/portal/templates/` returns only component internals |
| Page size reduction | Migrated pages reduce line count by ≥ 20% |
| Tests pass | `make test-portal && make test-e2e` exits 0 |

### Phase B — E2E Test Maintenance

Phase B adds **layout primitives** and migrates large pages — HTML structure changes significantly.

| E2E test file | Risk area | Action |
|--------------|-----------|--------|
| `tests/e2e/test_portal_services_e2e.py` | Service detail page restructured with `page_header` / `section_card` | Rewrite page-level selectors, verify content still accessible |
| `tests/e2e/test_portal_orders_e2e.py` | Product catalog/detail restructured | Verify product card and checkout flow selectors |
| `tests/e2e/test_portal_profile_e2e.py` | Profile page restructured | Update heading/section selectors to match new primitives |
| `tests/e2e/test_portal_billing_e2e.py` | Badge variant migration changes class names | Verify status badge selectors use semantic variant classes |

**Rule**: Same as Phase A — fix E2E in the same PR. Layout primitives should preserve `data-testid` or `id` attributes for E2E stability.

### Phase B Verification Checklist
- [ ] 4 new layout primitives exist with template tags and docstrings.
- [ ] Profile and service_detail pages use `page_header` + `section_card`.
- [ ] Typography token classes defined in CSS and referenced in Tailwind config.
- [ ] `grep -r 'bg-green-100\|bg-red-100\|bg-yellow-100' services/portal/templates/` returns only component internals.
- [ ] `make build-css && make test-portal` passes.
- [ ] `make test-e2e` passes (selectors updated for restructured pages).
- [ ] Manual QA: profile, service detail, product catalog on desktop (1280px) + mobile (375px).

---

## Phase C — Harden & Align (2-3 weeks)

> **Goal**: Consolidate JS, add regression tests, align cross-service components, audit performance.

### C.1 Standardize Toast / Modal JS Behavior
**Priority**: P2 | **Effort**: 2-3 days | **Risk**: Medium

**Problem**: Global toasts in `base.html` and custom toasts in pages (e.g., `product_catalog.html`) use different animation/dismiss logic. Modal JS (`openModal`/`closeModal`) is duplicated per instance.

**Files to modify/create**:
- `services/portal/static/js/components/toast.js` (NEW — single toast module)
- `services/portal/static/js/components/modal.js` (NEW — single modal module)
- `services/portal/templates/base.html` (reference JS modules)
- `services/portal/templates/components/toast.html` (remove inline `<script>`)
- `services/portal/templates/components/modal.html` (remove inline `<script>`)
- `services/portal/templates/orders/product_catalog.html` (remove custom toast logic)

**Deliverables**:
1. Create `static/js/components/toast.js`:
   - `showToast(variant, message, options)` API
   - Auto-dismiss (configurable, default 5s)
   - Stacked positioning (max 3 visible)
   - Accessible: `role="alert"`, `aria-live="assertive"`
2. Create `static/js/components/modal.js`:
   - `openModal(id)` / `closeModal(id)` API
   - Focus trap on open, restore focus on close
   - Escape key handler (single listener, not per-modal)
   - HTMX `afterSwap` integration
3. Remove all inline `<script>` blocks from toast and modal templates.
4. Remove custom toast HTML/JS from `product_catalog.html` and other pages.

**Acceptance criteria**:
- `grep -r '<script' services/portal/templates/components/toast.html` returns 0.
- `grep -r '<script' services/portal/templates/components/modal.html` returns 0.
- Toast behavior is identical across all pages.
- Modal Escape handler fires once regardless of modal count on page.

---

### C.2 Add UI Regression Test Suite
**Priority**: P2 | **Effort**: 3-4 days | **Risk**: Low

**Problem**: Zero test coverage for UI component template tags. No contract tests for page structure.

**Files to create**:
- `services/portal/tests/ui/test_component_button.py`
- `services/portal/tests/ui/test_component_badge.py`
- `services/portal/tests/ui/test_component_alert.py`
- `services/portal/tests/ui/test_component_input.py`
- `services/portal/tests/ui/test_component_modal.py`
- `services/portal/tests/ui/test_component_toast.py`
- `services/portal/tests/ui/test_component_card.py`
- `services/portal/tests/ui/test_component_icon.py`
- `services/portal/tests/ui/test_component_page_primitives.py`
- `services/portal/tests/ui/test_design_tokens.py`
- `services/portal/tests/ui/test_component_usage.py`
- `services/portal/tests/ui/test_mobile_layouts.py`
- `services/portal/tests/ui/test_xss_sanitization.py`

**Test categories**:

| Category | Assertions |
|----------|-----------|
| **Component rendering** | Each tag renders valid HTML with correct classes/variants |
| **XSS sanitization** | `_sanitize_and_escape_attrs` blocks injection in button attrs |
| **Icon completeness** | All 35+ icons render valid SVG with correct viewBox |
| **Token presence** | CSS output contains all declared token variables |
| **Page contracts** | Key pages include required components (mobile header, breadcrumb, etc.) |
| **No duplicate headers** | No page includes both `mobile_header` and `portal_mobile_header` |
| **Form accessibility** | Auth pages have labels, error regions, `aria-describedby` |
| **Mobile safety** | Primary CTAs not hidden at narrow viewport |

**Acceptance criteria**:
- ≥ 90% line coverage for `ui_components.py`.
- All component tags have at least 1 render test and 1 variant test.
- XSS sanitization test with malicious input passes.
- `make test-portal` includes and passes all new tests.

---

### C.3 Align Portal & Platform Component Libraries
**Priority**: P2 | **Effort**: 2-3 days | **Risk**: Low

**Problem**: 18 shared components exist in both services but may have drifted. No mechanism to detect divergence.

**Files to modify/create**:
- `scripts/check_component_parity.py` (NEW — CI check)
- `services/portal/templates/components/*.html` (shared set)
- `services/platform/templates/components/*.html` (shared set)

**Deliverables**:
1. Create `check_component_parity.py` script:
   - Compares shared component files between Portal and Platform.
   - Reports diffs for files that should be identical.
   - Allows intentional divergences via `.component-parity-ignore` config.
2. Diff all 18 shared components and fix any unintentional drift.
3. Add script to `make pre-commit` or CI pipeline.
4. Document which components are shared vs. intentionally divergent.

**Acceptance criteria**:
- `python scripts/check_component_parity.py` exits 0.
- Script is integrated in CI.
- All 18 shared templates are byte-identical or documented as intentionally different.

---

### C.4 Performance Audit: CSS & Component Weight
**Priority**: P2 | **Effort**: 1-2 days | **Risk**: Low

**Problem**: No audit of unused CSS, template complexity budget, or component render cost.

**Deliverables**:
1. Run PurgeCSS analysis on compiled portal CSS — report unused selectors.
2. Document template query budgets for top 6 largest pages.
3. Identify any component templates that generate excessive DOM nodes.
4. Create `make css-audit` target that reports file size and unused selector count.

**Acceptance criteria**:
- Portal CSS ≤ 50KB gzipped after purge.
- Top 6 pages have documented query budgets.
- No single component generates > 200 DOM nodes.

---

### Phase C — Definition of Done

| Evidence artifact | Command / check |
|------------------|-----------------|
| No inline scripts in components | `grep -r '<script' services/portal/templates/components/toast.html services/portal/templates/components/modal.html` returns 0 |
| UI test count | `make test-portal` runs ≥ 40 new UI tests |
| Component parity | `python scripts/check_component_parity.py` exits 0 |
| CSS weight | Portal CSS ≤ 50KB gzipped |
| Full green CI | `make test && make test-e2e` both exit 0 |

### Phase C — E2E Test Maintenance

Phase C consolidates JS behavior and adds component parity checks — modal/toast behavior changes.

| E2E test file | Risk area | Action |
|--------------|-----------|--------|
| `tests/e2e/test_portal_modal_e2e.py` (if exists) | Modal open/close JS API changes | Verify `openModal(id)` / `closeModal(id)` API works with HTMX afterSwap |
| `tests/e2e/test_portal_orders_e2e.py` | Product catalog toast logic replaced | Verify toast appears on add-to-cart actions |
| All E2E files | Global toast behavior unified | Run full `make test-e2e` — any page that triggers toast |

**Rule**: C.2 (UI regression test suite) should cover all component rendering — these are unit-level, not E2E. But E2E must still pass after JS module extraction.

### Phase C Verification Checklist
- [ ] Zero inline `<script>` blocks in toast and modal templates.
- [ ] `make test-portal` runs ≥ 40 new UI tests and all pass.
- [ ] `python scripts/check_component_parity.py` exits 0.
- [ ] Portal CSS ≤ 50KB gzipped.
- [ ] `make build-css && make test && make test-e2e` passes.

---

## Phase D — Polish & Maintain (Ongoing)

> **Goal**: Continuous improvement, automation, and long-term design system health.

### D.1 Template Linting Pre-Commit Hook
**Priority**: P2 | **Effort**: 2 days | **Risk**: Low

**Deliverables**:
1. Create `scripts/lint_template_components.py`:
   - Detects raw `<input>` / `<button>` in feature templates (should use component tags).
   - Detects raw semantic color classes (`bg-green-100`, `text-red-800`) outside component templates.
   - Detects duplicate `<style>` blocks in templates.
   - Detects inline `<script>` blocks in component templates.
2. Add to `.pre-commit-config.yaml`.
3. Add `make lint-templates` target.

**Acceptance criteria**:
- `make lint-templates` exits 0 on current codebase.
- New PRs with raw inputs/buttons in feature templates fail pre-commit.

---

### D.2 Component Documentation / Living Styleguide
**Priority**: P2 | **Effort**: 3-4 days | **Risk**: Low

**Deliverables**:
1. Create `services/portal/templates/styleguide/` page (staff-only, dev mode only).
2. Render every component with all variants and sizes.
3. Show code snippets for each component usage.
4. Include token color swatches, typography scale, spacing scale.
5. Link from portal dev nav bar (visible only when `DEBUG=True`).

**Acceptance criteria**:
- `/styleguide/` renders all components without errors.
- Each component section shows usage code.
- Page auto-updates when components change (no manual maintenance).

---

### D.3 Accessibility Audit (WCAG AA)
**Priority**: P2 | **Effort**: 2-3 days | **Risk**: Low

**Deliverables**:
1. Run axe-core on all key portal pages (auth, billing, services, orders, profile).
2. Fix all Critical and Serious violations.
3. Document remaining Minor violations with planned fixes.
4. Add Playwright accessibility assertions to E2E tests.

**Acceptance criteria**:
- Zero Critical/Serious axe-core violations on auth and billing pages.
- All form inputs have programmatic labels.
- Color contrast ≥ 4.5:1 for normal text, ≥ 3:1 for large text.

---

### D.4 Dark Mode Completeness Pass
**Priority**: P3 | **Effort**: 2-3 days | **Risk**: Low

**Deliverables**:
1. Audit all portal pages for dark mode token usage.
2. Ensure all new components (page_header, section_card, etc.) support dark mode.
3. Fix any hardcoded light-only colors in templates.
4. Add dark mode screenshots to component styleguide.

**Acceptance criteria**:
- All portal pages render correctly in dark mode.
- No hardcoded white/gray backgrounds outside of token system.
- Styleguide shows both light and dark variants.

---

## Epic Branch Workflow

**Branch**: `feat/ui-ux-design-system`

All design system work happens on a single epic branch with internal phase gates. This prevents partial design system states in `master`.

### Workflow Rules

1. **Create epic branch** from `master` at start of Phase A.
2. **Phase gates**: Each phase (A, B, C) must pass its Definition of Done before starting the next phase.
3. **Internal PRs**: Feature branches merge into the epic branch (not `master`).
4. **Rebase regularly**: Keep epic branch rebased on `master` (weekly minimum).
5. **Atomic merge**: Epic branch merges to `master` after Phase C completes — single squash merge.
6. **Phase D** continues on `master` via normal branch workflow (no epic branch needed).

### Phase Gate Checkpoints

```
master ─────────────────────────────────────────────────────── ← merge after Phase C
  └── feat/ui-ux-design-system
        ├── Phase A gate ✅ (DoD met) → start Phase B
        ├── Phase B gate ✅ (DoD met) → start Phase C
        └── Phase C gate ✅ (DoD met) → merge to master
```

### Interim Demos

After each phase gate, create a tagged commit on the epic branch for stakeholder review:
- `ui-ux-phase-a-complete`
- `ui-ux-phase-b-complete`
- `ui-ux-phase-c-complete`

---

## Migration Scoreboard

Track progress per template as work proceeds. Update this table as templates are migrated.

| Template | Phase | Status | PR | Notes |
|----------|-------|--------|----|-------|
| `users/login.html` | A.1 | ✅ Complete | epic | Componentized via `form_field`/`form_checkbox` |
| `users/register.html` | A.1 | ✅ Complete | epic | Componentized + JS extracted |
| `users/password_reset.html` | A.1 | ✅ Complete | epic | Componentized with error summary |
| `users/change_password.html` | A.1 | ✅ Complete | epic | Componentized; later migrated to page primitives |
| `billing/invoice_detail.html` | A.2 | ✅ Complete | epic | Badge migration, format_currency/format_date, line-items partial |
| `billing/proforma_detail.html` | A.2 | ✅ Complete | epic | Badge migration, format_currency/format_date, line-items partial |
| `base.html` (styles/toast) | A.3 | ✅ Complete | epic | Inline styles removed; toast componentized |
| `components/mobile_header.html` | A.3+A.4 | ✅ Complete | epic | Canonical header retained; JS extracted |
| `components/button.html` | A.3 | ✅ Complete | epic | Inline styles moved to `assets/css/input.css` |
| `tickets/ticket_create.html` | A.5 | ✅ Complete | epic | Emoji removed from priority options (Finding 3) |
| `users/profile.html` | B.1 | ✅ Complete | epic | Migrated to `page_header` + `section_card` |
| `services/service_detail.html` | B.1 | ✅ Complete | epic | Migrated to `page_header` + `section_card` |
| `orders/product_catalog.html` | B.1 | ✅ Complete | epic | Migrated to `page_header` + `section_card` |
| `orders/checkout.html` | B.1 | ✅ Complete | epic | Migrated to `page_header` + `section_card` |
| `static/js/components/modal.js` | C.1 | ✅ Complete | epic | Vanilla JS IIFE; focus trap, Escape handler, HTMX integration |
| `static/js/components/toast.js` | C.1 | ✅ Complete | epic | `showToast()` API; XSS-safe, auto-dismiss, stack management |
| `tests/ui/test_design_system_filters.py` | C.2 | ✅ Complete | epic | 87 tests for status/icon/label filters |
| `tests/ui/test_component_*.py` | C.2 | ✅ Complete | epic | 226 new tests: badge, button, icon, page primitives, XSS |
| `scripts/check_component_parity.py` | C.3 | ✅ Complete | epic | Compares 18 shared components; `.component-parity-ignore` for intentional divergence |
| `make css-audit` | C.4 | ✅ Complete | epic | Portal CSS 17 KB gzipped (target ≤ 50 KB); bundle size gate |
| `scripts/lint_template_components.py` | D.1 | ✅ Complete | epic | 8 rules (TMPL001-008); `make lint-templates` + pre-commit hook |
| `styleguide/index.html` | D.2 | ✅ Complete | epic | 12 sections, DEBUG-only, English text, sidebar nav |
| `scripts/audit_accessibility.py` | D.3 | ✅ Complete | epic | 10 rules (A11Y001-010); `make audit-a11y` — 168 findings baseline |
| `scripts/audit_dark_mode.py` | D.4 | ✅ Complete | epic | 5 rules (DM001-005); `make audit-dark-mode` — 260 findings baseline |

---

## Recommended Execution Order

```
Week 1-2:  A.1 (auth forms) + A.3 (style cleanup) + A.4 (mobile header) + A.5 (icons) ✅
Week 2-3:  A.2 (billing detail) ✅
Week 3-5:  B.1 (page primitives) + B.2 (tokens) + B.3 (status mapping) ✅
Week 5-7:  C.1 (JS consolidation) + C.2 (test suite) ✅
Week 7-8:  C.3 (cross-service parity) + C.4 (CSS audit) ✅
Ongoing:   D.1 (lint hook) ✅ → D.2 (styleguide) ✅ → D.3 (a11y) ✅ → D.4 (dark mode) ✅
```

### Dependency Graph

```
A.3 (style cleanup) ──→ A.1 (auth forms) ──→ B.1 (page primitives)
  ├──→ A.4 (mobile header)                        ↓
  └──→ A.5 (icon pass)                       B.2 (tokens)
A.2 (billing) ────────→ B.3 (status mapping)   ↓
                                              C.1 (JS consolidation)
                                              C.2 (test suite) ──→ D.1 (lint hook)
                                              C.3 (parity check)
                                              C.4 (CSS audit) ──→ D.4 (dark mode)
```

**Critical path**: A.3 → A.1 → B.1 → B.2 → C.1 → C.2 (style cleanup must happen before form migration, primitives before token formalization, JS consolidation before test suite).

---

## Risks & Mitigations

| # | Risk | Impact | Likelihood | Mitigation |
|---|------|--------|------------|------------|
| 1 | Visual regression on billing pages | High (trust / revenue) | Medium | Before/after screenshots in every PR; manual QA on billing pages; Rollback Plan in design system spec |
| 2 | E2E test breakage cascading across phases | Medium (CI red) | High | Fix E2E selectors in same PR as template change; add `data-testid` attrs for E2E stability |
| 3 | Epic branch diverges too far from master | Medium (merge conflicts) | Medium | Weekly rebase; keep PRs < 400 LOC; phase gates force regular checkpoints |
| 4 | Cookie consent banner obstructs forms after refactor | High (GDPR + UX) | Low | Test cookie banner z-index against modal/form overlays; add E2E assertion |
| 5 | Component API backward-compat broken | High (all pages break) | Low | Locked Decision #6 in spec: existing tag APIs are frozen; only additive changes |
| 6 | Performance regression from CSS token migration | Medium (page load) | Low | CSS ≤ 50KB gzipped gate in Phase C; PurgeCSS audit before merge |
| 7 | Cross-service component drift during epic | Low (Platform unaffected) | Medium | Phase C.3 parity script catches drift; run before final merge |

---

## Success Metrics

| Metric | Current | Phase A Target | Phase B Target | Phase C Target |
|--------|---------|---------------|---------------|---------------|
| Inline `<style>` blocks in templates | ~4 | 0 | 0 | 0 |
| Inline `<script>` blocks in components | ~5 | ~3 | ~3 | 0 |
| Raw input/button in feature templates | ~10+ | 0 (auth pages) | 0 (all pages) | 0 |
| UI component test count | 1 | 5+ | 15+ | 40+ |
| `ui_components.py` test coverage | 0% | 20% | 50% | 90% |
| Duplicate component files | 1 (portal_mobile_header) | 0 | 0 | 0 |
| Pages using `page_header` primitive | 0 | 0 | 7+ | 7+ |
| Cross-service component drift | Unknown | Unknown | Tracked | 0 diffs |
| Emoji in templates/Python | 12 | 0 | 0 | 0 |
| Raw `<svg>` in feature templates | ~20+ | ~5 | 0 | 0 |
| E2E test pass rate | 100% | 100% | 100% | 100% |
