# Portal UI/UX Design System

> **Status**: Active specification
> **Owner**: PRAHO Platform Team
> **Last updated**: 2026-03-05
> **Companion**: [portal-ui-ux-backlog.md](portal-ui-ux-backlog.md) (implementation roadmap)
> **Branch**: `feat/ui-ux-design-system-epic`

---

## 1) Design System Objectives

- Consistent visual rhythm (spacing, typography, hierarchy) across all portal pages.
- Single source of truth for components, variants, and states.
- Accessible defaults for forms, alerts, async feedback, and mobile behavior.
- HTMX-friendly states (loading, empty, error, success) in every async region.
- Zero-runtime JavaScript strategy: Alpine.js for interactivity, no build-step JS bundles.
- **English-first, internationally standard** codebase with Romanian as the primary deployed locale.
  - All code, comments, component APIs, and variable names are in English.
  - English (EN) is the base/default language for all user-facing strings in templates.
  - Romanian (RO) is the primary *translation* — delivered via Django i18n (`{% trans %}` / `{% blocktrans %}`).
  - Formatting follows international standards (ISO dates in code, ISO currency codes) with locale-aware *display* rendering for the active locale.

## 2) Non-Goals

These are explicitly **out of scope** for this design system effort:

- **No frontend framework switch** — no React, Vue, Svelte, or Lit. Django templates + HTMX + Alpine.js remains the stack.
- **No new CSS framework** — Tailwind CSS remains. No migration to Bootstrap, Bulma, or CSS-in-JS.
- **No platform-first delivery** — Portal stabilizes first; Platform alignment is optional and only starts after Phase B.
- **No i18n string extraction** — This effort normalizes formatting filters and prevents mixed-language labels, but does not perform a full translation pass.
- **No visual redesign** — Tokens formalize the *existing* visual language rather than inventing a new one.
- **No breaking API changes to existing tags** — `button`, `input_field`, `checkbox_field`, `badge`, `alert`, `modal`, `data_table` must remain backward-compatible.

## 3) Locked Decisions

| # | Decision | Rationale |
|---|----------|-----------|
| 1 | Canonical docs live in `docs/architecture/ui-ux/`; root-level files are pointer stubs | Clean namespace, discoverability via docs README |
| 2 | Portal-first delivery; Platform alignment is optional after Portal A/B stabilization | De-risk scope; Portal has customer-facing urgency |
| 3 | Single delivery branch (`feat/ui-ux-design-system-epic`) with internal phase gates | Atomic merge; prevents partial design system in main |
| 4 | Existing component layer is the base architecture — no framework switch | Minimal disruption, leverage 937L of existing tag code |
| 5 | Migration prioritizes trust and conversion paths first | Auth → billing → catalog → service → profile |

---

## 4) Icon Standardization Policy

The portal uses a **single canonical icon system**: the `{% icon %}` template tag rendering inline Heroicon SVGs.

### 4.1 Allowed Icon Sources

| Source | Status | Where |
|--------|--------|-------|
| `{% icon "name" %}` template tag | ✅ **Standard** | All templates (feature + component) |
| Raw `<svg>` inside `components/*.html` | ⚠️ Restricted | **Only** complex visuals (spinners/charts/illustrations) listed in `.component-svg-allowlist` |
| Raw `<svg>` in feature templates | ❌ **Prohibited** | Must migrate to `{% icon %}` tag |
| Emoji characters in UI text | ❌ **Prohibited** | Replace with `{% icon %}` or remove entirely |
| Emoji defaults in Python dataclasses | ❌ **Prohibited** | Replace with `{% icon %}` reference or empty string |
| Image-based icons (`<img>`, `.png`, `.ico`) | ❌ **Prohibited** | Use SVG via `{% icon %}` tag |

### 4.2 Icon Tag Contract

```html
{% icon "check" class="w-5 h-5" %}     {# Named Heroicon, renders inline SVG #}
{% icon "lock" class="w-4 h-4 text-primary" %}  {# With color token class #}
```

- Icons are **inline SVG** — no external sprite sheets or icon fonts.
- The `{% icon %}` tag supports 35+ Heroicon names (see `ui_components.py` ICON_SVGS dict).
- All icon sizing via Tailwind utility classes (`w-4 h-4`, `w-5 h-5`, `w-6 h-6`).
- New icons: add to the `ICON_SVGS` dictionary in `ui_components.py`, not as raw SVG in templates.
- Icon-like SVG in component templates must also use `{% icon %}`.

### 4.2.1 Raw SVG Exception Process

Raw `<svg>` is allowed only for complex visuals that cannot be represented cleanly via `{% icon %}` (for example animated spinners).

1. Add one entry in `.component-svg-allowlist` with path + reason.
2. Keep scope minimal; prefer migrating to `{% icon %}`.
3. Ensure `scripts/lint_template_components.py` passes with no unexpected `TMPL009` findings.

### 4.3 Current Violations (to fix)

| Location | Issue | Fix |
|----------|-------|-----|
| `ui_components.py` line ~155 | `empty_icon: str = "📋"` emoji default on `EmptyStateConfig` | Change to `{% icon "clipboard" %}` or `icon_name` string param |
| `ticket_create.html` `<option>` tags | 4 emoji characters as priority labels | Replace with text-only labels or SVG-decorated `<select>` |
| `invoice_detail.html` `<option>` tags | 7 emoji characters in status options | Replace with text-only labels |
| 39 feature/component templates | Raw `<svg>` elements (148 instances) | Migrate feature template SVGs to `{% icon %}` tag; keep component-internal SVGs |

### 4.4 Icon Anti-Patterns

| Anti-pattern | Correct approach |
|-------------|------------------|
| `🔒` emoji in template text | `{% icon "lock" class="w-4 h-4 inline" %}` |
| `<svg xmlns="..." viewBox="...">` in feature template | `{% icon "name" class="w-5 h-5" %}` |
| `empty_icon: str = "📋"` in Python | `icon_name: str = "clipboard"` + render via `{% icon %}` |
| Copy-pasting SVG markup between templates | Add icon to `ICON_SVGS` dict once, reuse via tag |
| Inline SVG with hardcoded `fill`/`stroke` colors | Use `currentColor` + Tailwind text color class |

---

## 5) Token Model

### 5.1 Color Tokens

All colors defined once in `assets/css/input.css` and referenced via Tailwind config.

| Category | Token | Purpose |
|----------|-------|---------|
| **Brand** | `--color-brand-primary` | Primary action color (hsl 210) |
|  | `--color-brand-primary-hover` | Hover state for primary actions |
| **Surface** | `--color-bg-page` | Page background |
|  | `--color-bg-card` | Card/panel background |
|  | `--color-bg-muted` | Subdued regions, table stripes |
|  | `--color-border-default` | Default border (dividers, card edges) |
| **Text** | `--color-text-primary` | Main body text |
|  | `--color-text-secondary` | Labels, secondary info |
|  | `--color-text-muted` | Timestamps, metadata, placeholders |
| **Semantic** | `--color-success-{bg,text,border}` | Positive states (active, paid, healthy) |
|  | `--color-warning-{bg,text,border}` | Caution states (pending, expiring) |
|  | `--color-danger-{bg,text,border}` | Negative states (overdue, error, cancelled) |
|  | `--color-info-{bg,text,border}` | Informational states (processing, draft) |

**Dark mode**: Tokens switch via `darkMode: 'class'` in Tailwind config. Portal surface palette defined in `portal.bg-dark`, `portal.text-dark`, `portal.border-dark`.

### 5.2 Typography Tokens

| Token | Value | Usage |
|-------|-------|-------|
| `--font-family-sans` | System stack (`-apple-system`, `BlinkMacSystemFont`, ...) | All body text |
| `--font-size-page-title` | `1.875rem` (30px) | Page `<h1>` via `page_header` |
| `--font-size-section-title` | `1.25rem` (20px) | Section `<h2>` via `section_card` header |
| `--font-size-body` | `1rem` (16px) | Default body text |
| `--font-size-meta` | `0.875rem` (14px) | Timestamps, labels, table cells |
| `--font-size-caption` | `0.75rem` (12px) | Helper text, badge text |
| `--line-height-tight` | `1.25` | Headings |
| `--line-height-normal` | `1.5` | Body text |
| `--line-height-relaxed` | `1.75` | Long-form content |
| `--font-weight-medium` | `500` | Labels, nav items |
| `--font-weight-semibold` | `600` | Section headings, badges |
| `--font-weight-bold` | `700` | Page titles, emphasis |

### 5.3 Spacing Tokens

4px base scale (`--space-1` = 4px, `--space-2` = 8px, ..., `--space-10` = 40px).

| Alias | Value | Usage |
|-------|-------|-------|
| `--space-page-gutter` | `--space-6` (24px) | Page content padding from edges |
| `--space-section-stack` | `--space-8` (32px) | Vertical gap between page sections |
| `--space-card-padding` | `--space-5` (20px) | Internal card padding |
| `--space-field-stack` | `--space-4` (16px) | Gap between form fields |

### 5.4 Radius / Shadow / Motion Tokens

| Token | Value | Usage |
|-------|-------|-------|
| `--radius-sm` | `0.25rem` | Badges, small pills |
| `--radius-md` | `0.375rem` | Inputs, buttons |
| `--radius-lg` | `0.5rem` | Cards, modals |
| `--radius-xl` | `0.75rem` | Hero sections, large panels |
| `--shadow-sm` | `0 1px 2px rgba(0,0,0,0.05)` | Subtle elevation (buttons) |
| `--shadow-md` | `0 4px 6px rgba(0,0,0,0.1)` | Cards, dropdowns |
| `--shadow-lg` | `0 10px 15px rgba(0,0,0,0.1)` | Modals, toast overlays |
| `--motion-fast` | `150ms ease` | Hover/focus micro-interactions |
| `--motion-normal` | `300ms ease-out` | Panel open/close, accordion |
| `--motion-slow` | `500ms ease-out` | Page-level transitions, skeleton fade |

### 5.5 Token Anti-Patterns

| Anti-pattern | Correct approach |
|-------------|-----------------|
| `bg-blue-500` in feature template | Use `{% button variant="primary" %}` or token variable |
| `bg-green-100 text-green-800` for status pill | Use `{% badge variant="success" %}` |
| `text-sm font-medium` for every label | Use `.text-meta` utility class |
| `p-6` for card padding on every card | Use `--space-card-padding` or `section_card` component |
| `style="color: #ef4444"` inline | Use `{% alert variant="danger" %}` or token variable |
| `<style>` block inside component template | Move to `assets/css/input.css` |

---

## 6) Component Inventory

### 6.1 Current State (as-built)

**Registered template tags** (16 in `ui_components.py`):

| Tag | Template | Category | Status |
|-----|----------|----------|--------|
| `{% button %}` | `components/button.html` | Action | ✅ Stable |
| `{% input_field %}` | `components/input.html` | Form | ✅ Stable |
| `{% checkbox_field %}` | `components/checkbox.html` | Form | ✅ Stable |
| `{% alert %}` | `components/alert.html` | Feedback | ✅ Stable |
| `{% badge %}` | `components/badge.html` | Status | ✅ Stable |
| `{% toast %}` | `components/toast.html` | Feedback | ⚠️ Bypassed by base.html |
| `{% modal %}` | `components/modal.html` | Overlay | ✅ Stable |
| `{% card %}` | `components/card.html` | Layout | ✅ Stable |
| `{% breadcrumb %}` | `components/breadcrumb.html` | Navigation | ✅ Stable |
| `{% dropdown %}` | `components/nav_dropdown.html` | Navigation | ✅ Stable |
| `{% data_table %}` | `components/table.html` | Data | ✅ Stable |
| `{% icon %}` | *(inline SVG)* | Utility | ✅ Stable (35+ icons) |
| `{% active_link %}` | *(string)* | Utility | ✅ Stable |
| `{% format_bytes %}` | *(string)* | Formatting | ✅ Stable |
| `{% romanian_percentage %}` | *(string)* | Formatting | ✅ Stable |

**Component templates** (25 in `services/portal/templates/components/`):

| Template | Lines | Inline `<style>` | Inline `<script>` | Notes |
|----------|-------|:-:|:-:|-------|
| `mobile_header.html` | 355 | ✅ ~80L | ✅ ~65L | Primary mobile nav, used in base.html |
| `portal_mobile_header.html` | 249 | ✅ ~20L | ✅ ~35L | **DEAD CODE** - never included |
| `cookie_consent_banner.html` | 321 | ✅ 1L | ✅ ~100L | Alpine.js component, GDPR consent |
| `button.html` | 77 | ✅ ~20L | — | HTMX loading indicator styles |
| `pagination.html` | 191 | — | — | Clean, HTMX-ready |
| `modal.html` | 159 | — | ✅ ~35L | Open/close/escape handlers |
| `step_navigation.html` | 122 | — | — | Horizontal/vertical/compact |
| `input.html` | 121 | — | ✅ ~7L | Password toggle only |
| `alert.html` | 87 | — | — | Alpine.js dismissible |
| `toast.html` | 83 | — | ✅ ~20L | Auto-dismiss (bypassed) |
| `button.html` | 77 | ✅ ~20L | — | Loading indicator styles |
| `checkbox.html` | 63 | — | — | Clean |
| `badge.html` | 56 | — | — | Clean |
| `breadcrumb.html` | 28 | — | — | Minimal |
| Others | varies | — | — | list_page_*, card, table, etc. |

### 6.2 Target Components (design system complete)

#### Layout Primitives

| Component | Status | Description |
|-----------|--------|-------------|
| `page_header` | 🆕 New | Title, subtitle, breadcrumb slot, action buttons, optional stat tiles |
| `section_card` | 🆕 New | Header/body/footer slots, collapsible option, border variants |
| `stat_tile` | 🆕 New | Label/value/meta/trend indicator/status badge |
| `empty_state` | 🆕 New | Icon + title + body + CTA button (empty lists, search-no-results) |

#### Form Components

| Component | Status | Description |
|-----------|--------|-------------|
| `input_field` | ✅ Exists | Text/email/password/textarea/select with validation |
| `checkbox_field` | ✅ Exists | Checkbox with variants and data attributes |
| `form_error_summary` | 🆕 New | Top-of-form error list with `aria-live="assertive"` |
| `form_actions` | 🆕 New | Standardized submit/cancel button row with alignment |

#### Status / Feedback

| Component | Status | Description |
|-----------|--------|-------------|
| `badge` | ✅ Exists | Status pills with icon variants |
| `alert` | ✅ Exists | Info/success/warning/danger with dismiss |
| `toast` | ⚠️ Needs fix | Must replace base.html inline toast with component |
| `loading_skeleton` | 🆕 New | Animated placeholder for async-loading regions |
| `inline_async_error` | 🆕 New | HTMX error fallback with retry button |

#### Navigation

| Component | Status | Description |
|-----------|--------|-------------|
| `mobile_header` | ⚠️ Needs cleanup | Must become single canonical version |
| `pagination` | ✅ Exists | HTMX-ready, clean |
| `breadcrumb` | ✅ Exists | Minimal |
| `step_navigation` | ✅ Exists | Multi-variant |

### 6.3 Component API Matrix

Full input/variant/size/state contract for each component:

| Component | Config Dataclass | Variants | Sizes | States | A11y |
|-----------|-----------------|----------|-------|--------|------|
| `button` | `ButtonConfig` | primary, secondary, success, warning, danger, info | xs, sm, md, lg, xl | default, disabled, loading | `aria-disabled`, `aria-busy` |
| `input_field` | `InputConfig` | text, email, password, textarea, select | *(single)* | default, error, disabled, readonly | `aria-describedby`, `aria-required`, `aria-invalid` |
| `checkbox_field` | `CheckboxConfig` | primary, success, warning, danger | *(single)* | default, checked, error, disabled | `aria-checked`, `aria-describedby` |
| `alert` | `AlertConfig` | info, success, warning, danger | *(single)* | visible, dismissed | `role="alert"`, `aria-live="assertive"` |
| `badge` | `BadgeConfig` | default, primary, success, warning, danger, info | sm, md, lg | default, dismissible | *(decorative — no role needed)* |
| `toast` | `ToastConfig` | info, success, warning, danger | *(single)* | visible, auto-dismissing, dismissed | `role="alert"`, `aria-live="assertive"` |
| `modal` | `ModalConfig` | *(none)* | sm, md, lg, xl | open, closed | `role="dialog"`, `aria-modal`, focus trap |
| `card` | `CardConfig` | *(none)* | *(single)* | default | *(landmark if needed)* |
| `breadcrumb` | *(simple)* | *(none)* | *(single)* | default | `aria-label="Breadcrumb"`, `aria-current` |
| `data_table` | `DataTableConfig` | *(none)* | *(single)* | default, empty, loading | `role="table"`, sortable headers |
| **New components** | | | | | |
| `page_header` | `PageHeaderConfig` | *(none)* | *(single)* | default | `<h1>` semantic heading |
| `section_card` | `SectionCardConfig` | default, bordered, muted | *(single)* | default, collapsed | `aria-expanded` if collapsible |
| `stat_tile` | `StatTileConfig` | success, warning, danger, info, default | sm, md | default | *(decorative)* |
| `empty_state` | `EmptyStateConfig` | *(none)* | *(single)* | default | `role="status"` |
| `form_error_summary` | `FormErrorSummaryConfig` | *(none)* | *(single)* | visible (has errors), hidden | `aria-live="assertive"`, `role="alert"` |
| `form_actions` | `FormActionsConfig` | *(none)* | *(single)* | default, submitting | *(inherits from button)* |
| `inline_async_error` | `AsyncErrorConfig` | *(none)* | *(single)* | error, retrying | `aria-live="polite"`, retry button |
| `loading_skeleton` | `SkeletonConfig` | *(none)* | sm, md, lg | animating | `aria-busy="true"`, `aria-label` |

---

## 7) Component API Rules

1. Every component:
   - Has explicit `variant` and `size` options with documented defaults.
   - Supports `class` / `css_class` extension without requiring it for normal usage.
   - Exposes accessibility attributes (`aria-*`, `role`) where semantically appropriate.
   - Is rendered via `{% component_name %}` template tag — never via raw HTML copy-paste.

2. **No inline `<style>` blocks** in component templates.
   - All styles must live in `assets/css/input.css` or Tailwind utility classes.
   - Exception: `[x-cloak]` display:none (single line, Alpine.js requirement).

3. **No inline `<script>` blocks** in component templates.
   - All JS must live in `services/portal/static/js/` as discrete modules.
   - Exception: Alpine.js `x-data` object literals directly on elements.

4. **No raw semantic color classes** (e.g., `bg-red-100 text-red-800`) in feature templates.
   - Use `{% badge variant="danger" %}` or `{% alert variant="warning" %}` instead.
   - Status-to-variant mapping happens in Python (services/views), not in templates.

5. **HTMX attributes** must stay on a single line — no line breaks between `hx-*` attributes.

---

## 8) UX Standards (Enforced)

### 8.1 Forms

- **Always show**: field labels, per-field inline errors, top-level `form_error_summary` on submit failure.
- Error copy remains visible until user action changes state (no auto-dismiss on errors).
- Required controls must never be hidden or conditionally omitted without a visible fallback.
- All forms use `{% csrf_token %}` and `method="post"` (never GET for mutations).
- Form submit buttons must show loading state during HTMX requests.

### 8.2 HTMX State Contract

Every HTMX-driven region must define and render **all four states**:

| State | Implementation | Mandatory element |
|-------|---------------|-------------------|
| **Loading** | `loading_skeleton` component or `htmx-indicator` spinner | `aria-busy="true"` on container |
| **Success** | Normal content render | Remove `aria-busy`; set `aria-live="polite"` |
| **Empty** | `empty_state` component with contextual CTA | Icon + message + action button |
| **Error** | `inline_async_error` component with retry button | `aria-live="polite"` + retry `{% button %}` |

**Timeout and fallback behavior**:
- If loading exceeds **10 seconds**, auto-transition to error state with retry button.
- Use `htmx:timeout` event (set via `hx-request="timeout:10000"`) to trigger fallback.
- Error state must include the original `hx-get`/`hx-post` URL for retry.
- Never leave a skeleton/spinner as the permanent state — always have a timeout escape hatch.

**Template pattern**:
```html
<div id="async-region" aria-live="polite"
     hx-get="/api/data/" hx-trigger="load" hx-target="#async-region"
     hx-swap="innerHTML" hx-indicator="#async-region-loader"
     hx-request="timeout:10000">
  <!-- Loading state (shown by htmx-indicator) -->
  <div id="async-region-loader" class="htmx-indicator">
    {% loading_skeleton size="md" %}
  </div>
  <!-- Content replaced by HTMX on success/empty/error -->
</div>
```

### 8.3 Mobile

- Primary CTA must remain visible and reachable (never hidden behind menus on mobile).
- Overlays (cookie consent, modals) cannot obscure required form controls.
- Long text should wrap or `line-clamp` with preserved readability.
- Touch target policy:
  - WCAG 2.2 AA minimum: 24×24 CSS px.
  - Product quality target: 44×44 CSS px where layout allows.
- Mobile header is a **single canonical component** — no duplicate implementations.

### 8.3.1 Motion and Reduced Motion

- Animations and transitions must respect `prefers-reduced-motion`.
- With reduced motion enabled:
  - Disable non-essential animation and parallax effects.
  - Keep only essential state feedback with reduced duration.
- Motion tokens (`--motion-fast`, `--motion-normal`, `--motion-slow`) are defaults and must not override accessibility preferences.

### 8.4 Localization Contract

**Language strategy**: English is the **base language** for all code, component APIs, variable names, comments, and default UI strings. Romanian is the primary **deployed translation** delivered via Django i18n.

- One locale context per rendered page (no mixed EN/RO labels in same block).
- All user-facing strings wrapped in `{% trans %}` / `{% blocktrans %}` with **English as the source string**.
- Currency formatting: use `{% format_currency %}` filter (amount in cents → locale-aware display).
- Date formatting: use `{% format_date %}` filter (locale-aware — `DD.MM.YYYY` for RO, `YYYY-MM-DD` for EN).
- Number formatting: use `{% romanian_percentage %}` for percentages (locale-aware separators).
- ISO standards in code (ISO 4217 currency codes, ISO 8601 dates), locale-aware rendering for display.

**Source-of-truth formatting filters** (use these, never inline formatting):

| Data type | Filter | EN output | RO output |
|-----------|--------|-----------|-----------|
| Money (cents) | `{% format_currency amount_cents %}` | `1,234.56 RON` | `1.234,56 RON` |
| Date | `{% format_date date_obj %}` | `2026-03-15` | `15.03.2026` |
| Percentage | `{% romanian_percentage value %}` | `21.00%` | `21,00%` |
| File size | `{% format_bytes bytes %}` | `2.4 GB` | `2,4 GB` |

**Prohibited patterns**:

| Anti-pattern | Why it breaks | Correct |
|-------------|---------------|---------|
| `{{ amount / 100 }}` in template | Locale-unaware, no currency symbol | `{% format_currency amount %}` |
| `{{ date\|date:"Y-m-d" }}` hardcoded | Ignores active locale | `{% format_date date %}` |
| `Price: {{ price }} RON` (bare label) | Not translatable, mixed concerns | `{% trans "Price" %}: {% format_currency price %}` |
| Hardcoded `19%` or `21%` in template | VAT rate changes (was 19%, now 21%) | `{% romanian_percentage vat_rate %}` |
| Romanian-only source strings | Breaks EN base language rule | Write English source, translate to RO in `.po` file |

### 8.5 Accessibility

- All form inputs have associated `<label>` elements (not just placeholder text).
- Error messages linked to fields via `aria-describedby`.
- Focus management: modal open traps focus, modal close restores focus.
- Keyboard navigation: all interactive elements reachable via Tab, Escape closes overlays.
- Color contrast: minimum 4.5:1 for normal text, 3:1 for large text (WCAG AA).

#### 8.5.1 Focus Appearance Gates

- Focus indicators must be visible in both light and dark themes.
- Minimum focus indicator contrast: 3:1 against adjacent colors.
- Focus indicator area must meet WCAG 2.2 focus appearance minimum (avoid subtle low-contrast 1px-only rings).
- Focus must not be fully obscured by sticky headers, overlays, or clipped containers.

#### 8.5.2 Modal Keyboard Contract

All modal implementations must satisfy:

1. `role="dialog"` and `aria-modal="true"`.
2. Initial focus moves inside the modal on open.
3. Tab/Shift+Tab cycles inside the modal (focus trap).
4. Escape closes the modal unless explicitly disabled for critical confirmation flows.
5. Focus returns to the triggering control on close.
6. Background content is inert/non-interactive while modal is open.

#### 8.5.3 Accessible Authentication Requirement

- Authentication flows must provide at least one non-cognitive challenge path.
- Recovery and MFA flows must not require puzzle-like or memory-only steps as the sole completion path.
- Any human verification step must provide an accessible alternative.

---

## 9) Cross-Service Component Parity

### 9.1 Current State

Portal is a **strict superset** of Platform components:

| Scope | Platform | Portal |
|-------|:--------:|:------:|
| Template tags | 16 | 16 (identical API) |
| Component templates | 18 | 25 (+7 portal-specific) |

**Shared components** (17): alert, badge, breadcrumb, button, card, checkbox, dangerous_action_modal, input, mobile_header, mobile_nav_item, modal, nav_dropdown, pagination, progress_indicator, step_navigation, table, toast.

**Portal-only** (7): account_status_banner, cookie_consent_banner, customer_selector, list_page_filters, list_page_header, list_page_skeleton, portal_mobile_header (dead code).

### 9.2 Alignment Strategy

- **Shared components** must stay functionally identical across services.
- Changes to shared component templates should be mirrored in both services.
- Portal-only components are intentionally separate (customer-facing concerns).
- Consider extracting shared components to a symlinked or copied common path in CI.

---

## 10) Source of Truth

| Artifact | Location | Role |
|----------|----------|------|
| Design system spec | `docs/architecture/ui-ux/portal-design-system.md` | Policy & token definitions |
| Implementation backlog | `docs/architecture/ui-ux/portal-ui-ux-backlog.md` | Prioritized task list |
| CSS tokens | `assets/css/input.css` | Compiled token source |
| Tailwind config | `services/portal/tailwind.config.js` | Tailwind theme extensions |
| Template tag API | `services/portal/apps/ui/templatetags/ui_components.py` | Python component API |
| Component templates | `services/portal/templates/components/*.html` | HTML implementations |
| Component tests | `services/portal/tests/ui/` | Regression coverage |

### 10.1 Token Portability

- Keep token names stable and semantic-first (`--color-*`, `--space-*`, `--radius-*`, `--motion-*`).
- Keep token structure compatible with future Design Tokens Community Group (DTCG)-style exports.
- Avoid tool-specific naming conventions that block cross-tool token exchange.

---

## 11) Governance

### PR Review Checklist for UI Changes

- [ ] Uses existing component(s) or creates a new one with documented API.
- [ ] No raw semantic color classes in feature templates (use variants).
- [ ] No inline `<style>` blocks added to templates.
- [ ] No inline `<script>` blocks added to component templates.
- [ ] No duplicate status badge/pill patterns.
- [ ] No raw `<svg>` in feature templates — use `{% icon %}` tag.
- [ ] No emoji characters in UI output.
- [ ] Mobile screenshot at 375px viewport width attached.
- [ ] Before/after screenshots for any visual change.
- [ ] Accessibility: labels present, errors linked, focus managed.
- [ ] HTMX regions have all four states (loading/success/empty/error).
- [ ] Shared component changes mirrored to both Portal and Platform.
- [ ] Tests added/updated for new component tags.
- [ ] All user-facing strings use English source with `{% trans %}` wrapper.
- [ ] No mixed-language labels in same interaction block.
- [ ] Focus indicators meet visibility and contrast gates in light and dark themes.
- [ ] Modals satisfy keyboard contract (trap, escape, focus return, inert background).
- [ ] Reduced-motion preference is respected.
- [ ] Touch targets meet 24×24 AA minimum (44×44 preferred where feasible).
- [ ] Performance budgets are checked for impacted pages/components.

### 11.1 Performance Acceptance Criteria

For UI changes that materially impact rendering (75th percentile):

- LCP ≤ 2.5s
- INP ≤ 200ms
- CLS ≤ 0.1

For significant UI payload changes:

1. Capture before/after Lighthouse (or equivalent) metrics.
2. Flag any metric regression beyond threshold in PR notes.
3. Open remediation task before merge if thresholds are exceeded.

### Reviewer Roles

| Role | Responsibility | When required |
|------|---------------|---------------|
| **Component owner** | Ensures API consistency, backward compat, dataclass correctness | Any change to `ui_components.py` or `components/*.html` |
| **Page author** | Verifies page-level layout, spacing, and data correctness | Any change to feature templates |
| **QA reviewer** | Checks mobile screenshots, HTMX states, accessibility | All UI PRs |

### Escalation Path

1. **Disagreement on component API** → open ADR discussion, defer to existing pattern until resolved.
2. **Visual regression reported** → rollback to last known-good CSS build (see Rollback Plan), hotfix in separate branch.
3. **Component used differently across services** → add to `.component-parity-ignore` with justification comment.

### Component Addition Process

1. Propose in backlog with use case and API sketch.
2. Add `@dataclass` config in `ui_components.py`.
3. Add `@register.inclusion_tag` with full docstring.
4. Create `components/{name}.html` template.
5. Add unit tests in `services/portal/tests/ui/test_component_{name}.py`.
6. Update this spec (component inventory + API matrix tables).
7. If shared: mirror to Platform service.

---

## 12) Rollback Plan

If a CSS or component change causes visual regression in production:

### CSS Regression
1. Revert the `assets/css/input.css` change (single file revert).
2. Run `make build-css` to regenerate compiled CSS.
3. Deploy the reverted CSS without touching templates.
4. Root cause in a separate branch with before/after screenshots.

### Component Template Regression
1. Revert the specific `components/*.html` file(s).
2. If the component tag API changed, revert `ui_components.py` in tandem.
3. Run `make test-portal` to verify no test breakage from revert.
4. Deploy. Fix forward in a new branch.

### Token/Tailwind Config Regression
1. Revert `assets/css/input.css` + `services/portal/tailwind.config.js`.
2. Rebuild CSS: `make build-css`.
3. Spot-check auth pages + billing pages (highest-traffic).
4. Deploy reverted build.

---

## 13) Known Issues (Current State)

| # | Severity | Issue | Backlog Ref |
|---|----------|-------|-------------|
| 1 | 🔴 High | Toast system bypassed: `base.html` has inline toast (~110 lines) ignoring `{% toast %}` component | P0.3 |
| 2 | 🟡 Medium | Partial test coverage for UI template tags; missing full interaction contract coverage for some components | P2.10 |
| 3 | 🟡 Medium | Duplicate `.brand-gradient` in `base.html` (lines 41-47) | P0.3 |
| 4 | 🟡 Medium | Dead code: `portal_mobile_header.html` (249 lines, never included) | P0.4 |
| 5 | 🟡 Medium | Inline `<style>` in 4 components: mobile_header, portal_mobile_header, button, cookie_consent | P0.3 |
| 6 | 🟡 Medium | Inline `<script>` in 5 components: mobile_header, portal_mobile_header, toast, modal, cookie_consent | P2.9 |
| 7 | 🟡 Medium | Scrollbar styles duplicated between `base.html` and `mobile_header.html` | P0.3 |
| 8 | 🟢 Low | `modal.html` JS functions duplicated if multiple modals on same page | P2.9 |

---

## 14) Migration Plan Overview

See [portal-ui-ux-backlog.md](portal-ui-ux-backlog.md) for the full task breakdown.

### Phase A — Foundation & Trust (2 weeks)
> Fix what's broken, remove duplication, establish component-first patterns on highest-traffic pages.

| Task | Focus |
|------|-------|
| A.1 | Unify form patterns on auth pages (login/register/password-reset/change-password) |
| A.2 | Normalize billing detail rendering and status components |
| A.3 | Remove duplicated global style sources and inline style blocks |
| A.4 | Canonicalize mobile header and cookie banner behavior |

### Phase B — Systematize (2-3 weeks)
> Create layout primitives, establish token conventions, migrate largest pages.

| Task | Focus |
|------|-------|
| B.1 | Create page-shell primitives (page_header, section_card, stat_tile, empty_state) |
| B.2 | Establish typography and spacing tokens in CSS + Tailwind config |
| B.3 | Consolidate status semantics and color mapping |

### Phase C — Harden & Align (2-3 weeks)
> Cross-service alignment, JS consolidation, regression testing.

| Task | Focus |
|------|-------|
| C.1 | Standardize toast/modal JS into single static module |
| C.2 | Add UI regression test suite |
| C.3 | Align Portal and Platform component libraries |
| C.4 | Performance audit: eliminate unused CSS, lazy-load heavy components |

### Phase D — Polish & Maintain (Ongoing)
> Continuous improvement, linting automation, storybook-like documentation.

| Task | Focus |
|------|-------|
| D.1 | Template linting pre-commit hook for component usage |
| D.2 | Component usage documentation / living styleguide page |
| D.3 | Accessibility audit (WCAG AA compliance) |
| D.4 | Dark mode completeness pass |
