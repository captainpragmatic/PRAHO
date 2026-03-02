# ADR-0026: Portal Frontend Architecture — HTMX, Component System & Design Consistency

## Status

Accepted

## Date

2026-03-02

## Context

The Portal's customer-facing list pages (Tickets, Invoices, Services) evolved independently, creating inconsistent UX:

- **Tickets** used HTMX live search with 600ms debounce, a skeleton loader, and the shared `pagination.html` component
- **Services** used simple `<a>` links for tab-based filtering (full page reloads), no search, and custom inline "Page X" pagination
- **Invoices** had a search input that was never wired to the backend, form-submit filtering with two dropdowns, and custom inline "Page X of Y" pagination

The component migration (buttons, inputs, alerts to `{% button %}`, `{% input %}`, `{% alert %}`) was at 70% completion. No ADR documented the frontend patterns, leading to each new page reinventing layout, filtering, and pagination.

## Decision

### 1. HTMX-First Interactivity

All list page filtering, search, and tab switching use HTMX (`hx-get` to search API endpoints) instead of full page reloads. Benefits:

- Instant visual feedback with skeleton loaders during requests
- No JavaScript framework required — just HTMX attributes on HTML elements
- Server returns HTML partials, leveraging Django's template engine directly
- URLs remain bookmarkable (query params preserved)

**Pattern:** Search inputs use `hx-trigger="keyup changed delay:600ms"`. Dropdowns use `hx-trigger="change"`. Tabs use `hx-get` with the tab value in the URL. All controls use `hx-include` to preserve sibling filter values.

### 2. Tab-Based Primary Filtering

The primary filter dimension on each list page uses visual tabs (`<button>` elements with `border-b-2` active indicator). Secondary/additional filters use dropdowns inside the same filter bar.

| Page | Tabs (Primary) | Dropdowns (Secondary) |
|------|---------------|----------------------|
| Tickets | Status: All / Open / In Progress / Waiting / Closed | — |
| Invoices | Doc Type: All / Invoices / Proformas | Status: All / Draft / Paid / Overdue / … |
| Services | Status: All / Active / Suspended / Pending / Cancelled | — |

Tabs are color-coded per status (green for active, red for suspended/danger, yellow for pending, blue for all/default).

### 3. Shared Template Includes Over Inheritance

Three shared component templates provide consistent layout for all list pages:

- **`components/list_page_header.html`** — Icon, title, subtitle, stats grid, action button area
- **`components/list_page_filters.html`** — HTMX-wired tabs + search input + optional extra dropdowns
- **`components/list_page_skeleton.html`** — Parameterized loading skeleton (column count, row count, avatar)

These use `{% include "..." with var=value %}` rather than template inheritance blocks. Rationale:
- More composable — each include is independent, not coupled to a base template hierarchy
- Dependencies are explicit (variables passed via `with`)
- Each page remains self-contained and easy to customize

### 4. Content Partials as HTMX Swap Targets

Each list page has a `partials/<name>_table.html` that renders the data table + pagination. This partial is returned by:
- The main view (initial page load, included via `{% include %}`)
- The search API endpoint (HTMX swap via `hx-target`)

This eliminates duplication between the full-page render and the HTMX response.

### 5. Shared Pagination Component

All pages use `components/pagination.html` (Shadcn-inspired design with smart page range, ellipsis, HTMX support, ARIA labels). No custom inline pagination.

A shared `PaginatorData` class in `apps/common/pagination.py` builds synthetic paginator objects compatible with the pagination component, replacing ~20 lines of duplicated pagination math in each view.

### 6. UI Component Library

All interactive elements use the `ui_components` template tags:
- `{% button %}` — Consistent button styling with HTMX support
- `{% badge %}` — Status badges with variant colors
- `{% alert %}` — Flash messages and notifications
- `{% input %}` — Form inputs with validation support

No raw HTML `<button>` or `<input>` elements with inline Tailwind classes in page-level templates.

### 7. Design Token Consistency

| Token | Value |
|-------|-------|
| Page background | `bg-slate-800` |
| Card border | `border border-slate-700` |
| Card rounded | `rounded-lg` |
| Section spacing | `space-y-6` |
| Desktop padding | `p-6` |
| Mobile padding | `p-4` |
| Table row hover | `hover:bg-slate-700/50` |
| Table dividers | `divide-y divide-slate-700` |
| Table header bg | `bg-slate-800` |
| Header text | `text-xs font-medium text-slate-300 uppercase tracking-wider` |
| Primary text | `text-white` |
| Secondary text | `text-slate-400` |
| Search input | `bg-slate-700 border-slate-600 text-white placeholder-slate-400` |

## Consequences

### Positive

- **Consistency**: All three list pages now share identical structure, spacing, and interaction patterns
- **Maintainability**: UI changes to shared components propagate to all pages automatically
- **Developer experience**: New list pages follow a documented recipe (include 3 components, create a table partial, add a search endpoint)
- **Performance**: HTMX live filtering avoids full page reloads; skeleton loaders provide perceived performance
- **Testability**: HTMX endpoints return HTML fragments, testable via E2E (Playwright) and unit tests

### Negative

- **`{% include %}` overhead**: Each include is a separate template lookup. Negligible for 3 includes but worth noting
- **Coupling to variable names**: Shared includes expect specific variable names (`filter_tabs`, `filter_search_url`, etc.). Renaming requires updating all consumers
- **Client-side search limitation**: Services and invoices filter client-side after fetching from the API (the Platform API may not support text search). This works for small datasets but won't scale to thousands of documents

### Risks

- **HTMX version dependency**: Relies on HTMX `hx-include`, `hx-indicator`, `hx-trigger` behavior. Major HTMX version bumps may require adjustments
- **Hidden input for tab state**: The `list-filter-active-tab` hidden input is updated via `onclick` inline JS. If JavaScript is disabled, tabs fall back to page reloads (graceful degradation)

## References

- `components/pagination.html` — Shadcn-inspired pagination component
- `docs/development/CLICKABLE_DATA_TABLE_GUIDE.md` — Enhanced table component guide
- `docs/development/COMPONENT_MIGRATION_SUMMARY.md` — Component migration tracking
- HTMX documentation: https://htmx.org/docs/
