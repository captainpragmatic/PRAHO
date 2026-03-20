# ADR-0035: Unified Design System Architecture

**Status**: Accepted
**Date**: 2026-03-17
**Decision Makers**: Platform Team

## Context

PRAHO has two Django services (Platform and Portal) that independently maintained overlapping UI components. Over time, the copies drifted: Portal adopted `{% icon %}` tags, Alpine.js, external JS modules, and better accessibility. Platform's copies retained hardcoded SVGs, inline scripts, and a red primary button bug.

Manual mirroring (per design system governance doc §9.2) failed silently — 14 of 16 shared components had diverged.

## Decision

Extract shared UI components into `shared/ui/` at the project root. Portal's component implementations are promoted as the canonical versions. Both services resolve shared components via Django's template loader directory priority.

### Architecture

```
shared/
├── ui/
│   ├── templates/components/   # 25 shared component templates (canonical)
│   └── static/js/components/   # Shared JS modules (modal.js, toast.js)
├── tailwind.preset.js          # Shared Tailwind configuration

services/platform/
├── templates/components/       # Platform-only: mobile_header.html, table_enhanced.html
├── apps/ui/templatetags/       # Platform's templatetag Python (unchanged)
└── tailwind.config.js          # Extends shared preset + platform-specific tokens

services/portal/
├── templates/components/       # Portal-only: 4 customer-specific components
├── apps/ui/templatetags/       # Portal's templatetag Python (unchanged)
└── tailwind.config.js          # Extends shared preset + portal-specific tokens
```

### Template Resolution

Django `TEMPLATES[0]['DIRS']` in both services:
1. `BASE_DIR / "templates"` — service-specific (highest priority, can override)
2. `REPO_ROOT / "shared" / "ui" / "templates"` — shared fallback

When a templatetag renders `{% include "components/button.html" %}`, Django checks the service dir first. If not found, it falls through to the shared dir.

### Static File Resolution

`STATICFILES_DIRS` in both services:
1. `BASE_DIR / "static"` — service-specific
2. `REPO_ROOT / "shared" / "ui" / "static"` — shared JS modules

### Templatetag Python Files

Remain in each service's `apps/ui/templatetags/`. They are NOT shared because:
- They import service-specific constants (`ROMANIAN_VAT_RATE` exists in Portal but not Platform)
- Django discovers templatetags via `APP_DIRS` + `INSTALLED_APPS`
- No `shared.ui` in INSTALLED_APPS (avoids import collisions and sys.path issues)

### Tailwind Configuration

Shared preset at `shared/tailwind.preset.js` provides: `darkMode`, font families, status colors, animations, keyframes, and core plugins. Each service config extends the preset with service-specific tokens.

Both service configs include `./shared/ui/templates/**/*.html` in content paths to ensure shared component classes are included in compiled CSS.

## Consequences

### Positive
- Single source of truth for shared components — drift is structurally impossible
- `scripts/check_component_parity.py` enforces no accidental shadowing
- Service-specific overrides still possible via directory priority
- No Django configuration complexity (no INSTALLED_APPS changes, no sys.path hacks)
- Both test suites pass with zero changes to production code

### Negative
- Templatetag Python files remain duplicated (acceptable — they contain service-specific logic)
- Developers must know that `shared/ui/templates/components/` is the canonical location
- Adding new shared components requires placing in shared dir, not service dir

### Neutral
- `mobile_header.html` is intentionally NOT shared (staff vs customer navigation)
- `table_enhanced.html` remains Platform-only
- Phase 3 (Platform raw HTML → component tag migration) is a separate, ongoing effort

## Components

### Shared (25)
alert, badge, breadcrumb, button, card, checkbox, dangerous_action_modal, empty_state, filter_select, form_actions, form_error_summary, input, list_page_filters, list_page_header, list_page_skeleton, mobile_nav_item, modal, nav_dropdown, page_header, pagination, section_card, stat_tile, step_progress, table, toast

### Portal-Only (4)
account_status_banner, cookie_consent_banner, customer_selector, rate_limit_inline_alert

### Platform-Only (2)
mobile_header, table_enhanced

## How to Add a New Shared Component

1. Create `shared/ui/templates/components/{name}.html`
2. Add corresponding `@dataclass` config and `@register.inclusion_tag` in both services' `ui_components.py`
3. Add to `SHARED_COMPONENTS` list in `scripts/check_component_parity.py`
4. Run `python scripts/check_component_parity.py` to verify

## How to Override a Shared Component for One Service

Place a file with the same name in the service's `templates/components/` directory. Django's template loader checks the service dir first.

Document the override in `.component-parity-ignore` with a justification comment.
