# Shared Cross-Service Assets

This directory contains assets shared between the Platform and Portal services.
See [ADR-0035](../docs/ADRs/ADR-0035-unified-design-system.md) for the architecture decision.

## Structure

```
shared/
├── ui/
│   ├── templates/
│   │   └── components/     # 15 shared component templates (canonical source)
│   └── static/
│       └── js/
│           └── components/ # Shared JS modules (modal.js, toast.js)
└── tailwind.preset.js      # Shared Tailwind CSS configuration preset
```

## How It Works

Both services include `shared/ui/templates/` in their Django `TEMPLATES[0]['DIRS']` setting,
and `shared/ui/static/` in `STATICFILES_DIRS`. Django's template loader checks the
service-specific directory first (allowing overrides), then falls through to shared.

## Rules

- **Shared components** live here and ONLY here (no copies in service dirs)
- **Service-specific components** stay in their service's `templates/components/`
- The `scripts/check_component_parity.py` pre-commit hook enforces no accidental shadowing
- To override a shared component for one service, place a same-named file in the service's
  `templates/components/` dir and document it in `.component-parity-ignore`

## Components

### Shared (15)
alert, badge, breadcrumb, button, card, checkbox, dangerous_action_modal,
input, mobile_nav_item, modal, nav_dropdown, pagination, step_progress, table, toast

### Not Shared (intentionally)
- `mobile_header.html` — differs between services (staff nav vs customer nav)
- `table_enhanced.html` — Platform-only
- Portal-only: account_status_banner, cookie_consent_banner, customer_selector, etc.
