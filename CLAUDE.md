# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Auto Memory

Save confirmed patterns, pitfalls, and user preferences to project memory. Update when things change.

## What is PRAHO

PRAHO (PRAHO Really Automates Hosting Operations) is a hosting provider management platform built for Romanian business compliance. It uses Django 5.2 with a **two-service architecture** (Platform + Portal), HTMX for frontend interactivity, and Tailwind CSS for styling. Current version: **0.27.0** (alpha).

**PragmaticHost** is the hosting company; **PRAHO** is the platform software.

## Architecture

### Services Split

```
services/
├── platform/    # Staff/admin service (:8700) - FULL database access
│   ├── apps/    # 18 Django apps with models, services, views
│   ├── config/  # Django settings (base, dev, prod, staging, test)
│   ├── templates/
│   └── tests/   # Mirrors apps/ structure
│
└── portal/      # Customer-facing service (:8701) - SQLite for sessions only, no business DB
    ├── apps/    # 10 Django apps (API proxies only, NO models.py)
    ├── config/  # Django settings (SQLite sessions, no business database)
    ├── templates/
    └── tests/   # Enforces no business DB access via pytest plugin (@pytest.mark.no_db)

shared/              # Cross-service shared assets (ADR-0035)
└── ui/
    ├── templates/components/  # 25 shared component templates (canonical)
    └── static/js/components/  # Shared JS modules (modal.js, toast.js)

assets/
└── css/input.css    # Shared Tailwind CSS source (design tokens)
```

- **Platform** has PostgreSQL + database cache (no Redis required)
- **Portal** uses local SQLite for session storage only - communicates with Platform via HMAC-signed HTTP requests
- **Shared UI** components live in `shared/ui/` — both services resolve via Django template loader (ADR-0035)
- Portal apps must NEVER import from Platform apps (enforced by pre-commit hook)

### Inter-Service Communication

Portal authenticates to Platform using HMAC (SHA-256 signed `X-User-Context` headers). No JWT.

### App-Level Patterns

Each Platform app follows the strategic seams pattern for future microservices extraction:
- `models.py` - Django ORM models
- `services.py` - Business logic (the primary entry point for operations)
- `repos.py` - Data access layer
- `gateways.py` - External integrations (Virtualmin, Stripe, registrars)
- `views.py` - HTTP handling (thin, delegates to services)
- `urls.py` - URL routing

### Core Business Domains

| App | Purpose |
|-----|---------|
| `users` | Email-based auth (no usernames), 2FA (TOTP), staff roles, customer memberships |
| `customers` | Business organizations with normalized profiles (Tax, Billing, Address) |
| `billing` | Romanian VAT invoicing, Proforma -> Invoice flow, e-Factura, subscriptions |
| `orders` | Order lifecycle (draft -> pending -> processing -> completed -> refunded) |
| `products` | Product catalog with multi-currency pricing (RON/EUR/USD) |
| `provisioning` | Hosting services, Virtualmin integration, two-phase provisioning with rollback |
| `domains` | Multi-registrar domain management (.ro via ROTLD, international) |
| `tickets` | Support system with SLA tracking |
| `integrations` | Webhook deduplication framework (Stripe, Virtualmin) |
| `audit` | Immutable audit trails, GDPR compliance |
| `notifications` | Bilingual email templates (RO/EN) |
| `common` | Romanian validators (CUI, VAT), shared types, security utilities |

### Key Model Facts

- **User model**: email-based (no username field), has `staff_role` field
- **Product**: uses `slug` and `product_type`, pricing in separate `ProductPrice` model (no `sku`/`price_cents`/`category`)
- **Invoice/Order**: `tax_cents` (not `vat_cents`), `line_total_cents` on OrderItem (not `total_cents`)
- **Proforma**: model is `ProformaInvoice` (not `Proforma`)
- **Monetary values**: stored as integers in cents to avoid floating-point issues

### FSM State Machines (ADR-0034)

10 models use `django-fsm-2` with `FSMField(protected=True)` for status management:

| Model | Field | Key Transitions |
|-------|-------|-----------------|
| `Order` | `status` | draft→pending→confirmed→processing→completed→refunded |
| `OrderItem` | `provisioning_status` | pending→in_progress→completed/failed |
| `Invoice` | `status` | draft→issued→paid/overdue→void/refunded |
| `ProformaInvoice` | `status` | draft→sent→accepted/expired→converted |
| `Payment` | `status` | pending→succeeded/failed→refunded |
| `Refund` | `status` | pending→processing→approved→completed |
| `Subscription` | `status` | pending→active→cancelled/expired (private `_method_now()` FSM transitions) |
| `Service` | `status` | pending→provisioning→active→suspended/terminated |
| `Domain` | `status` | pending→active→expired/suspended/transfer_out |
| `Ticket` | `status` | open→in_progress/waiting_on_customer→closed |

**Rules:**
- **NEVER** assign `.status = "value"` directly — use FSM transition methods (e.g., `order.confirm()`)
- **NEVER** use `QuerySet.update(status=)` or `bulk_update` with FSM fields
- For test setup, use `force_status(instance, "target")` from `tests/helpers/fsm_helpers.py`
- `ConcurrentTransitionMixin` on `Order` and `Service` (optimistic locking)
- `refresh_from_db()` is overridden on FSM models to bypass the descriptor guard
- Lint: `make lint-fsm` (also runs as Phase 6 of `make lint`)
- Inline bypass: `# fsm-bypass: reason` comment on the line

**FSM Change Protocol (Mandatory for any transition modification):**

When modifying any FSM transition (adding gates, changing preconditions, adding side effects):

1. **Parallel Paths Audit:** Before writing code, grep for ALL code paths that reach the target state:
   ```bash
   rg "\.target_method\b|\.target_state" --type py -l
   ```
   List every path in views, services, tasks, signals, webhooks, admin, and management commands.
   Each path must be explicitly marked: MUST UPDATE / NO CHANGE (with reason).

2. **Background Task Consistency:** Every background task (`tasks.py`) that calls FSM transitions must go through the same service method as the primary path. Direct `model.transition()` calls in tasks are prohibited — they bypass gates.

3. **Exception Completeness:** Models with `ConcurrentTransitionMixin` (Order, Service) require catching BOTH `TransitionNotAllowed` AND `ConcurrentTransition` — they are separate exception hierarchies.

**Test Quality Rules:**

Tests must satisfy these checks (enforced during review):

1. **No tautological assertions:** `force_status(x, "done"); assertEqual(x.status, "done")` always passes. Test real transitions.
2. **No mock-the-unit-under-test:** Mock external dependencies (email, Stripe API), never the service being tested.
3. **Boundary coverage:** Threshold tests must include: above, at boundary, and below.
4. **Failure path coverage:** Every test file with happy-path tests must also test at least one failure/error path.
5. **Signal/on_commit testing:** Use `self.captureOnCommitCallbacks(using="default")` for deferred side effects.

## Commands

All commands run from project root via Makefile.

### Development
```bash
make install          # Set up dev environment (uv sync)
make dev              # Start both services (platform :8700, portal :8701)
make dev-platform     # Platform service only
make dev-portal       # Portal service only
make migrate          # Run platform database migrations
make fixtures         # Load comprehensive sample data
make fixtures-light   # Load minimal sample data (fast)
make build-css        # Build Tailwind CSS for all services
make watch-css        # Watch and rebuild CSS during development
```

### Testing
```bash
make test                    # Run ALL tests (platform + portal + integration)
make test-fast               # Fast platform tests (failfast + keepdb + parallel)
make test-platform           # Platform tests (Django test runner + SQLite)
make test-platform-pytest    # Platform tests via pytest
make test-portal             # Portal tests (SQLite sessions only, no business DB)
make test-integration        # Cross-service integration tests
make test-e2e                # Playwright E2E tests (requires services running)
make test-security           # Service isolation validation
make test-cache              # Database cache tests (no Redis)

# Run a specific test file
make test-file FILE=tests.users.test_users_2fa
make test-fast FILE=tests.users.test_users_2fa   # Same, but with failfast + keepdb
```

### Code Quality
```bash
make lint              # Lint all services (Ruff + Django checks)
make lint-fix          # Auto-fix safe lint issues (ruff --fix)
make lint-platform     # Lint platform only
make lint-portal       # Lint portal only
make lint-fsm          # FSM guardrail lint (ADR-0034)
make lint-security     # Security static analysis (Semgrep + credentials)
make check-types       # MyPy type checking all services
make check-pysyntax    # Syntax check all Python files (or FILE=<path> for one)
make pre-commit        # Run all pre-commit hooks
```

### IMPORTANT: Always Use Makefile Targets

**NEVER** invoke `python`, `python3`, `pytest`, `ruff`, `mypy`, or any `.venv-*/bin/*` binary directly.
Always use `make` targets which resolve the correct OS-specific venv (`.venv-darwin/` on macOS, `.venv-linux/` on Linux).

| Instead of | Use |
|-----------|-----|
| `python -c "import ast; ..."` | `make check-pysyntax FILE=<path>` |
| `python manage.py test ...` | `make test-file FILE=<dotted.path>` or `make test-fast` |
| `mypy apps/...` | `make check-types FILE=<relative-to-platform>` |
| `ruff check .` | `make lint` (or `make lint FILE=<path>` for one file) |
| `ruff check --fix .` | `make lint-fix` (or `make lint-fix FILE=<path>` for one file) |
| `pytest ...` | `make test-platform-pytest` |

### Deployment
```bash
make docker-build      # Build Docker images
make docker-dev        # Start dev services via docker-compose
make docker-prod       # Start production services
make backup            # Database backup
make restore-latest    # Restore from latest backup
make health-check      # Check service health
```

## Testing Details

Three-layer testing architecture:

1. **Platform tests** (`services/platform/tests/`) - Full DB access, Django test runner primary, pytest alternative. Mirrors `apps/` structure. Uses `config.settings.dev`.
2. **Portal tests** (`services/portal/tests/`) - SQLite for sessions only; `@pytest.mark.no_db` opt-in blocks business DB access. Tests API proxies and HMAC auth.
3. **Integration/E2E tests** (`tests/`) - Cross-service tests at project root. E2E uses Playwright.

Test naming: `test_{app}_{feature}.py` (e.g., `test_users_2fa.py`)

Test credentials: `admin@pragmatichost.com` / `admin123` (superuser), `customer@pragmatichost.com` / `testpass123` (customer)

### Test setUpClass Ordering Rule

In any `TestCase.setUpClass()` override, **ALWAYS** check skip conditions and raise `SkipTest` BEFORE calling `super().setUpClass()`. The `super()` call acquires the database connection and enters an atomic block. Raising `SkipTest` after that poisons the PostgreSQL connection for the entire test suite.

```python
# WRONG — corrupts PG connection, causes cascade failures
@classmethod
def setUpClass(cls):
    super().setUpClass()
    if not CREDENTIALS:
        raise SkipTest("missing creds")  # BAD: atomic block already open

# RIGHT — safe skip before connection is acquired
@classmethod
def setUpClass(cls):
    if not CREDENTIALS:
        raise SkipTest("missing creds")  # GOOD: no connection yet
    super().setUpClass()
```

This bug is invisible on SQLite but causes 2,900+ cascade errors on PostgreSQL.

## Code Quality

### Tooling
- **Ruff** for linting and formatting (line length 120, configured in `pyproject.toml`)
- **MyPy** with Django plugin (`django-stubs`), layered strict strategy (ADR-0009)
- **Pre-commit hooks**: ruff-format, ruff new-violations-only, mypy modified-files, type-ignore prevention, template syntax, portal isolation, credential scanning, i18n coverage, performance anti-patterns
- **UV** for workspace dependency management (`pyproject.toml` at root defines workspace)
- Coverage target: 90% on changed lines

### Outbound HTTP Security

All outbound HTTP requests **must** use the helpers in `apps.common.outbound_http`:
- **`safe_request(method, url, policy=...)`** — DNS-pinned `requests`-compatible API (Platform)
- **`safe_urlopen(url, policy=...)`** — `urllib` wrapper for callsites needing `HTTPResponse` (Platform)
- **`portal_request(method, url, ...)`** — thin wrapper enforcing HTTPS/timeout/no-redirects (Portal, in `apps.common.outbound_http`)

Pre-built policies (`OutboundPolicy` frozen dataclass):
| Policy | Use case |
|--------|----------|
| `STRICT_EXTERNAL` | Default — HTTPS-only, no redirects, DNS pinning |
| `TRUSTED_PROVIDER` | Known provider APIs (longer timeout, retries) |
| `INTERNAL_SERVICE` | Platform-internal — allows HTTP |

To add a new outbound integration:
1. Define an `OutboundPolicy` with appropriate `allowed_domains`, `timeout_seconds`, and `verify_tls`
2. Call `safe_request(method, url, policy=your_policy, ...)`
3. Add tests verifying private IP rejection and redirect blocking
4. Never use raw `requests.get/post` or `urllib.request.urlopen` outside the helper module

> For full policy definitions, SSRF prevention details, and dangerous ports list, see [Security Configuration Guide](docs/security/SECURITY_CONFIGURATION.md#8-outbound-http-security).

### Ruff Rules — Write Compliant Code (ADR-0002)

These are the rules that fail most often. Follow them when writing ANY Python code:

| Rule | What it means | How to comply |
|------|--------------|---------------|
| **PLC0415** | Imports must be at module top | Move imports to top of file. Only use local imports inside `TYPE_CHECKING` blocks or with `# noqa: PLC0415` when circular imports force it. Files in `apps/*/apps.py` are exempt. |
| **PLR0913** | Max 5 function parameters | Use a dataclass or TypedDict for parameter groups. For test helpers, `# noqa: PLR0913` is acceptable. |
| **PLR2004** | No magic numbers in production code | Define named constants: `MAX_RETRY = 3`, `DEFAULT_PAGE_SIZE = 20`. Test files are exempt. |
| **C901/PLR0912/PLR0915** | Function too complex (>12 branches, >50 statements) | Extract helper functions. Target: each function does one thing. |
| **ANN001/ANN201** | Missing type annotations | All public functions need parameter + return type annotations. Test files are exempt. |
| **F401** | Unused import | Remove it. If needed for re-export, use `__all__`. |
| **F841** | Unused local variable | Remove it, or prefix with `_` if intentionally unused. |
| **SIM105** | Use `contextlib.suppress(X)` | Replace `try: ... except X: pass` with `with contextlib.suppress(X):` |
| **S110** | Silent exception swallowing | Never bare `except: pass`. Log the exception or use `contextlib.suppress`. |
| **PIE807** | Use `list` not `lambda: []` | For default factory callables, `list` is the idiomatic empty-list callable. |
| **RUF100** | Unused `noqa` directive | Remove `# noqa: RULE` if the rule isn't actually triggered on that line. |
| **RUF012** | Mutable class variable needs `ClassVar` | Use `ClassVar[list[...]]` for class-level mutables. Django model/form `Meta` classes and admin classes are exempt. |

### MyPy Rules — Layered Type Strategy (ADR-0009)

MyPy uses a **pragmatic layered strategy**: strict for business logic, relaxed for Django framework layers.

| Module pattern | Strictness | Notes |
|----------------|-----------|-------|
| `*.services.*`, `*.repos.*`, `*.gateways.*`, `*.validators` | **Strict** | Full `disallow_untyped_defs`, `disallow_untyped_calls` |
| `*.views`, `*.forms`, `*.serializers` | **Relaxed** | `attr-defined`, `misc`, `assignment`, `type-arg` suppressed |
| `*.admin` | **Relaxed** | Dynamic attributes from Django admin metaclass |
| `*.models` | **Default + RUF012** | ORM fields create noise; `RUF012` exempted |

**Critical rules:**
- **NEVER add `# type: ignore`** — the pre-commit hook blocks all new type-ignore comments. Fix the type issue instead:
  - Use `from __future__ import annotations` + `TYPE_CHECKING` block for circular imports
  - Use type narrowing (`if x is not None:`, `isinstance()`, `assert`) instead of ignoring
  - For `union-attr` on `request.user`: add `if request.user.is_authenticated:` guard
  - For Django ORM attributes: check if the module override in `pyproject.toml` already suppresses it
- **No bare `Any`** — use specific types. If truly dynamic, use `object` or a Protocol.
- **Result pattern** — use `Ok[T]` / `Err[E]` from `apps.common.types` instead of raising exceptions in services (ADR-0003)

### Pre-commit Pipeline Order

The hooks run in this order — failures at any stage block the commit:
1. `trailing-whitespace`, `end-of-file-fixer`, `check-merge-conflict`
2. `ruff-format` — auto-formats (files modified → need re-stage)
3. `ruff-new-violations` — blocks NEW violations only (historical debt tolerated)
4. `check-types-modified` — mypy on staged `.py` files
5. `prevent-type-ignore` — blocks any new `# type: ignore` comment
6. `django-template-check` — template syntax (spacing in comparisons)
7. `portal-isolation-check` — portal must not import from platform
8. `security-credentials-check` — no hardcoded secrets
9. `i18n-coverage` — unwrapped user-facing strings
10. `performance-check` — O(N^2) and other anti-patterns
11. `fsm-guardrails` — FSM lint checks (ADR-0034): direct status assignment, missing save(), naive datetime, objects.create bypass

## Conventions

### Commits
- Format: `type(scope): short imperative summary`
- Types: `feat|fix|perf|refactor|docs|test|build|ci|chore|revert`
- Do not mention AI or Claude in commit messages
- One logical change per commit; commit after tests pass

### Branches
- `feat/<slug>`, `fix/<slug>`, `refactor/<slug>`
- Squash merge with Conventional Commit title

### Versioning & Tags
- **SemVer** (semver.org): `0.MINOR.PATCH` during pre-1.0 alpha
- **Minor bump** (0.Y.0) for every new feature or breaking change - not just patches
- **Patch bump** (0.0.Z) only for bug fixes
- Tags are annotated: `git tag -a v0.27.0 -m "v0.27.0 - Description"`
- Version tracked in `pyproject.toml` (`version = "0.27.0"`) - keep in sync with tags
- CHANGELOG.md must be updated with each version bump
- Current: **v0.27.0** (alpha) - see `git tag -l 'v*' --sort=version:refname` for full history

### Naming
| Kind | Style | Example |
|------|-------|---------|
| Python files | `snake_case` | `credential_vault.py` |
| Directories | `snake_case` for Python, `kebab-case` for docs | `api_handlers/` |
| Classes | `PascalCase` | `ConnectionManager` |
| Functions/vars | `snake_case` | `track_active_sockets()` |
| Constants | `UPPER_SNAKE` | `MAX_RETRY_ATTEMPTS` |

### Logging
Include emoji tag + scope + message: `✅ [Proxy] Started TCP tunnel on :443`

| Emoji | Level | Use |
|-------|-------|-----|
| ✅ | INFO | Successful milestones |
| ⚠️ | WARN | Recoverable anomaly |
| 🔥 | ERROR | Unhandled exception |
| 🚀 | STARTUP | Service/task startup |
| 🐢 | SLOW PATH | Performance degradation |

### Golden Rules
1. **Fail Fast, Loud & Logged** - Every unexpected branch logs and returns early
2. **Small Diffs, High Tests** - PRs < 400 LOC; >= 90% coverage for touched lines
3. **Type Safety First** - Python type hints for all new code, no bare `Any`
4. **Complexity Budget** - Target <= O(log N). O(N^2)+ needs `# Complexity:` comment
5. **User Impact** - Breaking user-visible changes get `BREAKING CHANGE` tag

## Django Template Pitfalls

### Comparison operators MUST have spaces
```
Wrong: {% if variable==value %}
Right: {% if variable == value %}
```

### Filter arguments MUST NOT have spaces
```
Wrong: {{ value | floatformat : 0 }}
Right: {{ value|floatformat:0 }}
```

### HTMX attributes must stay on one line
```html
<!-- Wrong -->
<button hx-get="/url"
        hx-target="#result">

<!-- Right -->
<button hx-get="/url" hx-target="#result">
```

Fix all templates: `make fix-templates` | Validate: `make check-templates`

> For XSS prevention patterns and CSP compliance, see [Template and CSP Security Guide](docs/development/TEMPLATE-AND-CSP-SECURITY.md).

## HTMX Guidelines

- Always provide `hx-swap` default (use `innerHTML`)
- Use `hx-confirm` for destructive actions
- Use `htmx-indicator` class for loading states
- Search inputs: `hx-trigger="keyup changed delay:500ms"`
- Use `aria-disabled` and `tabindex="-1"` for disabled states

> For HTMX CSRF patterns and CSP considerations, see [Template and CSP Security Guide](docs/development/TEMPLATE-AND-CSP-SECURITY.md).

### HTMX Partials Development

HTMX endpoints return HTML fragments, not full pages. Follow this pattern:

```python
# View: return a rendered partial template
def my_widget(request: HttpRequest) -> HttpResponse:
    return render(request, "app/partials/widget.html", context)
```

```html
<!-- Trigger: use hx-get/hx-post on a visible element -->
<button hx-post="{% url 'app:action' %}" hx-headers='{"X-CSRFToken": "{{ csrf_token }}"}' hx-swap="none" hx-indicator="#spinner">
```

- Every HTMX endpoint **must have a visible trigger** (button, input, link) — invisible API-only endpoints are untestable and unusable
- POST endpoints need CSRF: use `hx-headers='{"X-CSRFToken": "{{ csrf_token }}"}'`
- Use `hx-swap="none"` for endpoints returning JSON (e.g., sync actions)
- Partial templates go in `templates/app/partials/` subdirectory

### HTMX Partials E2E Testing

HTMX partials can't be tested with `page.goto()` (returns fragment, not full page). Use `page.evaluate(fetch())`:

```python
response_data: dict = page.evaluate("""
    async () => {
        const resp = await fetch('/app/partial/', {
            credentials: 'same-origin',
            headers: { 'HX-Request': 'true' },
        });
        return { status: resp.status, html: await resp.text() };
    }
""")
```

For POST partials, include CSRF token extraction:
```python
response_data: dict = page.evaluate("""
    async () => {
        const csrfToken = document.querySelector('[name=csrfmiddlewaretoken]')?.value
            || document.cookie.match(/csrftoken=([^;]+)/)?.[1] || '';
        const resp = await fetch('/app/action/', {
            method: 'POST',
            credentials: 'same-origin',
            headers: { 'HX-Request': 'true', 'X-CSRFToken': csrfToken },
        });
        return { status: resp.status, html: await resp.text() };
    }
""")
```

## Internationalization

- **Coverage**: 100% Romanian (ro) + English (en) — Platform 4,470 entries, Portal 1,285 entries
- All user-facing strings must use `{% trans %}` / `{% blocktrans %}` in templates, `gettext_lazy()` in Python
- Use `locale/` folder exclusively for translation files
- **Extraction**: `make i18n-extract` (runs `makemessages -l ro` on both services)
- **Compilation**: `make i18n-compile` (runs `compilemessages` on both services)
- **Translation workflow**: `make translate-ai` → review YAML → `make translate-apply`
- **Stats**: `make translate-stats` for per-app coverage
- **Linter**: `scripts/lint_i18n_coverage.py` detects unwrapped strings (integrated in `make lint` Phase 4)
- Romanian plural forms use 3 variants: singular, 2-19, 20+

## Romanian Business Context

- **CUI validation**: Romanian company identifiers (RO12345678)
- **VAT**: 21% Romanian rate (Aug 2025), EU cross-border with reverse charge
- **Invoice numbering**: Sequential, legally required
- **e-Factura**: XML generation for Romanian tax authority (ANAF)
- **GDPR**: Full compliance with Romanian Law 190/2018
- **Currency**: Amounts stored in cents, display via template filters
