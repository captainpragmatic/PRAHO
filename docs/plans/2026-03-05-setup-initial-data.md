# Unified Initial Data Seeding (`setup_initial_data`)

## Context

Database setup is inconsistent across deployment modes: native Ansible runs 3 setup commands,
Docker runs nothing (no entrypoint), and `make fixtures` runs 4 commands. There's no superuser
automation. A single `setup_initial_data` command should be the canonical bootstrap for all
deployment modes — production-safe, idempotent, and auto-detecting the environment.

## Approach

Create a 2-tier orchestrator command (`setup_initial_data`) that calls existing setup commands
in sequence. Core tier always runs; Business tier auto-activates for prod/staging based on
`DJANGO_SETTINGS_MODULE`. Rename `setup_categories` → `setup_settings_categories` with
backward-compat alias. Add `ensure_superuser` for env-var-based superuser creation. Add Docker
entrypoint. Simplify Ansible and Makefile to use the single command.

## Tasks

### 1. Rename `setup_categories` → `setup_settings_categories`
- **File:** `services/platform/apps/settings/management/commands/setup_categories.py`
- **Change:** Rename file to `setup_settings_categories.py` (git mv). Content stays identical.
- **Test:** `python manage.py setup_settings_categories` works, creates 15 categories.

### 2. Create backward-compat alias for `setup_categories`
- **Depends on:** Task 1
- **File:** `services/platform/apps/settings/management/commands/setup_categories.py` (new)
- **Change:** Thin wrapper that imports and calls `setup_settings_categories` with a
  `self.stderr.write(self.style.WARNING("⚠️ setup_categories is deprecated, use setup_settings_categories"))`.
  Call the parent command via `call_command('setup_settings_categories', **options)`.
- **Test:** `python manage.py setup_categories` still works, prints deprecation warning.

### 3. Create `ensure_superuser` management command
- **File:** `services/platform/apps/common/management/commands/ensure_superuser.py` (new)
- **Change:** Create command that:
  - Reads `DJANGO_SUPERUSER_EMAIL` and `DJANGO_SUPERUSER_PASSWORD` from `os.environ`
  - If both set AND `User.objects.filter(is_superuser=True).count() == 0`:
    - In non-DEBUG: reject passwords < 12 chars or in a deny list (`admin123`, `changeme`, `password`, etc.)
    - Create superuser via `User.objects.create_superuser(email=..., password=...)`
    - Print `✅ Superuser created: {email}`
  - If env vars missing: print `💡 Hint: set DJANGO_SUPERUSER_EMAIL and DJANGO_SUPERUSER_PASSWORD to auto-create`
  - If superuser already exists: print `⏭️ Superuser already exists, skipping`
  - Add `--force` flag to skip the "already exists" check (creates additional superuser)
- **Test:** Run with env vars set → creates user. Run again → skips. Run without env vars → prints hint.

### 4. Create `setup_initial_data` orchestrator command
- **Depends on:** Tasks 1, 2, 3
- **File:** `services/platform/apps/common/management/commands/setup_initial_data.py` (new)
- **Change:** Create command that orchestrates existing setup commands:
  - Auto-detect logic:
    ```python
    settings_module = os.environ.get("DJANGO_SETTINGS_MODULE", "")
    is_prod_or_staging = "prod" in settings_module or "staging" in settings_module
    ```
  - Core tier (always runs):
    1. `call_command('setup_settings_categories')`
    2. `call_command('setup_default_settings')`
    3. `call_command('setup_scheduled_tasks')`
    4. `call_command('setup_email_templates')`
    5. `call_command('ensure_superuser')`
  - Business tier (prod/staging auto-detect, or `--include-business`, or `--all`):
    6. `call_command('setup_tax_rules')`
    7. `call_command('setup_dunning_policies')`
  - CLI arguments:
    - `--tier=core|business` — run only that tier
    - `--all` — run all tiers
    - `--include-business` — add business tier (for dev environments)
    - `--dry-run` — print what would run without executing
  - Each sub-command wrapped in try/except: log error, continue to next
  - Print summary table at end: command name, status (✅/⚠️/⏭️), duration
- **Test:** Run in dev settings → core only. Run with `--all` → core + business. Run with `--dry-run` → prints plan.

### 5. Write tests for `setup_initial_data`
- **Depends on:** Task 4
- **File:** `services/platform/tests/common/test_setup_initial_data.py` (new)
- **Change:** Test cases:
  - `test_core_tier_runs_all_core_commands` — mock `call_command`, verify 5 core commands called
  - `test_business_tier_auto_detects_prod` — with `DJANGO_SETTINGS_MODULE=config.settings.prod`, verify tax_rules + dunning called
  - `test_business_tier_skipped_in_dev` — with dev settings, verify tax_rules NOT called
  - `test_include_business_flag` — explicit flag adds business tier in dev
  - `test_dry_run_does_not_execute` — verify no `call_command` calls in dry-run mode
  - `test_tier_flag_overrides_auto_detect` — `--tier=core` in prod skips business
  - `test_sub_command_failure_continues` — if one command raises, others still run
- **Test:** `make test-file FILE=tests.common.test_setup_initial_data`

### 6. Write tests for `ensure_superuser`
- **Depends on:** Task 3
- **File:** `services/platform/tests/common/test_ensure_superuser.py` (new)
- **Change:** Test cases:
  - `test_creates_superuser_from_env_vars` — set env vars, run, verify user created
  - `test_skips_when_superuser_exists` — create a superuser first, run, verify no new user
  - `test_skips_when_env_vars_missing` — no env vars, run, verify no user + hint printed
  - `test_rejects_weak_password_in_prod` — DEBUG=False + weak password → error, no user
  - `test_allows_weak_password_in_dev` — DEBUG=True + weak password → creates user (dev convenience)
  - `test_force_flag_creates_additional_superuser` — even with existing superuser
- **Test:** `make test-file FILE=tests.common.test_ensure_superuser`

### 7. Create Docker entrypoint script
- **File:** `deploy/platform/entrypoint.sh` (new)
- **Change:** Create bash entrypoint:
  ```bash
  #!/bin/bash
  set -e
  echo "🚀 Running database migrations..."
  python manage.py migrate --noinput
  echo "📦 Collecting static files..."
  python manage.py collectstatic --noinput
  echo "🏗️ Creating cache table..."
  python manage.py createcachetable 2>/dev/null || true
  echo "🎯 Setting up initial data..."
  python manage.py setup_initial_data
  echo "✅ Starting Gunicorn..."
  exec gunicorn --bind 0.0.0.0:${PORT:-8700} --workers ${GUNICORN_WORKERS:-4} --timeout 120 config.wsgi:application
  ```
  Make executable: `chmod +x deploy/platform/entrypoint.sh`
- **Test:** `bash -n deploy/platform/entrypoint.sh` (syntax check)

### 8. Update Platform Dockerfile to use entrypoint
- **Depends on:** Task 7
- **File:** `deploy/platform/Dockerfile`
- **Change:**
  - Add `COPY deploy/platform/entrypoint.sh /app/entrypoint.sh` after the code COPY
  - Before USER directive, add `RUN chmod +x /app/entrypoint.sh`
  - Replace `CMD ["gunicorn", ...]` with `ENTRYPOINT ["/app/entrypoint.sh"]`
  - Keep `CMD` empty or remove (entrypoint handles everything)
- **Test:** `docker build -f deploy/platform/Dockerfile .` succeeds

### 9. Simplify Ansible native role to use `setup_initial_data`
- **Depends on:** Task 4
- **File:** `deploy/ansible/roles/praho-native/tasks/main.yml`
- **Change:** Replace the 4 separate tasks (lines 256-282: setup_categories, setup_default_settings,
  setup_scheduled_tasks) with a single task:
  ```yaml
  - name: Set up initial data
    command: >
      {{ project_root }}/.venv/bin/python manage.py setup_initial_data
    args:
      chdir: "{{ project_root }}/src/services/platform"
    become_user: "{{ project_user }}"
    environment: "{{ django_env }}"
  ```
- **Test:** Review YAML syntax, ensure `django_env` is still in scope

### 10. Update Makefile targets
- **Depends on:** Task 4
- **File:** `Makefile`
- **Change:**
  - `dev-platform` target: replace 4 setup calls (lines 182-189) with single
    `@$(PYTHON_PLATFORM_MANAGE) setup_initial_data --settings=config.settings.dev || echo "⚠️ Initial data setup skipped"`
  - `fixtures` target: replace 4 setup calls (lines 416-422) with
    `@$(PYTHON_PLATFORM_MANAGE) setup_initial_data --include-business --settings=config.settings.dev`
    then keep `generate_sample_data` call as-is
  - `fixtures-light` target: same pattern but keep the smaller `generate_sample_data` args
  - `migrate` target: leave as-is (just runs migrate, no setup)
- **Test:** `make dev-platform` starts successfully, `make fixtures` loads data

### 11. Add superuser env vars to `.env.example.dev`
- **File:** `.env.example.dev`
- **Change:** Add section after "Allowed hosts":
  ```
  # Superuser (auto-created on first setup_initial_data if no superuser exists)
  DJANGO_SUPERUSER_EMAIL=admin@pragmatichost.com
  DJANGO_SUPERUSER_PASSWORD=admin123
  ```
- **Test:** File is valid, values are clearly dev-only

### 12. Add superuser env vars to Ansible env templates
- **File:** `deploy/ansible/roles/praho-native/templates/env.native.j2`
- **Change:** Add lines (values from Ansible vars, not hardcoded):
  ```
  # Superuser (only used on first deploy)
  {% if superuser_email is defined and superuser_email %}
  DJANGO_SUPERUSER_EMAIL={{ superuser_email }}
  DJANGO_SUPERUSER_PASSWORD={{ superuser_password }}
  {% endif %}
  ```
- **File:** `deploy/ansible/roles/praho/templates/env.j2`
- **Change:** Same addition for Docker env template
- **Test:** Template renders correctly with and without vars defined
