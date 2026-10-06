# Pre-commit Hooks Guide

PRAHO runs a set of pre-commit hooks on every `git commit` to keep type safety, architecture
boundaries and code quality from regressing. `.pre-commit-config.yaml` is the authoritative list of
hooks. This guide explains them and how to work with them, and the config wins wherever the two
disagree.

## Install

```bash
make install
```

`make install` syncs both services' dependencies and runs `pre-commit install`. If the hooks ever go
missing, run it again. The hooks run through `scripts/run_project_python`, which picks this
machine's virtualenv: `.venv-darwin` on macOS, `.venv-linux` on Linux.

## What runs on commit

These groups summarise the hooks. Use the config file for the exact ids, arguments and file filters.

| Group | Hook ids | Blocks the commit? |
|---|---|---|
| File hygiene | `trailing-whitespace`, `end-of-file-fixer`, `check-yaml`, `check-added-large-files`, `check-merge-conflict`, `debug-statements`, `check-shebang-scripts-are-executable` | Yes. Fixers rewrite the file and fail the commit; see below |
| Ruff | `ruff-format` (formats), `ruff-new-violations` (no new violations against the base) | Yes |
| Typing | `check-types-modified` (mypy on staged files), `prevent-type-ignore` (no new `# type: ignore` in staged files) | Yes |
| Templates | `django-template-check` (spacing around comparison operators, check only), `lint-template-components` (design-system rules) | Yes |
| Architecture and security guards | `portal-isolation-check`, `audit-coverage-check`, `code-health-check`, `cross-app-model-import-check`, `fsm-guardrail-check`, `secret-key-isolation`, `i18n-coverage-check` | Yes |
| Informational | `security-credentials-check` (Ruff S105-S108), `performance-check` (Ruff PERF/C90/PIE/SIM) | **No.** They print findings and always pass |

`check-executables-have-shebangs` is configured for the manual stage only.

## Run the hooks by hand

Set `PC` to this machine's pre-commit binary:

```bash
PC=.venv-$(uname -s | tr '[:upper:]' '[:lower:]')/bin/pre-commit

$PC run                          # Staged files, exactly as a commit would run it
$PC run --all-files              # Every file; the exit code is honest
$PC run fsm-guardrail-check --all-files   # One hook
```

`make pre-commit` also runs every hook on every file, but it **always exits 0**, printing "skipped"
when a hook fails. Read its output, or use `$PC run --all-files` when you need pass/fail.

## When a hook fails

- **A fixer rewrote files** (`ruff-format`, `trailing-whitespace`, `end-of-file-fixer`). The commit
  fails and `git status` shows those files as `MM`. Run `git add` on them and commit again.
- **Type check.** Reproduce it with `make check-types FILE=apps/users/models.py`, using a path
  relative to `services/platform`. For the portal, use `make check-types-portal`.
- **Template comparison spacing.** Write `{% if a == b %}`, not `{% if a==b %}`. The hook runs
  `services/platform/scripts/fix_template_comparisons.py --check`, and running that script without
  `--check` rewrites the templates.
- **A new `# type: ignore`.** Fix the type instead. `prevent_type_ignore.py --allow-legacy` exists
  only for code that predates the rule.

If the commit fails after you typed a long message, the message is gone. For long messages, write
them to a file and commit with `git commit -F <file>`.

## Skipping hooks

```bash
SKIP=check-types-modified git commit -m "wip: ..."                    # One hook, by id
SKIP=ruff-format,ruff-new-violations git commit -m "wip: ..."         # Several hooks
git commit --no-verify -m "..."                                       # Everything
```

Use the ids from the config. There is no single `ruff` id: the Ruff hooks are `ruff-format` and
`ruff-new-violations`. CI does not run pre-commit. `make lint` in CI covers Ruff and most of the
scans, but not every hook, so a skipped hook may go unchecked until someone runs it.

## Helper scripts

Run them through `scripts/run_project_python`, from the repository root:

| Script | Purpose |
|---|---|
| `services/platform/scripts/check_types_modified.py [--staged \| --since <ref>] [--verbose]` | mypy on changed files only |
| `services/platform/scripts/prevent_type_ignore.py [--check-all] [--allow-legacy]` | Reports `# type: ignore` comments |
| `services/platform/scripts/type_coverage_report.py [--markdown]` | Typing coverage report |
| `services/platform/scripts/fix_template_comparisons.py [--check]` | Template comparison spacing |

## Further reading

- [ADR-0003: Comprehensive Type Safety Implementation](../ADRs/ADR-0003-comprehensive-type-safety-implementation.md)
- [Gradual Typing Configuration](GRADUAL_TYPING_CONFIGURATION.md)
- [Strategic Linting Framework](../ADRs/ADR-0002-strategic-linting-framework.md)
- [Linting Guide](LINTING_GUIDE.md)
- [Pre-commit Documentation](https://pre-commit.com/)
