"""
Unified initial data seeding for all PRAHO deployment modes.

Orchestrates existing setup commands in two tiers:

- **Core** (always): settings categories, default settings, scheduled tasks,
  email templates, superuser from env vars.
- **Business** (prod/staging auto-detect): tax rules, dunning policies.

Auto-detects the environment from DJANGO_SETTINGS_MODULE:
  prod/staging → core + business
  dev          → core only (use --include-business or --all to add business)

All sub-commands are idempotent (get_or_create) — safe to run on every deploy.
"""

import os
import time
from typing import Any

from django.core.management import call_command
from django.core.management.base import BaseCommand, CommandParser

CORE_COMMANDS: list[tuple[str, str]] = [
    ("setup_settings_categories", "Setting categories"),
    ("setup_default_settings", "Default system settings"),
    ("setup_scheduled_tasks", "Scheduled background tasks"),
    ("setup_email_templates", "Email templates"),
    ("ensure_superuser", "Superuser account"),
]

BUSINESS_COMMANDS: list[tuple[str, str]] = [
    ("setup_tax_rules", "Romanian & EU tax rules"),
    ("setup_dunning_policies", "Payment retry policies"),
]


def _detect_tiers() -> list[str]:
    """Auto-detect which tiers to run from DJANGO_SETTINGS_MODULE."""
    settings_module = os.environ.get("DJANGO_SETTINGS_MODULE", "")
    if "prod" in settings_module or "staging" in settings_module:
        return ["core", "business"]
    return ["core"]


class Command(BaseCommand):
    help = "Set up initial data for PRAHO Platform (idempotent, safe for every deploy)"

    def add_arguments(self, parser: CommandParser) -> None:
        group = parser.add_mutually_exclusive_group()
        group.add_argument(
            "--tier",
            choices=["core", "business"],
            help="Run only a specific tier",
        )
        group.add_argument(
            "--all",
            action="store_true",
            help="Run all tiers (core + business)",
        )
        group.add_argument(
            "--include-business",
            action="store_true",
            help="Add business tier (useful in dev to seed tax rules / dunning)",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Show what would run without executing",
        )

    def handle(self, *args: Any, **options: Any) -> None:
        dry_run: bool = options.get("dry_run", False)

        # Determine which tiers to run
        tiers = self._resolve_tiers(options)

        commands: list[tuple[str, str]] = []
        if "core" in tiers:
            commands.extend(CORE_COMMANDS)
        if "business" in tiers:
            commands.extend(BUSINESS_COMMANDS)

        self.stdout.write("")
        self.stdout.write(self.style.SUCCESS("🎯 PRAHO Initial Data Setup"))
        self.stdout.write(f"   Tiers: {', '.join(tiers)}")
        self.stdout.write(f"   Commands: {len(commands)}")
        if dry_run:
            self.stdout.write(self.style.WARNING("   Mode: DRY RUN (no changes)"))
        self.stdout.write("")

        if dry_run:
            self._print_dry_run(commands)
            return

        results = self._execute_commands(commands)
        self._print_summary(results)

    def _resolve_tiers(self, options: dict[str, Any]) -> list[str]:
        """Resolve which tiers to run from CLI flags and auto-detection."""
        if options.get("tier"):
            return [options["tier"]]
        if options.get("all"):
            return ["core", "business"]

        tiers = _detect_tiers()
        if options.get("include_business") and "business" not in tiers:
            tiers.append("business")
        return tiers

    def _print_dry_run(self, commands: list[tuple[str, str]]) -> None:
        """Print what would run without executing."""
        for cmd_name, label in commands:
            self.stdout.write(f"  ⏩ {label} ({cmd_name})")
        self.stdout.write("")
        self.stdout.write(f"Would run {len(commands)} commands. Use without --dry-run to execute.")

    def _execute_commands(self, commands: list[tuple[str, str]]) -> list[tuple[str, str, str, float]]:
        """Execute commands sequentially, catching errors per-command."""
        results: list[tuple[str, str, str, float]] = []

        for cmd_name, label in commands:
            self.stdout.write(f"  ▶ {label}...")
            t0 = time.monotonic()
            try:
                call_command(cmd_name)
                elapsed = time.monotonic() - t0
                results.append((cmd_name, label, "ok", elapsed))
                self.stdout.write(self.style.SUCCESS(f"    ✅ done ({elapsed:.1f}s)"))
            except Exception as exc:
                elapsed = time.monotonic() - t0
                results.append((cmd_name, label, f"error: {exc}", elapsed))
                self.stdout.write(self.style.ERROR(f"    ⚠️  {cmd_name} failed: {exc}"))

        return results

    def _print_summary(self, results: list[tuple[str, str, str, float]]) -> None:
        """Print final summary table."""
        ok_count = sum(1 for *_, status, _ in results if status == "ok")
        fail_count = len(results) - ok_count
        total_time = sum(t for *_, t in results)

        self.stdout.write("")
        self.stdout.write("━" * 60)
        self.stdout.write(f"  ✅ {ok_count} succeeded   ⚠️  {fail_count} failed   ⏱  {total_time:.1f}s total")
        self.stdout.write("━" * 60)

        if fail_count > 0:
            self.stdout.write("")
            self.stdout.write(self.style.ERROR("Failed commands:"))
            for _cmd_name, label, status, _ in results:
                if status != "ok":
                    self.stdout.write(f"  ❌ {label}: {status}")
