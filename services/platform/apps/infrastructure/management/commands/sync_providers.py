"""
Management command to sync cloud provider catalog data from APIs.

Usage:
    python manage.py sync_providers                    # Sync all providers
    python manage.py sync_providers --provider hetzner # Specific provider
    python manage.py sync_providers --dry-run          # Preview changes
"""

from __future__ import annotations

import contextlib
import os
from argparse import ArgumentParser
from typing import Any

from django.core.management.base import BaseCommand, CommandError

from apps.infrastructure.provider_sync import sync_hetzner_provider


class Command(BaseCommand):
    help = "Sync cloud provider catalog data (regions, server types, pricing) from APIs"

    def add_arguments(self, parser: ArgumentParser) -> None:
        parser.add_argument(
            "--provider",
            type=str,
            choices=["hetzner"],
            help="Sync only a specific provider (default: all)",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Preview changes without writing to database",
        )

    def handle(self, *args: Any, **options: Any) -> None:
        provider = options.get("provider")
        dry_run = options.get("dry_run", False)

        if dry_run:
            self.stdout.write(self.style.WARNING("DRY RUN — no changes will be made"))

        providers_to_sync = [provider] if provider else ["hetzner"]

        for p in providers_to_sync:
            if p == "hetzner":
                self._sync_hetzner(dry_run=dry_run)

    def _sync_hetzner(self, dry_run: bool = False) -> None:
        self.stdout.write("🌐 Syncing Hetzner Cloud provider catalog...")

        # Get token from environment or CredentialVault
        token = os.environ.get("HCLOUD_TOKEN", "")
        if not token:
            with contextlib.suppress(Exception):
                from apps.common.credential_vault import get_credential_vault  # noqa: PLC0415

                vault = get_credential_vault()
                token = vault.get_secret("hcloud_token") or ""

        if not token:
            self.stdout.write(
                self.style.WARNING(
                    "⚠️  No HCLOUD_TOKEN found in environment or credential vault. "
                    "Set HCLOUD_TOKEN env var or add 'hcloud_token' to credential vault."
                )
            )
            return

        result = sync_hetzner_provider(token=token, dry_run=dry_run)

        if result.is_err():
            raise CommandError(f"Hetzner sync failed: {result.unwrap_err()}")

        sync_result = result.unwrap()
        self.stdout.write(self.style.SUCCESS(f"✅ Hetzner sync complete: {sync_result.summary}"))

        if sync_result.errors:
            for error in sync_result.errors:
                self.stdout.write(self.style.ERROR(f"  Error: {error}"))
