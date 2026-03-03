"""
Management command to sync cloud provider catalog data from APIs.

Usage:
    python manage.py sync_providers                    # Sync all providers
    python manage.py sync_providers --provider hetzner # Specific provider
    python manage.py sync_providers --dry-run          # Preview changes
"""

from __future__ import annotations

from argparse import ArgumentParser
from typing import Any

from django.core.management.base import BaseCommand, CommandError

from apps.infrastructure.provider_config import (
    PROVIDER_SYNC_REGISTRY,
    get_provider_sync_fn,
    get_provider_token,
)


class Command(BaseCommand):
    help = "Sync cloud provider catalog data (regions, server types, pricing) from APIs"

    def add_arguments(self, parser: ArgumentParser) -> None:
        parser.add_argument(
            "--provider",
            type=str,
            choices=list(PROVIDER_SYNC_REGISTRY.keys()),
            help="Sync only a specific provider (default: all registered)",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Preview changes without writing to database",
        )

    def handle(self, *args: Any, **options: Any) -> None:
        provider_filter = options.get("provider")
        dry_run = options.get("dry_run", False)

        if dry_run:
            self.stdout.write(self.style.WARNING("DRY RUN — no changes will be made"))

        providers_to_sync = [provider_filter] if provider_filter else list(PROVIDER_SYNC_REGISTRY.keys())

        for provider_type in providers_to_sync:
            self._sync_provider(provider_type, dry_run=dry_run)

    def _sync_provider(self, provider_type: str, dry_run: bool = False) -> None:
        from apps.infrastructure.models import CloudProvider  # noqa: PLC0415

        self.stdout.write(f"🌐 Syncing {provider_type} provider catalog...")

        sync_fn = get_provider_sync_fn(provider_type)
        if not sync_fn:
            self.stdout.write(self.style.WARNING(f"⚠️  No sync function registered for {provider_type}"))
            return

        # Find active provider of this type to get credentials
        provider = CloudProvider.objects.filter(provider_type=provider_type, is_active=True).first()
        if not provider:
            self.stdout.write(self.style.WARNING(f"⚠️  No active {provider_type} provider configured"))
            return

        token_result = get_provider_token(provider)
        if token_result.is_err():
            self.stdout.write(
                self.style.WARNING(
                    f"⚠️  No credentials found for {provider.name}. "
                    f"Store token in credential vault or set environment variable."
                )
            )
            return

        result = sync_fn(token=token_result.unwrap(), dry_run=dry_run)

        if result.is_err():
            raise CommandError(f"{provider_type} sync failed: {result.unwrap_err()}")

        sync_result = result.unwrap()
        self.stdout.write(self.style.SUCCESS(f"✅ {provider_type} sync complete: {sync_result.summary}"))

        if sync_result.errors:
            for error in sync_result.errors:
                self.stdout.write(self.style.ERROR(f"  Error: {error}"))
