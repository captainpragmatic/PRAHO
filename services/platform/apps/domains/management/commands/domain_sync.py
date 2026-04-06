"""Pull current domain status from registrars and detect drift.

Usage:
    python manage.py domain_sync                  # sync all active domains
    python manage.py domain_sync --domain example.com  # sync one domain
    python manage.py domain_sync --registrar gandi     # sync all domains at a registrar
    python manage.py domain_sync --dry-run             # show what would change
"""

from __future__ import annotations

import logging
from typing import Any

from django.core.management.base import BaseCommand, CommandParser

from apps.domains.models import Domain
from apps.domains.services import DomainLifecycleService

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = "Sync domain status from registrar APIs to detect drift"

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument("--domain", type=str, help="Sync a specific domain by name")
        parser.add_argument("--registrar", type=str, help="Sync all domains at a specific registrar")
        parser.add_argument("--dry-run", action="store_true", help="Show what would change without applying")

    def handle(self, *args: Any, **options: Any) -> None:
        domain_name = options.get("domain")
        registrar_name = options.get("registrar")
        dry_run = options.get("dry_run", False)

        domains = self._get_domains(domain_name, registrar_name)

        if not domains.exists():
            self.stdout.write(self.style.WARNING("No domains found matching criteria."))
            return

        total = domains.count()
        self.stdout.write(f"Syncing {total} domain(s){'  [DRY RUN]' if dry_run else ''}...")

        synced = 0
        failed = 0
        drifted = 0

        for domain in domains.select_related("registrar"):
            if dry_run:
                self.stdout.write(f"  Would sync: {domain.name} ({domain.registrar.name})")
                synced += 1
                continue

            result = DomainLifecycleService.sync_domain_info(domain)
            if result.is_ok():
                op = result.unwrap()
                if op.result:
                    drifted += 1
                    self.stdout.write(self.style.WARNING(f"  Synced (drift detected): {domain.name}"))
                else:
                    self.stdout.write(self.style.SUCCESS(f"  Synced: {domain.name}"))
                synced += 1
            else:
                self.stdout.write(self.style.ERROR(f"  Failed: {domain.name} — {result.unwrap_err()}"))
                failed += 1

        self.stdout.write("")
        self.stdout.write(f"Results: {synced} synced, {drifted} with drift, {failed} failed")

    def _get_domains(self, domain_name: str | None, registrar_name: str | None) -> Any:
        qs = Domain.objects.filter(status="active")

        if domain_name:
            qs = Domain.objects.filter(name=domain_name.lower())

        if registrar_name:
            qs = qs.filter(registrar__name=registrar_name)

        return qs
