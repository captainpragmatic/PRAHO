"""Backfill trusted SHA-256 pins for self-signed Virtualmin node certificates."""

from __future__ import annotations

from typing import Any

from django.core.exceptions import ObjectDoesNotExist
from django.core.management.base import BaseCommand, CommandError, CommandParser

from apps.infrastructure.validation_service import get_validation_service
from apps.provisioning.virtualmin_models import VirtualminServer


class Command(BaseCommand):
    """Pin certificates through the deployment SSH trust path, never network TOFU."""

    help = "Pin self-signed Virtualmin certificates over trusted deployment SSH"

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument("--server-id", type=int, help="Limit the backfill to one VirtualminServer ID")
        parser.add_argument("--dry-run", action="store_true", help="List candidate servers without changing them")

    def handle(self, *args: Any, **options: Any) -> None:
        candidates = VirtualminServer.objects.filter(
            use_ssl=True,
            ssl_verify=False,
            ssl_cert_fingerprint="",
        )
        if options["server_id"] is not None:
            candidates = candidates.filter(pk=options["server_id"])
        servers = list(candidates)

        if options["dry_run"]:
            self.stdout.write(f"Would pin {len(servers)} Virtualmin certificate(s)")
            return

        validation = get_validation_service()
        pinned = 0
        failed = 0
        for server in servers:
            try:
                deployment = server.node_deployment
            except ObjectDoesNotExist:
                failed += 1
                self.stderr.write(
                    self.style.WARNING(
                        f"Skipped VirtualminServer {server.id} ({server.hostname}): no linked node deployment"
                    )
                )
                continue

            result = validation.get_webmin_certificate_fingerprint(deployment)
            if result.is_err():
                failed += 1
                self.stderr.write(
                    self.style.WARNING(
                        f"Could not pin VirtualminServer {server.id} ({server.hostname}): {result.unwrap_err()}"
                    )
                )
                continue

            server.ssl_cert_fingerprint = result.unwrap()
            server.save(update_fields=["ssl_cert_fingerprint", "updated_at"])
            pinned += 1

        self.stdout.write(self.style.SUCCESS(f"Pinned {pinned} Virtualmin certificate(s)"))
        if failed:
            raise CommandError(f"Failed to pin {failed} Virtualmin certificate(s)")
