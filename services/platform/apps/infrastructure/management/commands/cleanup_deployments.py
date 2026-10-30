"""
Infrastructure CLI: cleanup_deployments

Clean up stale failed deployments by removing orphaned cloud resources
and marking deployments as cleaned. This provides CLI parity with the
``cleanup_failed_deployments_task`` that runs as a scheduled Django-Q2 task.

Each deployment runs through the same teardown as destroy and the sweep: a
deployment is marked destroyed only when its DNS, servers, firewalls and keys
are proven gone. Only the cloud resources are removed — the database record is
preserved for audit trail purposes.

Usage examples::

    # Preview what would be cleaned (safe)
    $ python manage.py cleanup_deployments --dry-run

    # Clean deployments failed for more than 24 hours (default)
    $ python manage.py cleanup_deployments

    # Clean deployments failed for more than 6 hours
    $ python manage.py cleanup_deployments --max-age-hours 6

    # Clean only a specific provider's failed deployments
    $ python manage.py cleanup_deployments --provider hetzner

See also:
    - deploy_node: Deploy a new infrastructure node
    - manage_node: Lifecycle operations (destroy, stop, start, etc.)
"""

from __future__ import annotations

import logging
from argparse import ArgumentParser
from datetime import timedelta
from typing import Any

from django.core.management.base import BaseCommand
from django.utils import timezone

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    """
    Clean up stale failed deployments and their orphaned cloud resources.

    Mirrors the behavior of ``cleanup_failed_deployments_task`` in tasks.py,
    but runs interactively with progress output and --dry-run support.

    Design decisions:
    - The shared teardown (node_teardown): a provider call that fails, or a
      token that is missing, leaves the deployment 'destroying' with its
      identifiers for the next run, never 'destroyed'.
    - Database records are never deleted — they're preserved for the audit
      trail. Only the cloud-side resources are cleaned up.
    - The ``destroyed`` status transition marks cleanup completion.
    """

    help = "Clean up stale failed deployments and orphaned cloud resources"

    def add_arguments(self, parser: ArgumentParser) -> None:
        parser.add_argument(
            "--max-age-hours",
            type=int,
            default=24,
            help="Only clean deployments failed longer than N hours (default: 24)",
        )
        parser.add_argument(
            "--provider",
            type=str,
            default=None,
            help="Limit cleanup to a specific provider type",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Show what would be cleaned without executing",
        )

    def handle(self, *args: Any, **options: Any) -> None:
        """
        Find and clean up stale failed deployments.

        Queries for deployments in 'failed' status older than the cutoff,
        attempts to delete their cloud resources, and transitions them
        to 'destroyed' status.

        The method continues on individual failures — one broken deployment
        doesn't prevent cleanup of the rest.
        """
        from apps.infrastructure.models import (  # noqa: PLC0415  # Deferred: avoids circular import
            NodeDeployment,  # Circular: cross-app  # Deferred: avoids circular import
        )

        max_age_hours = options["max_age_hours"]
        dry_run = options.get("dry_run", False)

        # Calculate the age cutoff — only clean deployments that have been
        # in 'failed' status for longer than max_age_hours
        cutoff = timezone.now() - timedelta(hours=max_age_hours)

        # Build queryset with optional provider filter
        queryset = NodeDeployment.objects.select_related("provider").filter(
            status="failed",
            updated_at__lt=cutoff,
        )

        if options.get("provider"):
            queryset = queryset.filter(provider__provider_type=options["provider"])

        deployments = list(queryset)

        if not deployments:
            self.stdout.write("No stale failed deployments found matching criteria.")
            return

        self.stdout.write(f"Found {len(deployments)} failed deployment(s) older than {max_age_hours} hours")

        if dry_run:
            self.stdout.write(self.style.WARNING("\nDRY RUN — no cleanup will be performed\n"))
            for dep in deployments:
                age_hours = (timezone.now() - dep.updated_at).total_seconds() / 3600
                self.stdout.write(
                    f"  {dep.hostname} "
                    f"({dep.provider.name}, "
                    f"server_id={dep.external_node_id or 'none'}, "
                    f"age={age_hours:.0f}h)"
                )
            return

        # Execute cleanup
        cleaned = 0
        errors = 0

        for dep in deployments:
            success = self._cleanup_deployment(dep, cutoff)
            if success:
                cleaned += 1
            else:
                errors += 1

        # Summary
        self.stdout.write(
            f"\n📊 Cleanup complete: {cleaned} cleaned, {errors} error(s) out of {len(deployments)} total"
        )

    def _cleanup_deployment(self, deployment: Any, stale_before: Any) -> bool:
        """
        Clean up a single failed deployment through the shared teardown.

        The same path as the scheduled sweep and destroy: the claim re-checks status and age under the
        row lock and refuses an occupied node, and every step proves its resources gone. A step that
        cannot leaves the row 'destroying' with its identifiers, never 'destroyed' (H15).

        Args:
            deployment: NodeDeployment instance in 'failed' status.
            stale_before: The age cutoff, re-checked under the row lock.

        Returns:
            True if the teardown finished, False if it was refused or stopped.
        """
        from apps.infrastructure.node_teardown import teardown_stale_deployment  # noqa: PLC0415  # Circular

        self.stdout.write(f"  🧹 Cleaning {deployment.hostname}...")
        try:
            result = teardown_stale_deployment(deployment, stale_before=stale_before)
        except Exception as e:
            self.stderr.write(self.style.ERROR(f"    🔥 Error cleaning {deployment.hostname}: {e}"))
            logger.error(f"[Cleanup] Error cleaning {deployment.hostname}: {e}")
            return False
        if result.is_err():
            self.stderr.write(self.style.WARNING(f"    ⚠️  {deployment.hostname}: {result.unwrap_err()}"))
            return False
        self.stdout.write(self.style.SUCCESS(f"    ✅ Cleaned: {deployment.hostname}"))
        return True
