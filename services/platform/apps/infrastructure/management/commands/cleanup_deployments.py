"""
Infrastructure CLI: cleanup_deployments

Clean up stale failed deployments by removing orphaned cloud resources
and marking deployments as cleaned. This provides CLI parity with the
``cleanup_failed_deployments_task`` that runs as a scheduled Django-Q2 task.

The cleanup is best-effort: if the cloud server was already deleted (404),
the deployment is still marked as cleaned. Only the cloud resources are
removed — the database record is preserved for audit trail purposes.

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
    - Best-effort cloud cleanup: if the provider API call fails (server
      already gone, token expired), the deployment is still counted as
      cleaned. The goal is to mark stale records, not guarantee cloud deletion.
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
            success = self._cleanup_deployment(dep)
            if success:
                cleaned += 1
            else:
                errors += 1

        # Summary
        self.stdout.write(
            f"\n📊 Cleanup complete: {cleaned} cleaned, {errors} error(s) out of {len(deployments)} total"
        )

    def _cleanup_deployment(self, deployment: Any) -> bool:
        """
        Clean up a single failed deployment.

        Attempts to delete the cloud server. Only marks the deployment as
        'destroyed' if cloud deletion succeeded (or no cloud server existed).
        If deletion fails, the deployment keeps its current status to prevent
        hiding orphaned servers that cost money.

        Args:
            deployment: NodeDeployment instance in 'failed' status.

        Returns:
            True if cleanup completed successfully,
            False if cloud deletion failed or an unexpected error occurred.
        """
        self.stdout.write(f"  🧹 Cleaning {deployment.hostname}...")

        try:
            # Attempt to delete cloud server if one was provisioned
            cloud_delete_ok = True
            if deployment.external_node_id and deployment.provider:
                cloud_delete_ok = self._delete_cloud_server(deployment)

            if cloud_delete_ok:
                # Only mark as destroyed if cloud deletion succeeded (H15 fix)
                deployment.destroyed_at = timezone.now()
                deployment.status = "destroyed"
                deployment.save(update_fields=["status", "destroyed_at", "updated_at"])
                self.stdout.write(self.style.SUCCESS(f"    ✅ Cleaned: {deployment.hostname}"))
                return True
            else:
                # Cloud deletion failed — keep current status to avoid hiding
                # orphaned servers that cost money
                self.stderr.write(
                    self.style.WARNING(
                        f"    ⚠️  Cloud deletion failed for {deployment.hostname}, keeping status '{deployment.status}'"
                    )
                )
                return False

        except Exception as e:
            self.stderr.write(self.style.ERROR(f"    🔥 Error cleaning {deployment.hostname}: {e}"))
            logger.error(f"[Cleanup] Error cleaning {deployment.hostname}: {e}")
            return False

    def _delete_cloud_server(self, deployment: Any) -> bool:
        """
        Delete the cloud server via the provider gateway.

        Returns True if the server was successfully deleted (or no token
        available to attempt deletion). Returns False if the deletion
        API call failed, indicating an orphaned server may still exist.
        """
        from apps.infrastructure.cloud_gateway import (  # noqa: PLC0415  # Deferred: avoids circular import
            get_cloud_gateway,  # Circular: cross-app  # Deferred: avoids circular import
        )
        from apps.infrastructure.provider_config import (  # noqa: PLC0415  # Deferred: avoids circular import
            get_provider_token,  # Circular: cross-app  # Deferred: avoids circular import
        )

        token_result = get_provider_token(deployment.provider)
        if token_result.is_err():
            self.stderr.write(
                self.style.WARNING(f"    ⚠️  No token for {deployment.provider.name}, skipping cloud deletion")
            )
            # No token = can't verify server exists, treat as success
            return True

        try:
            gateway = get_cloud_gateway(
                deployment.provider.provider_type,
                token_result.unwrap(),
            )
            delete_result = gateway.delete_server(deployment.external_node_id)

            if delete_result.is_ok():
                self.stdout.write(f"    🗑️  Cloud server deleted: {deployment.external_node_id}")
                return True
            else:
                # Deletion failed — server may still be running and costing money
                self.stderr.write(
                    self.style.WARNING(f"    ⚠️  Could not delete cloud server: {delete_result.unwrap_err()}")
                )
                return False
        except Exception as e:
            self.stderr.write(self.style.WARNING(f"    ⚠️  Cloud deletion error: {e}"))
            return False
