"""
Infrastructure CLI: deploy_node

Deploy a new infrastructure node via CLI, with full parity to the web UI's
deployment_create view. Resolves provider, region, and size by their
identifiers, auto-generates hostname and node number, and either queues the
deployment asynchronously (via Django-Q2) or runs it synchronously.

The command is fully provider-agnostic — it uses the CloudProviderGateway
ABC and credential vault, supporting Hetzner, DigitalOcean, AWS, and Vultr
identically.

Usage examples::

    # Deploy with async queuing (matches web UI behavior)
    $ python manage.py deploy_node --provider hetzner --environment prd \\
        --region fsn1 --size cpx21 --async

    # Synchronous deploy (blocks until complete or failed)
    $ python manage.py deploy_node --provider hetzner --environment dev \\
        --region fsn1 --size cpx21

    # Preview what would be deployed without executing
    $ python manage.py deploy_node --provider digitalocean --environment stg \\
        --region nyc1 --size s-2vcpu-4gb --dry-run

See also:
    - store_credentials: Store provider API tokens in the vault
    - manage_node: Lifecycle operations on deployed nodes
    - sync_providers: Sync provider catalog (regions, sizes)
"""

from __future__ import annotations

from argparse import ArgumentParser
from typing import Any

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from apps.infrastructure.provider_config import get_provider_token


class Command(BaseCommand):
    """
    Deploy a new infrastructure node via the cloud provider gateway.

    This command mirrors the web UI's ``deployment_create`` view:
    1. Resolves provider, region, size, and panel type from DB
    2. Validates that API credentials exist in the vault
    3. Auto-generates hostname via the naming convention
    4. Queues deployment via Django-Q2 (--async) or runs synchronously

    All provider-specific logic is handled by the CloudProviderGateway ABC —
    this command contains zero provider-specific code.
    """

    help = "Deploy a new infrastructure node (provider-agnostic, CLI parity with web UI)"

    def add_arguments(self, parser: ArgumentParser) -> None:
        # Required arguments matching the web UI's NodeDeploymentForm fields
        parser.add_argument(
            "--provider",
            type=str,
            required=True,
            help="Provider slug (hetzner, digitalocean, aws, vultr)",
        )
        parser.add_argument(
            "--environment",
            type=str,
            required=True,
            choices=["prd", "stg", "dev"],
            help="Deployment environment (prd=Production, stg=Staging, dev=Development)",
        )
        parser.add_argument(
            "--region",
            type=str,
            required=True,
            help="Region identifier (e.g., fsn1, nyc1, us-east-1)",
        )
        parser.add_argument(
            "--size",
            type=str,
            required=True,
            help="Server size/type identifier (e.g., cpx21, s-2vcpu-4gb)",
        )

        # Optional arguments with sensible defaults
        parser.add_argument(
            "--node-type",
            type=str,
            default="sha",
            choices=["sha", "vps", "ctr", "ded", "app"],
            help="Node type (default: sha=Shared Hosting)",
        )
        parser.add_argument(
            "--panel",
            type=str,
            default="virtualmin",
            help="Control panel type (default: virtualmin)",
        )
        parser.add_argument(
            "--image",
            type=str,
            default="ubuntu-22.04",
            help="OS image (default: ubuntu-22.04)",
        )
        parser.add_argument(
            "--hostname",
            type=str,
            default=None,
            help="Custom hostname (auto-generated from naming convention if omitted)",
        )
        parser.add_argument(
            "--display-name",
            type=str,
            default="",
            help="Optional friendly display name",
        )

        # Execution mode flags
        parser.add_argument(
            "--async",
            action="store_true",
            dest="run_async",
            help="Queue deployment via Django-Q2 (matches web UI behavior)",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Preview the deployment plan without executing",
        )

    def handle(self, *args: Any, **options: Any) -> None:
        """
        Execute the node deployment pipeline.

        Resolves all referenced objects (provider, region, size, panel),
        validates credentials, creates the NodeDeployment record, and
        dispatches to either async queue or synchronous execution.

        Raises:
            CommandError: If any referenced object not found, credentials missing,
                         or deployment fails.
        """
        from apps.infrastructure.models import (  # Circular: cross-app  # noqa: PLC0415  # Deferred: avoids circular import
            CloudProvider,
            NodeDeployment,
            NodeRegion,
            NodeSize,
            PanelType,
        )
        from apps.settings.services import (  # noqa: PLC0415  # Deferred: avoids circular import
            SettingsService,  # Circular: cross-app  # Deferred: avoids circular import
        )

        # Check if deployment is enabled globally (same check as web UI)
        if not SettingsService.get_setting("node_deployment.enabled", True):
            raise CommandError("Node deployment is disabled in settings.")

        # --- Resolve provider ---
        provider = CloudProvider.objects.filter(
            provider_type=options["provider"],
            is_active=True,
        ).first()
        if not provider:
            raise CommandError(f"No active provider found for type '{options['provider']}'.")

        # --- Resolve region by provider_region_id within this provider ---
        region = NodeRegion.objects.filter(
            provider=provider,
            provider_region_id=options["region"],
            is_active=True,
        ).first()
        if not region:
            # Show available regions to help the user
            available = list(
                NodeRegion.objects.filter(provider=provider, is_active=True).values_list(
                    "provider_region_id", flat=True
                )
            )
            raise CommandError(
                f"Region '{options['region']}' not found for {provider.name}. "
                f"Available: {', '.join(available) or 'none (run sync_providers first)'}"
            )

        # --- Resolve size by provider_type_id within this provider ---
        size = NodeSize.objects.filter(
            provider=provider,
            provider_type_id=options["size"],
            is_active=True,
        ).first()
        if not size:
            available = list(
                NodeSize.objects.filter(provider=provider, is_active=True).values_list("provider_type_id", flat=True)
            )
            raise CommandError(
                f"Size '{options['size']}' not found for {provider.name}. "
                f"Available: {', '.join(available) or 'none (run sync_providers first)'}"
            )

        # --- Resolve panel type ---
        panel = PanelType.objects.filter(panel_type=options["panel"], is_active=True).first()
        if not panel:
            raise CommandError(f"Panel type '{options['panel']}' not found or inactive.")

        # --- Validate credentials exist before creating the deployment ---
        token_result = get_provider_token(provider)
        if token_result.is_err():
            raise CommandError(
                f"No API token found for {provider.name}. Run: python manage.py store_credentials {options['provider']}"
            )

        # --- Dry run: show plan and exit WITHOUT creating DB records ---
        # (C2 fix: dry-run must not call save() or consume a node number)
        if options.get("dry_run"):
            self.stdout.write(self.style.WARNING("DRY RUN — no deployment will be executed\n"))
            self._print_dry_run_summary(provider, region, size, options)
            return

        # --- Create NodeDeployment record (mirrors deployment_create view) ---
        with transaction.atomic():
            node_number = NodeDeployment.get_next_node_number(
                environment=options["environment"],
                node_type=options["node_type"],
                provider=provider,
                region=region,
            )

            deployment = NodeDeployment(
                environment=options["environment"],
                node_type=options["node_type"],
                provider=provider,
                node_size=size,
                region=region,
                panel_type=panel,
                node_number=node_number,
                display_name=options.get("display_name", ""),
                # initiated_by is None for CLI (no authenticated user)
                initiated_by=None,
            )

            # Auto-generate hostname unless explicitly provided
            if options.get("hostname"):
                deployment.hostname = options["hostname"]
            # else: save() calls generate_hostname() automatically

            # Set DNS zone from settings (same as web UI)
            deployment.dns_zone = str(SettingsService.get_setting("node_deployment.dns_default_zone", "") or "")

            deployment.save()

        # --- Dispatch deployment ---
        self._print_deployment_summary(deployment, provider, region, size)

        if options.get("run_async"):
            self._deploy_async(deployment, provider)
        else:
            self._deploy_sync(deployment, token_result.unwrap())

    def _deploy_async(self, deployment: Any, provider: Any) -> None:
        """
        Queue deployment via Django-Q2 (matches web UI behavior).

        The queue function only receives IDs — tokens are fetched from the
        credential vault at task execution time, preventing cleartext secrets
        from being serialized to the Django-Q2 task queue.
        """
        from apps.infrastructure.tasks import (  # noqa: PLC0415  # Deferred: avoids circular import
            queue_deploy_node,  # Circular: cross-app  # Deferred: avoids circular import
        )

        task_id = queue_deploy_node(
            deployment_id=deployment.id,
            provider_id=provider.id,
        )

        self.stdout.write(self.style.SUCCESS(f"✅ Deployment queued: {deployment.hostname} (task_id={task_id})"))

    def _deploy_sync(self, deployment: Any, token: str) -> None:
        """
        Run deployment synchronously (blocks until complete or failed).

        Calls the same ``deploy_node()`` service method used by the async
        task, but directly in the current process. Useful for debugging
        and single-node deployments where you want immediate feedback.
        """
        from apps.infrastructure.deployment_service import (  # noqa: PLC0415  # Deferred: avoids circular import
            get_deployment_service,  # Circular: cross-app
        )

        self.stdout.write("🚀 Starting synchronous deployment (this may take several minutes)...")

        service = get_deployment_service()

        # Build credentials dict — service layer expects {"api_token": "xxx"}
        credentials = {"api_token": token}

        result = service.deploy_node(deployment, credentials)

        if result.is_err():
            raise CommandError(f"Deployment failed: {result.unwrap_err()}")

        deploy_result = result.unwrap()
        self.stdout.write(
            self.style.SUCCESS(
                f"✅ Deployment complete: {deployment.hostname}\n"
                f"   Server ID: {deploy_result.cloud_result.server_id if deploy_result.cloud_result else 'N/A'}\n"
                f"   IPv4: {deployment.ipv4_address or 'N/A'}\n"
                f"   Duration: {deploy_result.duration_seconds:.1f}s\n"
                f"   Stages: {', '.join(deploy_result.stages_completed)}"
            )
        )

    def _print_dry_run_summary(
        self,
        provider: Any,
        region: Any,
        size: Any,
        options: dict[str, Any],
    ) -> None:
        """Print a preview summary for dry-run mode (no DB records created)."""
        self.stdout.write(
            f"\n  Provider:    {provider.name} ({provider.provider_type})\n"
            f"  Region:      {region.name} ({region.provider_region_id})\n"
            f"  Size:        {size.display_name} ({size.provider_type_id})\n"
            f"  Environment: {options['environment']}\n"
            f"  Node Type:   {options.get('node_type', 'sha')}\n"
            f"  Hostname:    {options.get('hostname') or '(auto-generated)'}\n"
        )

    def _print_deployment_summary(
        self,
        deployment: Any,
        provider: Any,
        region: Any,
        size: Any,
    ) -> None:
        """Print a human-readable summary of the deployment configuration."""
        self.stdout.write(
            f"\n  Provider:    {provider.name} ({provider.provider_type})\n"
            f"  Region:      {region.name} ({region.provider_region_id})\n"
            f"  Size:        {size.display_name} ({size.provider_type_id})\n"
            f"  Environment: {deployment.get_environment_display()}\n"
            f"  Node Type:   {deployment.get_node_type_display()}\n"
            f"  Hostname:    {deployment.hostname}\n"
        )
