"""
Infrastructure CLI: manage_node

Perform lifecycle operations on deployed nodes by hostname. Supports all
actions available in the web UI: stop, start, reboot, destroy, retry, and
upgrade. Operations are provider-agnostic — they route through the same
service layer and cloud gateway ABC used by the web UI views.

Usage examples::

    # Power operations
    $ python manage.py manage_node prd-sha-het-de-fsn1-001 stop
    $ python manage.py manage_node prd-sha-het-de-fsn1-001 start
    $ python manage.py manage_node prd-sha-het-de-fsn1-001 reboot

    # Destroy with confirmation prompt
    $ python manage.py manage_node prd-sha-het-de-fsn1-001 destroy

    # Destroy without prompt (for scripting)
    $ python manage.py manage_node prd-sha-het-de-fsn1-001 destroy --force

    # Resize to a new server type
    $ python manage.py manage_node prd-sha-het-de-fsn1-001 upgrade --size cpx31

    # Queue via Django-Q2 instead of blocking
    $ python manage.py manage_node prd-sha-het-de-fsn1-001 reboot --async

    # Preview what would happen
    $ python manage.py manage_node prd-sha-het-de-fsn1-001 destroy --dry-run

See also:
    - deploy_node: Deploy a new infrastructure node
    - drift_scan: Run configuration drift scans
    - cleanup_deployments: Clean up stale failed deployments
"""

from __future__ import annotations

from argparse import ArgumentParser
from typing import Any

from django.core.management.base import BaseCommand, CommandError

from apps.common.types import Result
from apps.infrastructure.provider_config import get_provider_token

# Valid lifecycle actions — maps to service layer methods
VALID_ACTIONS = ("stop", "start", "reboot", "destroy", "retry", "upgrade")


class Command(BaseCommand):
    """
    Lifecycle management for deployed infrastructure nodes.

    Looks up a NodeDeployment by hostname, validates the requested action
    is valid for the deployment's current status, and dispatches to the
    appropriate service method. All operations go through the provider-
    agnostic service layer — no provider-specific code here.

    Supports both synchronous execution and async queuing via Django-Q2,
    matching the web UI's behavior exactly.
    """

    help = "Manage node lifecycle (stop/start/reboot/destroy/retry/upgrade) by hostname"

    def add_arguments(self, parser: ArgumentParser) -> None:
        parser.add_argument(
            "hostname",
            type=str,
            help="Node hostname (e.g., prd-sha-het-de-fsn1-001)",
        )
        parser.add_argument(
            "action",
            type=str,
            choices=VALID_ACTIONS,
            help="Lifecycle action to perform",
        )
        parser.add_argument(
            "--size",
            type=str,
            default=None,
            help="New server size (required for 'upgrade' action)",
        )
        parser.add_argument(
            "--async",
            action="store_true",
            dest="run_async",
            help="Queue via Django-Q2 instead of running synchronously",
        )
        parser.add_argument(
            "--force",
            action="store_true",
            help="Skip confirmation prompt for destructive actions (destroy)",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Show what would happen without executing",
        )

    def handle(self, *args: Any, **options: Any) -> None:
        """
        Execute the requested lifecycle action on the specified node.

        Validates status preconditions, resolves credentials, and dispatches
        to either sync or async execution path.

        Raises:
            CommandError: If node not found, invalid status for action,
                         credentials missing, or action fails.
        """
        from apps.infrastructure.models import (  # noqa: PLC0415  # Deferred: avoids circular import
            NodeDeployment,  # Circular: cross-app  # Deferred: avoids circular import
        )

        hostname = options["hostname"]
        action = options["action"]

        # Resolve deployment by hostname
        deployment = (
            NodeDeployment.objects.select_related("provider", "node_size", "region").filter(hostname=hostname).first()
        )

        if not deployment:
            raise CommandError(f"No deployment found with hostname '{hostname}'.")

        # Validate: upgrade requires --size
        if action == "upgrade" and not options.get("size"):
            raise CommandError("--size is required for the 'upgrade' action.")

        # Validate credentials exist
        token_result = get_provider_token(deployment.provider)
        if token_result.is_err():
            raise CommandError(
                f"No API token found for {deployment.provider.name}. "
                f"Run: python manage.py store_credentials {deployment.provider.provider_type}"
            )

        # Dry run: show what would happen and exit
        if options.get("dry_run"):
            self.stdout.write(self.style.WARNING("DRY RUN — no action will be executed\n"))
            self.stdout.write(
                f"  Hostname:  {deployment.hostname}\n"
                f"  Provider:  {deployment.provider.name}\n"
                f"  Status:    {deployment.get_status_display()}\n"
                f"  Action:    {action}\n"
            )
            if action == "upgrade":
                self.stdout.write(f"  New Size:  {options['size']}\n")
            return

        # Confirmation prompt for destroy — bypassed with --force for scripting
        if action == "destroy" and not options.get("force"):
            confirm = input(
                f"⚠️  Destroy '{deployment.hostname}'? This will delete the cloud server. Type the hostname to confirm: "
            )
            if confirm.strip() != hostname:
                raise CommandError("Confirmation failed. Destroy cancelled.")

        # Dispatch to async or sync execution
        if options.get("run_async"):
            self._dispatch_async(deployment, action, options)
        else:
            self._dispatch_sync(deployment, action, token_result.unwrap(), options)

    def _validate_status_for_action(self, deployment: Any, action: str) -> None:
        """
        Validate that the deployment's current status allows the requested action.

        Mirrors the precondition checks done in views.py to prevent invalid
        state transitions. Without this, async queuing would accept actions
        that would later fail at execution time.

        Raises:
            CommandError: If the deployment status is incompatible with the action.
        """
        status = deployment.status

        # Status sets that permit each action
        stoppable = {"completed"}  # Only running nodes can be stopped
        startable = {"stopped"}  # Only stopped nodes can be started
        rebootable = {"completed"}  # Only running nodes can be rebooted
        destroyable = {"completed", "stopped", "failed"}  # Not pending/provisioning
        retryable = {"failed"}  # Only failed nodes can be retried

        checks: dict[str, tuple[set[str], str]] = {
            "stop": (stoppable, "Cannot stop a node in '{status}' status. Must be: completed."),
            "start": (startable, "Cannot start a node in '{status}' status. Must be: stopped."),
            "reboot": (rebootable, "Cannot reboot a node in '{status}' status. Must be: completed."),
            "destroy": (
                destroyable,
                "Cannot destroy a node in '{status}' status. Must be: completed, stopped, or failed.",
            ),
            "retry": (retryable, "Cannot retry a node in '{status}' status. Must be: failed."),
            "upgrade": (stoppable, "Cannot upgrade a node in '{status}' status. Must be: completed."),
        }

        if action in checks:
            valid_statuses, msg_template = checks[action]
            if status not in valid_statuses:
                raise CommandError(msg_template.format(status=status))

    def _dispatch_async(
        self,
        deployment: Any,
        action: str,
        options: dict[str, Any],
    ) -> None:
        """
        Queue the action via Django-Q2 for async execution.

        Validates deployment status preconditions before queuing to prevent
        invalid state transitions from being silently accepted.

        Uses the queue_* functions from tasks.py which only receive IDs —
        tokens are fetched from the credential vault at task execution time.
        """
        # H14 fix: validate status before queuing (mirrors web UI checks)
        self._validate_status_for_action(deployment, action)

        from apps.infrastructure.tasks import (  # Circular: cross-app  # noqa: PLC0415  # Deferred: avoids circular import
            queue_destroy_node,
            queue_reboot_node,
            queue_retry_deployment,
            queue_start_node,
            queue_stop_node,
            queue_upgrade_node,
        )

        provider_id = deployment.provider_id

        # Action → queue function dispatch table
        if action == "stop":
            task_id = queue_stop_node(deployment.id, provider_id)
        elif action == "start":
            task_id = queue_start_node(deployment.id, provider_id)
        elif action == "reboot":
            task_id = queue_reboot_node(deployment.id, provider_id)
        elif action == "destroy":
            task_id = queue_destroy_node(
                deployment.id,
                provider_id,
            )
        elif action == "retry":
            task_id = queue_retry_deployment(
                deployment.id,
                provider_id,
            )
        elif action == "upgrade":
            size = self._resolve_size(deployment, options["size"])
            task_id = queue_upgrade_node(deployment.id, size.id, provider_id)
        else:
            raise CommandError(f"Unknown action: {action}")

        self.stdout.write(
            self.style.SUCCESS(f"✅ {action.capitalize()} queued for {deployment.hostname} (task_id={task_id})")
        )

    def _dispatch_sync(
        self,
        deployment: Any,
        action: str,
        token: str,
        options: dict[str, Any],
    ) -> None:
        """
        Execute the action synchronously, blocking until completion.

        Calls the same service methods used by the async tasks, but directly
        in the current process. Provides immediate feedback.
        """
        from apps.infrastructure.deployment_service import (  # noqa: PLC0415  # Deferred: avoids circular import
            get_deployment_service,  # Circular: cross-app
        )

        service = get_deployment_service()

        # Build credentials dict — service layer expects {"api_token": "xxx"}
        credentials = {"api_token": token}

        self.stdout.write(f"🚀 Executing {action} on {deployment.hostname}...")

        # Action → service method dispatch
        node_result: Result[Any, str]
        if action == "stop":
            node_result = service.stop_node(deployment, credentials)
        elif action == "start":
            node_result = service.start_node(deployment, credentials)
        elif action == "reboot":
            node_result = service.reboot_node(deployment, credentials)
        elif action == "destroy":
            node_result = service.destroy_node(deployment, credentials)
        elif action == "retry":
            node_result = service.retry_deployment(deployment, credentials)
        elif action == "upgrade":
            size = self._resolve_size(deployment, options["size"])
            node_result = service.upgrade_node_size(deployment, size, credentials)
        else:
            raise CommandError(f"Unknown action: {action}")

        if node_result.is_err():
            raise CommandError(f"{action.capitalize()} failed: {node_result.unwrap_err()}")

        self.stdout.write(self.style.SUCCESS(f"✅ {action.capitalize()} completed for {deployment.hostname}"))

    def _resolve_size(self, deployment: Any, size_slug: str) -> Any:
        """
        Resolve a NodeSize by provider_type_id for the deployment's provider.

        Raises:
            CommandError: If the size is not found or belongs to a different provider.
        """
        from apps.infrastructure.models import (  # noqa: PLC0415  # Deferred: avoids circular import
            NodeSize,  # Circular: cross-app  # Deferred: avoids circular import
        )

        size = NodeSize.objects.filter(
            provider=deployment.provider,
            provider_type_id=size_slug,
            is_active=True,
        ).first()

        if not size:
            available = list(
                NodeSize.objects.filter(provider=deployment.provider, is_active=True).values_list(
                    "provider_type_id", flat=True
                )
            )
            raise CommandError(
                f"Size '{size_slug}' not found for {deployment.provider.name}. Available: {', '.join(available)}"
            )
        return size
