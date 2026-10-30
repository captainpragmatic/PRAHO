"""
Node Deployment Service

Orchestrates the complete node deployment pipeline:
1. SSH key generation
2. Cloud provider provisioning (hcloud SDK)
3. DNS configuration
4. Ansible configuration
5. Validation
6. Registration
"""

from __future__ import annotations

import contextlib
import logging
import secrets
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Any, ClassVar

from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone
from django.utils.translation import gettext

from apps.common.types import Err, Ok, Result, Retriability, retriability_of
from apps.infrastructure.ansible_service import AnsibleResult, get_ansible_service, node_admin_allowed_cidrs
from apps.infrastructure.audit_service import InfrastructureAuditContext, InfrastructureAuditService
from apps.infrastructure.cloud_gateway import (
    CloudProviderGateway,
    FirewallRule,
    ServerCreateRequest,
    ServerCreateResult,
    get_cloud_gateway,
    node_firewall_rules,
)
from apps.infrastructure.deployment_lifecycle import (
    OperationLease,
    OperationOwnershipLostError,
    claim_operation,
    owned_transition,
    owned_update,
    provider_token_fingerprint,
    still_owns,
)
from apps.infrastructure.deployment_preflight import validate_deployment_fqdn
from apps.infrastructure.dns_gateway import DnsRecordSpec, ExpectedDnsRecord, get_dns_gateway
from apps.infrastructure.maintenance import resolve_maintenance_playbooks
from apps.infrastructure.node_teardown import (
    DESTROYABLE_STATES,
    claim_teardown,
    close_node_admission,
    deactivate_api_credential,
    record_destroy_failure,
    run_claimed_teardown,
)
from apps.infrastructure.provider_config import (
    run_provider_command,
)
from apps.infrastructure.registration_service import get_registration_service
from apps.infrastructure.ssh_key_manager import get_ssh_key_manager
from apps.infrastructure.validation_service import NodeValidationReport, get_validation_service
from apps.settings.services import SettingsService

if TYPE_CHECKING:
    from apps.infrastructure.models import NodeDeployment, NodeSize
    from apps.users.models import User

logger = logging.getLogger(__name__)

# The orderable check runs on a queue worker before the claim: fail fast instead of the SDK's
# default of no timeout and five retries.
ORDERABLE_CHECK_TIMEOUT_SECONDS = 10
ORDERABLE_CHECK_MAX_RETRIES = 1


@dataclass
class DeploymentProgress:
    """Tracks progress through deployment stages"""

    stage: str
    percentage: int
    message: str
    started_at: datetime = field(default_factory=timezone.now)
    completed_at: datetime | None = None
    error: str | None = None


@dataclass
class DeploymentResult:
    """Complete result of a deployment operation"""

    success: bool
    deployment_id: int
    hostname: str
    stages_completed: list[str]
    cloud_result: ServerCreateResult | None = None
    ansible_results: list[AnsibleResult] | None = None
    validation_report: NodeValidationReport | None = None
    virtualmin_server_id: Any = None
    error: str | None = None
    duration_seconds: float = 0.0


class NodeDeploymentService:
    """
    Main Deployment Orchestrator

    Manages the complete lifecycle of node deployments:
    - Initial deployment (hcloud SDK + Ansible)
    - Validation and registration
    - Upgrade operations
    - Destruction

    All operations are designed to be resumable and idempotent where possible.
    """

    # Deployment stages with progress percentages
    STAGES: ClassVar[dict[str, tuple[int, str]]] = {
        "init": (0, "Initializing deployment"),
        "ssh_key": (5, "Generating SSH key"),
        "provision_server": (15, "Creating cloud server"),
        "update_deployment": (40, "Updating deployment records"),
        "configuring_dns": (45, "Configuring DNS records"),
        "ansible_base": (50, "Running base configuration"),
        "ansible_panel": (60, "Installing control panel"),
        "ansible_harden": (70, "Hardening server"),
        "ansible_backup": (80, "Configuring backups"),
        "validation": (85, "Validating node"),
        "registration": (95, "Registering node"),
        "complete": (100, "Deployment complete"),
    }

    @staticmethod
    def _node_firewall_rules() -> list[FirewallRule]:
        return node_firewall_rules(node_admin_allowed_cidrs())

    def __init__(self) -> None:
        """Initialize deployment service with all required sub-services"""
        self._ssh_manager = get_ssh_key_manager()
        self._ansible = get_ansible_service()
        self._validation = get_validation_service()
        self._registration = get_registration_service()

    def _deployment_preflight(self, deployment: NodeDeployment) -> Result[tuple[str, ...], str]:
        """Reject unverified cloud image selectors before any deployment side effects."""
        from apps.infrastructure.models import CloudProvider  # noqa: PLC0415 -- Deferred app model import.

        provider_type = CloudProvider.objects.values_list("provider_type", flat=True).get(pk=deployment.provider_id)
        if provider_type != "hetzner":
            return Err(
                gettext(
                    "Automatic node deployment currently supports Hetzner Ubuntu 26.04 only. "
                    "Other provider image selectors require Ubuntu 24.04/26.04 verification before deployment or retry."
                )
            )
        try:
            return Ok(self._ansible.operator_public_keys())
        except (OSError, ValueError):
            return Err(
                gettext(
                    "Approved operator public keys are missing or invalid. "
                    "Configure PRAHO_SSH_OPERATOR_PUBLIC_KEYS_FILE before deployment or retry."
                )
            )

    @staticmethod
    def _provenance_refusal(deployment: NodeDeployment, api_token: str) -> str:
        """Why this token may not act on the row's provider resources, or "" when it may.

        A recorded fingerprint means a provider write was attempted (it is stored first): a key or
        firewall may exist under that token even when no server was, so only that token may continue.
        """
        may_hold_resources = (
            bool(deployment.external_node_id)
            or bool(deployment.provider_token_fingerprint)
            or deployment.server_create_state in ("intent", "unknown", "created")
        )
        if not may_hold_resources or deployment.provider_token_fingerprint == provider_token_fingerprint(api_token):
            return ""
        if not deployment.provider_token_fingerprint:
            return gettext(
                "The provider token that created this deployment's resources was never recorded; "
                "reconcile its provider resources before retrying."
            )
        return gettext(
            "This deployment's provider resources were created with a different provider token; "
            "reconcile them before retrying."
        )

    @staticmethod
    def _claim_deploy(
        deployment: NodeDeployment, expected_token: uuid.UUID | None, kind: str
    ) -> Result[tuple[OperationLease, str], str]:
        """Claim a pending row for the pipeline together with its provider, under both row locks."""
        from apps.infrastructure.models import CloudProvider  # noqa: PLC0415 -- Claim the current provider too.

        with transaction.atomic():
            claim = claim_operation(
                deployment.pk,
                from_states=("pending",),
                to_status="provisioning_node",
                kind=kind,
                expected_token=expected_token,
            )
            if claim.is_err():
                return Err(claim.unwrap_err())
            claimed_provider = CloudProvider.objects.select_for_update().get(pk=deployment.provider_id)
            if claimed_provider.provider_type != "hetzner":
                transaction.set_rollback(True)
                return Err(gettext("Provider image support changed before deployment claim; no VM was created."))
        return Ok((claim.unwrap(), claimed_provider.provider_type))

    @staticmethod
    def _ask_orderable(
        deployment: NodeDeployment, api_token: str, server_type: str
    ) -> tuple[Result[bool | None, str], CloudProviderGateway | None]:
        """Ask the provider now whether ``server_type`` can be ordered in the deployment's region.

        Uses its own client that fails fast (the SDK default is no timeout and five retries), and
        contains its own faults: callers run it before they hold any claim or audit context.
        """
        try:
            gateway = get_cloud_gateway(
                deployment.provider.provider_type,
                api_token,
                timeout=ORDERABLE_CHECK_TIMEOUT_SECONDS,
                max_retries=ORDERABLE_CHECK_MAX_RETRIES,
            )
            return gateway.server_type_orderable(server_type, deployment.region.provider_region_id), gateway
        except Exception as error:  # An unexpected fault refuses; it never escapes.
            return Err(str(error)), None

    def _check_orderable(self, deployment: NodeDeployment, credentials: dict[str, str]) -> Result[bool, str]:
        """Ask the provider, before the first write for a new server, whether its size is still sold in its region.

        The synced catalogue can be a day old, and Hetzner retires server types per location. A
        refusal queues a provider sync, which corrects the catalogue; this check never edits it.
        """
        api_token = credentials.get("api_token", "")
        if not api_token:
            return Ok(True)  # deploy_node fails on the missing token itself, before any provider call.
        server_type = deployment.node_size.provider_type_id
        location = deployment.region.provider_region_id
        orderable, gateway = self._ask_orderable(deployment, api_token, server_type)
        if orderable.is_err():
            return self._refuse_unorderable(
                deployment,
                f"Could not confirm that {server_type} can be ordered in {location}; "
                f"no server was created: {orderable.unwrap_err()}",
            )
        if orderable.unwrap() is not False or gateway is None:
            return Ok(True)
        # A server created before a crash, whose id was never stored, is adopted by create_server
        # through its deployment label. Refusing here would strand it.
        existing = gateway.find_deployment_server(str(deployment.correlation_id))
        if existing.is_err():
            return self._refuse_unorderable(
                deployment,
                f"{server_type} can no longer be ordered in {location}, and the check for a server already "
                f"created for this deployment failed; no server was created: {existing.unwrap_err()}",
            )
        if existing.unwrap():
            logger.info(
                f"✅ [Deployment:{deployment.hostname}] Server {existing.unwrap()} already exists for this "
                f"deployment; it is adopted although {server_type} is no longer sold in {location}"
            )
            return Ok(True)
        self._queue_catalogue_sync(deployment)
        return self._refuse_unorderable(
            deployment,
            f"{server_type} can no longer be ordered in {location}; no server was created. "
            "Choose another size; a provider sync has been queued to refresh the catalogue.",
        )

    def _check_resize_orderable(
        self, deployment: NodeDeployment, new_size: NodeSize, credentials: dict[str, str]
    ) -> Result[bool, str]:
        """Ask the provider, before a resize writes anything, whether the new size is still sold in the region."""
        api_token = credentials.get("api_token", "")
        if not api_token:
            return Ok(True)  # The resize command fails on the missing token itself.
        server_type = new_size.provider_type_id
        location = deployment.region.provider_region_id
        orderable, _gateway = self._ask_orderable(deployment, api_token, server_type)
        if orderable.is_err():
            return self._refuse_unorderable(
                deployment,
                f"Could not confirm that {server_type} can be ordered in {location}; "
                f"the node was not resized: {orderable.unwrap_err()}",
                phase="upgrading",
            )
        if orderable.unwrap() is False:
            self._queue_catalogue_sync(deployment)
            return self._refuse_unorderable(
                deployment,
                f"Size {server_type} is not available in {location}: the provider no longer sells it there, "
                "and the node was not resized. A provider sync has been queued to refresh the catalogue.",
                phase="upgrading",
            )
        return Ok(True)

    @staticmethod
    def _refuse_unorderable(deployment: NodeDeployment, message: str, phase: str = "init") -> Result[bool, str]:
        from apps.infrastructure.models import NodeDeploymentLog  # noqa: PLC0415  # Deferred: avoids circular import

        logger.warning(f"⚠️ [Deployment:{deployment.hostname}] {message}")
        NodeDeploymentLog.objects.create(deployment=deployment, level="ERROR", message=message, phase=phase)
        return Err(message)

    @staticmethod
    def _queue_catalogue_sync(deployment: NodeDeployment) -> None:
        from apps.infrastructure.tasks import (  # noqa: PLC0415  # Deferred: tasks imports this module
            queue_sync_providers,
        )

        try:
            queue_sync_providers()
        except Exception as error:  # The refusal stands without a sync; the daily sync corrects the catalogue.
            logger.warning(f"⚠️ [Deployment:{deployment.hostname}] Could not queue a provider sync: {error}")

    def deploy_node(  # Complexity: deployment orchestration  # noqa: C901, PLR0911, PLR0912, PLR0913, PLR0915  # Complexity: multi-step business logic; retry passes check_orderable
        self,
        deployment: NodeDeployment,
        credentials: dict[str, str],
        cloudflare_api_token: str | None = None,
        user: User | None = None,
        progress_callback: Callable[..., None] | None = None,
        expected_token: uuid.UUID | None = None,
        operation_kind: str = "deploy",
        check_orderable: bool = True,
    ) -> Result[DeploymentResult, str]:
        """
        Execute complete node deployment pipeline.

        Args:
            deployment: NodeDeployment instance to deploy
            credentials: Provider credentials dict (e.g., {"api_token": "xxx"})
            cloudflare_api_token: Cloudflare API token (optional)
            user: User performing the deployment
            progress_callback: Optional callback for progress updates
            expected_token: The token reserved at enqueue (or by the retry claim); only its holder starts
            operation_kind: "deploy", or "retry" when retry_deployment hands over its claim
            check_orderable: False when the caller (retry_deployment) already ran the orderable check

        Returns:
            Result with DeploymentResult or error
        """
        provider_result = self._deployment_preflight(deployment)
        if provider_result.is_err():
            return Err(provider_result.unwrap_err())
        fqdn_result = validate_deployment_fqdn(deployment.hostname, deployment.dns_zone)
        if fqdn_result.is_err():
            return Err(fqdn_result.unwrap_err())

        start_time = timezone.now()
        stages_completed: list[str] = []
        _cloud_result: ServerCreateResult | None = None  # unused; actual tracking via server_create_result
        ansible_results: list[AnsibleResult] = []
        # Track created cloud resources for cleanup on failure: (resource_type, resource_id)
        created_resources: list[tuple[str, str]] = []
        # gateway is captured here so the except block can access it for cleanup
        gateway: CloudProviderGateway | None = None
        # Created before the try so every failure path can audit with the caller's context.
        audit_ctx = InfrastructureAuditContext(user=user)
        lease: OperationLease | None = None

        def report_progress(stage: str) -> None:
            if progress_callback and stage in self.STAGES:
                pct, msg = self.STAGES[stage]
                progress_callback(DeploymentProgress(stage=stage, percentage=pct, message=msg))

        def log_deployment(level: str, message: str) -> None:
            """Log to both logger and deployment log"""
            from apps.infrastructure.models import (  # noqa: PLC0415  # Deferred: avoids circular import
                NodeDeploymentLog,  # Circular: cross-app  # Deferred: avoids circular import
            )

            getattr(logger, level)(f"[Deployment:{deployment.hostname}] {message}")
            NodeDeploymentLog.objects.create(
                deployment=deployment,
                level=level.upper(),
                message=message,
                phase=stages_completed[-1] if stages_completed else "init",
            )

        try:
            report_progress("init")
            log_deployment("info", "Starting node deployment")

            # Check if deployment is enabled
            if not SettingsService.get_setting("node_deployment.enabled", True):
                return Err("Node deployment is disabled in settings")

            # A new server will be created: confirm its size is still sold in its region before the
            # claim and before any vault or provider write. An existing VM is reused unchecked, and a
            # row the claim will refuse anyway is not checked.
            if check_orderable and not deployment.external_node_id and deployment.status == "pending":
                orderable_result = self._check_orderable(deployment, credentials)
                if orderable_result.is_err():
                    return Err(orderable_result.unwrap_err())

            # One locked claim: only a pending row starts, and a retry only with the token it reserved.
            claim = self._claim_deploy(deployment, expected_token, operation_kind)
            if claim.is_err():
                return Err(claim.unwrap_err())
            lease, claimed_provider_type = claim.unwrap()

            # Refresh local instance after the claim
            deployment.refresh_from_db()

            # Audit: deployment started
            try:
                InfrastructureAuditService.log_deployment_started(deployment, audit_ctx)
            except Exception:
                logger.warning(f"[Deployment:{deployment.hostname}] Failed to log audit: deployment started")

            # Validate DNS config presence BEFORE any paid/external resource is created, so a
            # missing token/zone fails before the VM (#347 GAP 3; codex C2). Runs after the
            # enabled + status guards. The zone-access + fqdn-containment check runs later in
            # _configure_dns (fail-closed + compensated).
            dns_config_result = self._resolve_dns_config(deployment, cloudflare_api_token)
            if dns_config_result.is_err():
                self._mark_failed(
                    deployment,
                    dns_config_result.unwrap_err(),
                    stage="provisioning_node",
                    audit_ctx=audit_ctx,
                    lease=lease,
                )
                return Err(dns_config_result.unwrap_err())
            dns_token, dns_zone_id = dns_config_result.unwrap()

            # Existing VMs still authorize their original deployment identity, and so does a stored vault
            # key: a server adopted by label after a lost create answer only accepts the first key.
            report_progress("ssh_key")
            reuse_key = bool(deployment.external_node_id or deployment.ssh_key_credential_id)
            log_deployment("info", "Reusing deployment SSH key" if reuse_key else "Generating deployment SSH key")

            key_result = (
                self._ssh_manager.get_deployment_key(deployment, user=user)
                if reuse_key
                else self._ssh_manager.generate_deployment_key(deployment, user=user)
            )

            if key_result.is_err():
                if reuse_key:
                    message = "Existing VM authentication key is unavailable; refusing to generate or replace it"
                    self._mark_failed(deployment, message, stage="ssh_key", audit_ctx=audit_ctx, lease=lease)
                    return Err(message)
                # Do not create a paid VM without a persisted authentication key.
                # An ambiguous key-generation mutation also retains UNKNOWN (#253/#254).
                message = "SSH key generation failed; no VM was created"
                self._mark_failed(deployment, message, stage="ssh_key", audit_ctx=audit_ctx, lease=lease)
                return Err(message, retriability=retriability_of(key_result))
            else:
                ssh_public_key = key_result.unwrap().public_key
                log_deployment("info", "Deployment SSH key ready")

            stages_completed.append("ssh_key")

            # Stage 2: Provision server via cloud provider gateway
            report_progress("provision_server")

            # Get API token from credentials
            api_token = credentials.get("api_token", "")
            if not api_token:
                self._mark_failed(
                    deployment, "No API token provided", stage="provision_server", audit_ctx=audit_ctx, lease=lease
                )
                return Err("No API token provided")

            # Retain the supported adapter selected under the claim, never a refreshed relation's type.
            provider_type = claimed_provider_type
            gateway = get_cloud_gateway(provider_type, api_token)

            # Only the token that created this row's resources can see them: under any other token a
            # "not found" proves nothing, and creating again could bill a second server elsewhere.
            provenance = self._provenance_refusal(deployment, api_token)
            if provenance:
                owned_update(lease, deployment, needs_reconciliation=True, reconciliation_reason=provenance)
                self._mark_failed(deployment, provenance, stage="provision_server", audit_ctx=audit_ctx, lease=lease)
                return Err(provenance)

            # Idempotent: skip server creation if external_node_id already set (retry scenario)
            server_create_result: ServerCreateResult | None = None
            server_from_create = False
            if deployment.external_node_id:
                log_deployment("info", f"Server already exists (id={deployment.external_node_id}), skipping creation")
                server_info_result = gateway.get_server(deployment.external_node_id)
                if server_info_result.is_err():
                    # Transient error — do NOT clear external_node_id
                    self._mark_failed(
                        deployment,
                        f"Cannot verify existing server: {server_info_result.unwrap_err()}",
                        stage="provision_server",
                        audit_ctx=audit_ctx,
                        lease=lease,
                    )
                    return Err(
                        f"Cannot verify existing server: {server_info_result.unwrap_err()}",
                        retriability=retriability_of(server_info_result),
                    )
                elif server_info_result.unwrap() is not None:
                    info = server_info_result.unwrap()
                    assert info is not None  # narrowed by elif above
                    server_create_result = ServerCreateResult(
                        server_id=info.server_id,
                        ipv4_address=info.ipv4_address,
                        ipv6_address=info.ipv6_address,
                    )
                else:
                    log_deployment("warning", "Previously created server not found, creating new one")
                    owned_update(lease, deployment, external_node_id="")
                    # The pre-claim check was skipped for the stored server; a replacement is new.
                    orderable_result = self._check_orderable(deployment, credentials)
                    if orderable_result.is_err():
                        self._mark_failed(
                            deployment,
                            orderable_result.unwrap_err(),
                            stage="provision_server",
                            audit_ctx=audit_ctx,
                            lease=lease,
                        )
                        return Err(orderable_result.unwrap_err())

            if not deployment.external_node_id:
                log_deployment("info", f"Creating server via {provider_type} API")

                # Record the intent and the token's provenance before the first provider write, so a
                # worker that dies mid-create leaves a row that teardown knows to reconcile. An earlier
                # "unknown" outcome is never downgraded: that server may still exist.
                prior_create_state = deployment.server_create_state
                owned_update(
                    lease,
                    deployment,
                    server_create_state="intent",
                    provider_token_fingerprint=provider_token_fingerprint(api_token),
                )

                def settle_create_state(state: str) -> None:
                    # "none" never overwrites history: a server that existed (created) or may have
                    # (unknown, intent) keeps the row out of never_got_a_server for good.
                    keep = prior_create_state != "none" and state == "none"
                    owned_update(lease, deployment, server_create_state=prior_create_state if keep else state)

                # Upload SSH key to provider, labelled so teardown finds it and no other owner's key is touched
                # Named per attempt: a re-deploy keeps the hostname, and a key or firewall left under an
                # older attempt's name (or an unlabelled legacy key) can never collide with this one.
                attempt = str(deployment.correlation_id)[:8]
                ssh_key_name = f"praho-{deployment.hostname}-{attempt}"
                key_upload_result = gateway.upload_owned_ssh_key(
                    ssh_key_name,
                    ssh_public_key,
                    {"managed-by": "praho", "praho-deployment": str(deployment.correlation_id)},
                )
                if key_upload_result.is_err():
                    settle_create_state("none")
                    if gateway is not None and created_resources:
                        self._cleanup_resources(gateway, created_resources, deployment, lease=lease)
                    self._mark_failed(
                        deployment,
                        f"SSH key upload failed: {key_upload_result.unwrap_err()}",
                        stage="provision_server",
                        lease=lease,
                    )
                    return Err(
                        f"SSH key upload failed: {key_upload_result.unwrap_err()}",
                        retriability=retriability_of(key_upload_result),
                    )

                created_resources.append(("ssh_key", ssh_key_name))
                log_deployment("info", f"SSH key '{ssh_key_name}' uploaded to provider")

                # Create firewall before server — attach during provisioning
                firewall_name = f"praho-fw-{deployment.hostname}-{attempt}"
                log_deployment("info", f"Creating firewall '{firewall_name}'")
                firewall_result = gateway.create_firewall(
                    name=firewall_name,
                    rules=self._node_firewall_rules(),
                    labels={
                        "managed-by": "praho",
                        "deployment-id": str(deployment.correlation_id),
                        "hostname": deployment.hostname,
                    },
                )
                if firewall_result.is_err():
                    settle_create_state("none")
                    if gateway is not None and created_resources:
                        self._cleanup_resources(gateway, created_resources, deployment, lease=lease)
                    self._mark_failed(
                        deployment,
                        f"Firewall creation failed: {firewall_result.unwrap_err()}",
                        stage="provision_server",
                        lease=lease,
                    )
                    return Err(
                        f"Firewall creation failed: {firewall_result.unwrap_err()}",
                        retriability=retriability_of(firewall_result),
                    )

                firewall_id = firewall_result.unwrap()
                created_resources.append(("firewall", firewall_id))
                log_deployment("info", f"Firewall '{firewall_name}' created (id={firewall_id})")
                # Persist firewall_id in a structured log entry so destroy_node can retrieve it by ID
                from apps.infrastructure.models import (  # noqa: PLC0415  # Deferred: avoids circular import
                    NodeDeploymentLog,  # Circular: cross-app  # Deferred: avoids circular import
                )

                NodeDeploymentLog.objects.create(
                    deployment=deployment,
                    level="INFO",
                    message=f"Firewall resource recorded: {firewall_name}",
                    phase="provision_server",
                    details={"firewall_id": firewall_id, "firewall_name": firewall_name},
                )

                # Create the server via gateway
                create_request = ServerCreateRequest(
                    name=deployment.hostname,
                    server_type=deployment.node_size.provider_type_id if deployment.node_size else "",
                    location=deployment.region.provider_region_id if deployment.region else "",
                    ssh_keys=[ssh_key_name],
                    firewall_ids=[firewall_id],
                    labels={
                        "managed-by": "praho",
                        "praho-deployment": str(deployment.correlation_id),
                        "hostname": deployment.hostname,
                        "environment": deployment.environment,
                    },
                )
                server_result = gateway.create_server(create_request)

                if server_result.is_err():
                    # Only a provable refusal means no server; any other outcome may be billed.
                    refused = retriability_of(server_result) is Retriability.NOT_RETRIABLE
                    settle_create_state("none" if refused else "unknown")
                    if gateway is not None and created_resources:
                        self._cleanup_resources(gateway, created_resources, deployment, lease=lease)
                    self._mark_failed(
                        deployment,
                        f"Server creation failed: {server_result.unwrap_err()}",
                        stage="provision_server",
                        lease=lease,
                    )
                    return Err(
                        f"Server creation failed: {server_result.unwrap_err()}",
                        retriability=retriability_of(server_result),
                    )

                server_create_result = server_result.unwrap()
                server_from_create = True  # new, or adopted before it was ever enrolled
                if server_create_result.adopted:
                    # An adopted server holds this deployment's earlier work, and its firewall is attached
                    # to it: a later failure of this attempt fails the row with both kept, for retry or
                    # teardown, and deletes neither.
                    created_resources[:] = [r for r in created_resources if r[0] != "firewall"]
                else:
                    created_resources.append(("server", server_create_result.server_id))
                # Persist the id at once: a worker that dies before the next stage leaves a known server.
                owned_update(
                    lease,
                    deployment,
                    external_node_id=server_create_result.server_id,
                    server_create_state="created",
                    # Costs run from the first server this attempt created; a re-deploy resets it.
                    started_at=deployment.started_at or timezone.now(),
                )
            stages_completed.append("provision_server")
            log_deployment("info", f"Server created successfully via {provider_type} gateway")

            # Stage 3: Update deployment with server details
            report_progress("update_deployment")

            if not server_create_result or not server_create_result.ipv4_address:
                if gateway is not None and created_resources:
                    self._cleanup_resources(gateway, created_resources, deployment, lease=lease)
                self._mark_failed(
                    deployment, "Server creation did not return an IP address", stage="update_deployment", lease=lease
                )
                return Err("Server creation did not return an IP address")

            identity: dict[str, Any] = {}
            if server_from_create:
                # Fresh provider images retain their bootstrap listener; None is the explicit
                # first-enrollment marker, never set by a retry.
                identity = {"ssh_port": 22, "ssh_host_keys": None}
            owned_transition(
                lease,
                deployment,
                "configuring_dns",
                external_node_id=server_create_result.server_id,
                ipv4_address=server_create_result.ipv4_address,
                ipv6_address=server_create_result.ipv6_address or "",
                **identity,
            )

            stages_completed.append("update_deployment")
            log_deployment("info", f"Server provisioned with IP: {deployment.ipv4_address}")

            # Stage: configure the node's own DNS (A/AAAA) before panel install. Fail closed —
            # a leaked record on a released IP is a subdomain-takeover risk (#347 GAP 3). The
            # HTTP call runs OUTSIDE the atomic block above (no row lock held across the network).
            report_progress("configuring_dns")
            dns_result = self._configure_dns(deployment, dns_token, dns_zone_id, log_deployment, lease)
            if dns_result.is_err():
                if gateway is not None and created_resources:
                    self._cleanup_resources(gateway, created_resources, deployment, lease=lease)
                self._mark_failed(
                    deployment, dns_result.unwrap_err(), stage="configuring_dns", audit_ctx=audit_ctx, lease=lease
                )
                return Err(dns_result.unwrap_err())
            stages_completed.append("configuring_dns")

            # Transition to panel installation phase
            owned_transition(lease, deployment, "installing_panel")

            # Stage 7-10: Run Ansible playbooks (panel-aware)
            panel_type = "virtualmin"
            if hasattr(deployment, "panel_type") and deployment.panel_type:
                panel_type = (
                    deployment.panel_type.panel_type
                    if hasattr(deployment.panel_type, "panel_type")
                    else str(deployment.panel_type)
                )

            # #347: resolve the dedicated Virtualmin API credential BEFORE the Ansible stages so the
            # panel playbook can provision it ON the node (create the ACL user with this password).
            # register_node stores it in the vault, so the first API call — and verify_and_activate
            # below — authenticate. Threaded via a 0600 vars file, never the ansible command line.
            #
            # #348 finding #8: REUSE an existing vault credential for this node; the vault is the
            # credential source of truth (ADR-0033). The node playbook's API-user helper
            # (praho-webmin-api-user) sets the password it is given on every run, also for an
            # existing user, so the node converges to whatever password is passed here. That also
            # covers a prior deploy that created the user but failed before the vault store: the
            # fresh password generated below replaces the node's on the re-deploy.
            from apps.common.credential_vault import (  # noqa: PLC0415  # Deferred: avoids circular import
                get_credential_vault,
            )

            virtualmin_api_username = "praho-api"
            # The vault key MUST stay aligned with register_node (service_identifier=server.hostname)
            # and verify_and_activate (reads by server.hostname). server.hostname is assigned
            # =deployment.fqdn at registration, so this read key matches; keep them coupled to the same
            # attribute if hostname derivation ever changes, or reuse silently never hits (fresh pw
            # every re-deploy -> permanent 401/disabled).
            _existing_cred = get_credential_vault().get_credential(
                service_type="virtualmin",
                service_identifier=deployment.fqdn,
                reason=f"Node deploy credential resolution for {deployment.hostname} (#348)",
            )
            if _existing_cred.is_ok() and _existing_cred.unwrap()[0] and _existing_cred.unwrap()[1]:
                virtualmin_api_username, virtualmin_api_password, _ = _existing_cred.unwrap()
                log_deployment("info", "Reusing existing Virtualmin API credential from the vault (re-deploy)")
            else:
                import string  # noqa: PLC0415  # Deferred: stdlib, local use

                virtualmin_api_password = "".join(
                    secrets.choice(string.ascii_letters + string.digits + "!@#$%^&*") for _ in range(24)
                )
                # Stored before the panel install sets it on the node, so a registration that fails
                # later can resume without reinstalling the panel (the only other way to learn it).
                stored = self._store_api_credential(deployment, virtualmin_api_username, virtualmin_api_password, user)
                if stored.is_err():
                    if gateway is not None and created_resources:
                        self._cleanup_resources(gateway, created_resources, deployment, lease=lease)
                    self._mark_failed(deployment, stored.unwrap_err(), stage="ansible_panel", lease=lease)
                    return Err(stored.unwrap_err())

            playbook_names = self._ansible.get_playbook_order(panel_type)
            stage_keys = ["ansible_base", "ansible_panel", "ansible_harden", "ansible_backup"]
            ansible_playbooks = list(zip(stage_keys, playbook_names, strict=False))

            for stage_name, playbook in ansible_playbooks:
                report_progress(stage_name)
                log_deployment("info", f"Running Ansible playbook: {playbook}")

                # Only the panel playbook (virtualmin.yml, the "ansible_panel" stage) provisions the
                # ACL user, so scope the API credential to that stage. Broadcasting it to base/harden/
                # backup would write the secret into a 0600 vars file for each and expose it to every
                # task/callback in playbooks that never use it (#348 finding #6).
                stage_extra_vars = (
                    {
                        "praho_api_user": virtualmin_api_username,
                        "praho_api_password": virtualmin_api_password,
                    }
                    if stage_name == "ansible_panel"
                    else None
                )

                playbook_result = self._ansible.run_playbook(
                    deployment=deployment,
                    playbook=playbook,
                    extra_vars=stage_extra_vars,
                    operator_public_keys=provider_result.unwrap(),
                )

                if playbook_result.is_err():
                    if gateway is not None and created_resources:
                        self._cleanup_resources(gateway, created_resources, deployment, lease=lease)
                    self._mark_failed(
                        deployment,
                        f"Ansible {playbook} failed: {playbook_result.unwrap_err()}",
                        stage=stage_name,
                        lease=lease,
                    )
                    return Err(
                        f"Ansible {playbook} failed: {playbook_result.unwrap_err()}",
                        retriability=retriability_of(playbook_result),
                    )

                result = playbook_result.unwrap()
                ansible_results.append(result)

                if not result.success:
                    if gateway is not None and created_resources:
                        self._cleanup_resources(gateway, created_resources, deployment, lease=lease)
                    self._mark_failed(
                        deployment, f"Ansible {playbook} failed: {result.stderr[:500]}", stage=stage_name, lease=lease
                    )
                    return Err(f"Ansible {playbook} failed: {result.stderr[:500]}")

                stages_completed.append(stage_name)
                log_deployment("info", f"Ansible {playbook} completed successfully")
                # Heartbeat: the four playbooks can legally run up to ~2h with no
                # status transition; touch updated_at after each so
                # recover_stuck_deployments_task never reaps a live deployment
                # mid-stage. Owned: a worker that recovery reclaimed stops here.
                owned_update(lease, deployment)

            # The FSM requires installing_panel -> configuring_backups -> validating;
            # the backup configuration is part of the ansible_backup playbook above,
            # so record the state transition once here before validating (without it
            # transition_to('validating') raises and every deployment fails at the
            # very end after all paid provisioning work).
            owned_transition(lease, deployment, "configuring_backups")

            # Stage 11: Validation
            report_progress("validation")
            owned_transition(lease, deployment, "validating")
            log_deployment("info", "Validating node health")

            validation_result = self._validation.validate_node(deployment)

            if validation_result.is_err():
                if gateway is not None and created_resources:
                    self._cleanup_resources(gateway, created_resources, deployment, lease=lease)
                self._mark_failed(
                    deployment,
                    f"Validation failed: {validation_result.unwrap_err()}",
                    stage="validation",
                    lease=lease,
                )
                return Err(
                    f"Validation failed: {validation_result.unwrap_err()}",
                    retriability=retriability_of(validation_result),
                )

            validation_report = validation_result.unwrap()

            if not validation_report.all_passed:
                # Warning but continue - some checks might fail initially
                log_deployment("warning", f"Validation: {validation_report.summary}")
            else:
                log_deployment("info", f"Validation passed: {validation_report.summary}")

            stages_completed.append("validation")

            # Stage 12: Registration
            report_progress("registration")
            owned_transition(lease, deployment, "registering")
            log_deployment("info", "Registering node as VirtualminServer")

            # From here the node is provisioned and installed: a failure keeps it (no compensation),
            # and Retry resumes registration alone.
            owned_update(lease, deployment, registration_state="started")
            registration_result = self._registration.register_node(
                deployment=deployment,
                admin_username=virtualmin_api_username,
                admin_password=virtualmin_api_password,
                user=user,
            )

            if registration_result.is_err():
                message = f"Registration failed: {registration_result.unwrap_err()}"
                self._mark_failed(deployment, message, stage="registration", audit_ctx=audit_ctx, lease=lease)
                return Err(message, retriability=retriability_of(registration_result))
            server = registration_result.unwrap()
            virtualmin_server_id = server.id
            owned_update(lease, deployment, registration_state="registered")
            log_deployment("info", f"Registered as VirtualminServer(id={server.id})")
            self._activate_registered(deployment, lease, server, log_deployment)

            stages_completed.append("registration")

            # Stage 13: Complete
            report_progress("complete")
            owned_transition(lease, deployment, "completed", release=True, completed_at=timezone.now())

            stages_completed.append("complete")

            duration = (timezone.now() - start_time).total_seconds()
            log_deployment("info", f"Deployment completed successfully in {duration:.1f}s")

            # Audit: deployment completed
            try:
                InfrastructureAuditService.log_deployment_completed(
                    deployment,
                    audit_ctx,
                    duration_seconds=duration,
                )
            except Exception:
                logger.warning(f"[Deployment:{deployment.hostname}] Failed to log audit: deployment completed")

            return Ok(
                DeploymentResult(
                    success=True,
                    deployment_id=deployment.id,
                    hostname=deployment.hostname,
                    stages_completed=stages_completed,
                    cloud_result=server_create_result,
                    ansible_results=ansible_results,
                    validation_report=validation_report,
                    virtualmin_server_id=virtualmin_server_id,
                    duration_seconds=duration,
                )
            )

        except OperationOwnershipLostError as lost:
            # Another owner (recovery, or a newer claim) holds the row: write nothing, delete nothing.
            logger.warning(f"⚠️ [Deployment:{deployment.hostname}] Stopped without writing: {lost}")
            return Err(f"Deployment stopped: {lost}")
        except Exception as e:
            logger.exception(f"Deployment failed for {deployment.hostname}: {e}")
            # Best-effort cleanup of cloud resources created before the failure; once registration has
            # started the node is installed and kept, for Retry to resume registration alone.
            if gateway is not None and created_resources and deployment.registration_state == "none":
                self._cleanup_resources(gateway, created_resources, deployment, lease=lease)
            self._mark_failed(deployment, str(e), audit_ctx=audit_ctx, lease=lease)

            duration = (timezone.now() - start_time).total_seconds()
            return Err(f"Deployment failed: {e}")

    def destroy_node(
        self,
        deployment: NodeDeployment,
        credentials: dict[str, str],
        cloudflare_api_token: str | None = None,
        user: User | None = None,
        expected_token: uuid.UUID | None = None,
    ) -> Result[bool, str]:
        """
        Destroy a deployed node through the shared teardown.

        The claim and the workload guard decide together: an occupied node, or a row in another
        status, is refused with nothing changed. A teardown that stops part-way stays ``destroying``
        with every unproven identifier kept, for the stale-destroying sweep to resume.

        Args:
            deployment: NodeDeployment instance to destroy
            credentials: Provider credentials dict
            cloudflare_api_token: Unused; DNS teardown reads the stored zone and the configured token
            user: User performing the destruction
            expected_token: The token reserved at enqueue; a task holding an older one is refused

        Returns:
            Result with success status or error
        """
        logger.info(f"[Destroy:{deployment.hostname}] Starting node destruction")
        audit_ctx = InfrastructureAuditContext(user=user)

        claim = claim_teardown(
            deployment, kind="destroy", from_states=DESTROYABLE_STATES, expected_token=expected_token
        )
        if claim.is_err():
            return record_destroy_failure(deployment, f"Destroy refused: {claim.unwrap_err()}", audit_ctx)
        lease = claim.unwrap()
        deployment.refresh_from_db()
        return run_claimed_teardown(
            deployment,
            lease,
            credentials.get("api_token", ""),
            ssh_manager=self._ssh_manager,
            registration=self._registration,
            user=user,
            audit_ctx=audit_ctx,
        )

    def retry_deployment(  # noqa: PLR0911  # One refusal per pre-claim check
        self,
        deployment: NodeDeployment,
        credentials: dict[str, str],
        cloudflare_api_token: str | None = None,
        user: User | None = None,
        expected_token: uuid.UUID | None = None,
    ) -> Result[DeploymentResult, str]:
        """
        Retry a failed deployment.

        Args:
            deployment: Failed NodeDeployment instance
            credentials: Provider credentials dict
            cloudflare_api_token: Cloudflare API token
            user: User performing the retry
            expected_token: The token reserved at enqueue; a task holding an older one is refused

        Returns:
            Result with DeploymentResult or error
        """
        provider_result = self._deployment_preflight(deployment)
        if provider_result.is_err():
            return Err(provider_result.unwrap_err())
        if deployment.status != "failed":
            return Err(f"Can only retry failed deployments, current status: {deployment.status}")

        fqdn_result = validate_deployment_fqdn(deployment.hostname, deployment.dns_zone)
        if fqdn_result.is_err():
            return Err(fqdn_result.unwrap_err())
        # A refused size is not an attempt: check before counting it, and only once. A row resuming its
        # registration creates no server, so it is never asked.
        if not deployment.external_node_id and deployment.registration_state == "none":
            orderable_result = self._check_orderable(deployment, credentials)
            if orderable_result.is_err():
                return Err(orderable_result.unwrap_err())

        # One locked claim: failed -> pending, the attempt counted in the same statement. A second retry
        # of the same row finds it no longer failed and runs nothing.
        claim = claim_operation(
            deployment.pk,
            from_states=("failed",),
            to_status="pending",
            kind="retry",
            increment_retry=True,
            require_reconciled=True,
            expected_token=expected_token,
        )
        if claim.is_err():
            return Err(claim.unwrap_err())
        lease = claim.unwrap()
        deployment.refresh_from_db()

        logger.info(f"[Retry:{deployment.hostname}] Retrying deployment (attempt {deployment.retry_count})")
        if deployment.registration_state != "none":
            # Provisioning, DNS and the panel install already succeeded: never run them again.
            return self._resume_registration(deployment, lease, user)

        # Audit: deployment retry
        try:
            InfrastructureAuditService.log_deployment_retry(
                deployment,
                InfrastructureAuditContext(user=user),
            )
        except Exception:
            logger.warning(f"[Retry:{deployment.hostname}] Failed to log audit: deployment retry")

        result = self.deploy_node(
            deployment=deployment,
            credentials=credentials,
            cloudflare_api_token=cloudflare_api_token,
            user=user,
            expected_token=lease.token,
            operation_kind="retry",
            check_orderable=False,
        )
        self._settle_refused_start(deployment, lease, result, "Retry")
        return result

    @staticmethod
    def _settle_refused_start(
        deployment: NodeDeployment, lease: OperationLease, result: Result[DeploymentResult, str], what: str
    ) -> None:
        """A pipeline refused before its claim leaves the row pending under ``lease``: fail it there.

        Once the pipeline claimed the row, the pipeline settled it and the lease no longer owns it.
        """
        if result.is_ok():
            return
        deployment.refresh_from_db()
        with contextlib.suppress(OperationOwnershipLostError, ValidationError):
            owned_transition(lease, deployment, "failed", f"{what} did not start: {result.unwrap_err()}", release=True)

    @staticmethod
    def _redeploy_refusal(deployment: NodeDeployment, new_size: NodeSize) -> str:  # noqa: PLR0911  # One per guard.
        """Why this row cannot be re-deployed with this size, or "" when it can."""
        from apps.infrastructure.models import (  # noqa: PLC0415  # Deferred: avoids circular import
            DriftRemediationRequest,
            NodeDeploymentLog,
        )
        from apps.provisioning.virtualmin_models import VirtualminServer  # noqa: PLC0415  # Circular: app registry

        if deployment.status not in ("failed", "destroyed"):
            return f"Can only re-deploy a failed or destroyed deployment, not '{deployment.status}'"
        if deployment.needs_reconciliation:
            return f"Reconcile the deployment first: {deployment.reconciliation_reason}"
        if not deployment.never_got_a_server:
            return "This deployment had a server; re-deploying it needs costs that track separate server lifetimes"
        if deployment.external_node_id or deployment.dns_record_ids or deployment.virtualmin_server_id:
            return "The deployment still holds a server id, DNS records or a registered node; destroy it first"
        reached_provider = (
            bool(deployment.provider_token_fingerprint)
            or NodeDeploymentLog.objects.filter(
                deployment=deployment, message__startswith="Firewall resource recorded:"
            ).exists()
        )
        if deployment.status == "failed" and reached_provider:
            return "This failed deployment reached the provider; destroy it before re-deploying"
        if not new_size.is_active or new_size.provider_id != deployment.provider_id:
            return "The new size must be an active size from the deployment's provider"
        if not new_size.is_offered_in(deployment.region):
            return f"Size {new_size.provider_type_id} is not available in {deployment.region.provider_region_id}"
        if VirtualminServer.objects.filter(hostname=deployment.fqdn).exists():
            return f"A Virtualmin node is already registered as {deployment.fqdn}"
        open_statuses = DriftRemediationRequest.OPEN_STATUSES
        if DriftRemediationRequest.objects.filter(deployment=deployment, status__in=open_statuses).exists():
            return "A drift remediation is open for this deployment"
        return ""

    def redeploy_node(  # noqa: PLR0911  # One refusal per pre-claim check
        self,
        deployment: NodeDeployment,
        new_size: NodeSize,
        credentials: dict[str, str],
        user: User | None = None,
        expected_token: uuid.UUID | None = None,
    ) -> Result[DeploymentResult, str]:
        """Deploy a failed or destroyed deployment again, keeping its hostname, with ``new_size``.

        Only a row that never got a server qualifies. The hostname, number, logs, audit and costs stay;
        everything that described the old attempt is reset, and the correlation id is rotated so nothing
        left under the old labels can be adopted. Needs the destroy permission.
        """
        from apps.infrastructure.models import NodeDeployment as Model  # noqa: PLC0415  # Deferred: circular import
        from apps.infrastructure.permissions import can_destroy_nodes  # noqa: PLC0415  # Deferred import

        if user is None or not can_destroy_nodes(user):
            return Err(gettext("Re-deploying a node needs the destroy permission."))
        provider_result = self._deployment_preflight(deployment)
        if provider_result.is_err():
            return Err(provider_result.unwrap_err())
        fqdn_result = validate_deployment_fqdn(deployment.hostname, deployment.dns_zone)
        if fqdn_result.is_err():
            return Err(fqdn_result.unwrap_err())
        refusal = self._redeploy_refusal(deployment, new_size)
        if refusal:
            return Err(refusal)
        # The new size must still be sold here: ask before the claim, as a first deploy does.
        old_size = deployment.node_size
        deployment.node_size = new_size
        orderable_result = self._check_orderable(deployment, credentials)
        deployment.node_size = old_size
        if orderable_result.is_err():
            return Err(orderable_result.unwrap_err())

        from_status = deployment.status
        with transaction.atomic():
            # Every guard again on the locked row, then the claim in the same transaction.
            locked = Model.objects.select_for_update().get(pk=deployment.pk)
            refusal = self._redeploy_refusal(locked, new_size)
            if refusal:
                return Err(refusal)
            claim = claim_operation(
                deployment.pk,
                from_states=("failed", "destroyed"),
                to_status="pending",
                kind="redeploy",
                increment_retry=True,
                require_reconciled=True,
                expected_token=expected_token,
            )
            if claim.is_err():
                return Err(claim.unwrap_err())
            lease = claim.unwrap()
            locked.refresh_from_db()
            locked.node_size = new_size
            locked.set_max_domains_from_size()
            owned_update(
                lease,
                locked,
                node_size=new_size,
                max_domains=locked.max_domains,
                correlation_id=uuid.uuid4(),
                external_node_id="",
                ipv4_address=None,
                ipv6_address=None,
                ssh_port=22,
                ssh_host_keys=None,
                ssh_key_credential_id="",
                started_at=None,
                completed_at=None,
                destroyed_at=None,
                status_message="",
                server_create_state="none",
                provider_token_fingerprint="",
                registration_state="none",
                dns_record_ids=[],
            )
        deployment.refresh_from_db()
        logger.info(f"🚀 [Redeploy:{deployment.hostname}] Re-deploying with {new_size.provider_type_id}")
        try:
            InfrastructureAuditService.log_deployment_retry(
                deployment,
                InfrastructureAuditContext(
                    user=user,
                    metadata={
                        "mode": "redeploy",
                        "old_size": old_size.provider_type_id,
                        "new_size": new_size.provider_type_id,
                        "from_status": from_status,
                    },
                ),
            )
        except Exception:
            logger.warning(f"[Redeploy:{deployment.hostname}] Failed to log audit: re-deploy")

        result = self.deploy_node(
            deployment=deployment,
            credentials=credentials,
            user=user,
            expected_token=lease.token,
            operation_kind="redeploy",
            check_orderable=False,
        )
        self._settle_refused_start(deployment, lease, result, "Re-deploy")
        return result

    @staticmethod
    def _store_api_credential(
        deployment: NodeDeployment, username: str, password: str, user: User | None
    ) -> Result[None, str]:
        """Store the node's Virtualmin API credential under the key registration and activation read."""
        from apps.common.credential_vault import CredentialData, get_credential_vault  # noqa: PLC0415  # Circular

        stored = get_credential_vault().store_credential(
            CredentialData(
                service_type="virtualmin",
                service_identifier=deployment.fqdn,
                username=username,
                password=password,
                metadata={"deployment_id": str(deployment.id), "pending_registration": True},
                expires_in_days=365,
                user=user,
                reason=f"Node deploy API credential for {deployment.hostname}, before the panel install",
            )
        )
        if stored.is_err():
            return Err(f"Could not store the Virtualmin API credential: {stored.unwrap_err()}")
        return Ok(None)

    def _activate_registered(
        self,
        deployment: NodeDeployment,
        lease: OperationLease,
        server: Any,
        log: Callable[[str, str], None],
    ) -> None:
        """Best-effort activation of a registered node; records "activated" only when it succeeds.

        #347: confirm the credential the playbook provisioned actually authenticates, then activate. A
        failed or raised check leaves the server 'disabled' (safe, never customer-routed) and never fails
        an otherwise-complete deployment (#348 finding #7).
        """
        try:
            activation = self._registration.verify_and_activate(server)
        except Exception as activation_err:  # best-effort: activation must never be fatal to the deploy
            log("warning", f"Node registered but activation raised (left disabled): {activation_err}")
            return
        if activation.is_ok():
            owned_update(lease, deployment, registration_state="activated")
            log("info", f"VirtualminServer(id={server.id}) credential-verified and activated")
        else:
            log("warning", f"Node registered but left disabled: {activation.unwrap_err()}")

    def _resume_registration(
        self, deployment: NodeDeployment, lease: OperationLease, user: User | None
    ) -> Result[DeploymentResult, str]:
        """Finish a node whose provisioning, DNS and panel install succeeded: register, activate, complete.

        Never calls the provider, DNS or Ansible. An unregistered node registers with the API credential
        stored before its panel install; without it, resuming would need the panel reinstalled, so the
        row fails closed.
        """
        from apps.common.credential_vault import get_credential_vault  # noqa: PLC0415  # Circular
        from apps.infrastructure.models import NodeDeploymentLog  # noqa: PLC0415  # Deferred: avoids circular import

        audit_ctx = InfrastructureAuditContext(user=user)
        start_time = timezone.now()

        def log(level: str, message: str) -> None:
            getattr(logger, level)(f"[Deployment:{deployment.hostname}] {message}")
            NodeDeploymentLog.objects.create(
                deployment=deployment, level=level.upper(), message=message, phase="registration"
            )

        try:
            owned_transition(lease, deployment, "registering", "Resuming registration")
            server = deployment.virtualmin_server
            if server is None:
                credential = get_credential_vault().get_credential(
                    service_type="virtualmin",
                    service_identifier=deployment.fqdn,
                    reason=f"Registration resume for {deployment.hostname}",
                )
                if credential.is_err() or not all(credential.unwrap()[:2]):
                    message = gettext(
                        "The node's Virtualmin API credential is not stored; registration cannot resume "
                        "without reinstalling the panel."
                    )
                    self._mark_failed(deployment, message, stage="registration", audit_ctx=audit_ctx, lease=lease)
                    return Err(message)
                username, password, _metadata = credential.unwrap()
                owned_update(lease, deployment, registration_state="started")
                registered = self._registration.register_node(
                    deployment=deployment, admin_username=username, admin_password=password, user=user
                )
                if registered.is_err():
                    message = f"Registration failed: {registered.unwrap_err()}"
                    self._mark_failed(deployment, message, stage="registration", audit_ctx=audit_ctx, lease=lease)
                    return Err(message, retriability=retriability_of(registered))
                server = registered.unwrap()
                owned_update(lease, deployment, registration_state="registered")
                log("info", f"Registered as VirtualminServer(id={server.id})")
            if deployment.registration_state != "activated":
                self._activate_registered(deployment, lease, server, log)
            owned_transition(lease, deployment, "completed", release=True, completed_at=timezone.now())
        except OperationOwnershipLostError as lost:
            logger.warning(f"⚠️ [Deployment:{deployment.hostname}] Resume stopped without writing: {lost}")
            return Err(f"Registration resume stopped: {lost}")
        except Exception as e:
            logger.exception(f"Registration resume failed for {deployment.hostname}: {e}")
            self._mark_failed(deployment, f"Registration resume failed: {e}", stage="registration", lease=lease)
            return Err(f"Registration resume failed: {e}")

        duration = (timezone.now() - start_time).total_seconds()
        log("info", f"Registration resumed and deployment completed in {duration:.1f}s")
        try:
            InfrastructureAuditService.log_deployment_completed(deployment, audit_ctx, duration_seconds=duration)
        except Exception:
            logger.warning(f"[Deployment:{deployment.hostname}] Failed to log audit: deployment completed")
        return Ok(
            DeploymentResult(
                success=True,
                deployment_id=deployment.id,
                hostname=deployment.hostname,
                stages_completed=["registration", "complete"],
                virtualmin_server_id=server.id,
                duration_seconds=duration,
            )
        )

    @staticmethod
    def _upgrade_refusal(deployment: NodeDeployment, new_size: NodeSize) -> str:
        """Why the node cannot be resized to this size, or "" when it can.

        The upgrade view, the upgrade task and the manage_node command all resize through here.
        """
        if deployment.status != "completed":
            return f"Can only upgrade completed deployments, current status: {deployment.status}"
        if deployment.node_size == new_size:
            return "Node is already using the selected size"
        if new_size.provider != deployment.provider:
            return "New size must be from the same provider"
        if not new_size.is_offered_in(deployment.region):
            return f"Size {new_size.provider_type_id} is not available in {deployment.region.provider_region_id}"
        return ""

    def upgrade_node_size(  # Complexity: deployment orchestration
        self,
        deployment: NodeDeployment,
        new_size: NodeSize,
        credentials: dict[str, str],
        user: User | None = None,
    ) -> Result[bool, str]:
        """
        Upgrade a node to a new size (resize VPS).

        Args:
            deployment: NodeDeployment instance to upgrade
            new_size: New NodeSize to resize to
            credentials: Provider credentials dict
            user: User performing the upgrade

        Returns:
            Result with success status or error
        """
        from apps.infrastructure.models import (  # noqa: PLC0415  # Deferred: avoids circular import
            NodeDeploymentLog,  # Circular: cross-app  # Deferred: avoids circular import
        )

        logger.info(f"[Upgrade:{deployment.hostname}] Starting node resize to {new_size.name}")

        refusal = self._upgrade_refusal(deployment, new_size)
        if refusal:
            return Err(refusal)
        # The catalogue can be a day old: ask the provider before anything is written or resized.
        orderable_result = self._check_resize_orderable(deployment, new_size, credentials)
        if orderable_result.is_err():
            return Err(orderable_result.unwrap_err())

        old_size = deployment.node_size
        audit_ctx = InfrastructureAuditContext(user=user)

        try:
            # Log the upgrade start
            NodeDeploymentLog.objects.create(
                deployment=deployment,
                level="INFO",
                message=f"Starting upgrade from {old_size.name} to {new_size.name}",
                phase="upgrading",
            )

            # Audit: upgrade started
            try:
                InfrastructureAuditService.log_node_upgrade_started(deployment, old_size, new_size, audit_ctx)
            except Exception:
                logger.warning(f"[Upgrade:{deployment.hostname}] Failed to log audit: upgrade started")

            # Use provider-agnostic command execution
            provider_type = deployment.provider.provider_type
            result = run_provider_command(
                provider_type=provider_type,
                operation="resize",
                credentials=credentials,
                timeout=300,
                server_id=str(deployment.external_node_id),
                size=new_size.provider_type_id,
            )

            if result.is_err():
                error_msg = f"Resize failed: {result.unwrap_err()}"
                NodeDeploymentLog.objects.create(
                    deployment=deployment,
                    level="ERROR",
                    message=error_msg,
                    phase="upgrading",
                )
                try:
                    InfrastructureAuditService.log_node_upgrade_failed(deployment, error_msg, audit_ctx)
                except Exception:
                    logger.warning(f"[Upgrade:{deployment.hostname}] Failed to log audit: upgrade failed")
                return Err(error_msg, retriability=retriability_of(result))

            cmd_result = result.unwrap()
            if not cmd_result.success:
                error_msg = f"Resize failed: {cmd_result.stderr}"
                NodeDeploymentLog.objects.create(
                    deployment=deployment,
                    level="ERROR",
                    message=error_msg,
                    phase="upgrading",
                )
                try:
                    InfrastructureAuditService.log_node_upgrade_failed(deployment, error_msg, audit_ctx)
                except Exception:
                    logger.warning(f"[Upgrade:{deployment.hostname}] Failed to log audit: upgrade failed")
                return Err(error_msg)

            # Write only the size: a full save would write back a lifecycle state read before the resize.
            deployment.node_size = new_size
            deployment.save(update_fields=["node_size", "updated_at"])

            NodeDeploymentLog.objects.create(
                deployment=deployment,
                level="INFO",
                message=f"Successfully upgraded to {new_size.name}",
                phase="completed",
            )

            # Audit: upgrade completed
            try:
                InfrastructureAuditService.log_node_upgrade_completed(deployment, old_size, new_size, audit_ctx)
            except Exception:
                logger.warning(f"[Upgrade:{deployment.hostname}] Failed to log audit: upgrade completed")

            logger.info(f"[Upgrade:{deployment.hostname}] Node upgraded successfully")
            return Ok(True)

        except Exception as e:
            logger.exception(f"Upgrade failed for {deployment.hostname}: {e}")
            NodeDeploymentLog.objects.create(
                deployment=deployment,
                level="ERROR",
                message=str(e),
                phase="upgrading",
            )
            try:
                InfrastructureAuditService.log_node_upgrade_failed(deployment, str(e), audit_ctx)
            except Exception:
                logger.warning(f"[Upgrade:{deployment.hostname}] Failed to log audit: upgrade failed")
            return Err(f"Upgrade failed: {e}")

    def run_maintenance(  # Complexity: deployment orchestration  # noqa: C901, PLR0911  # Complexity: multi-step business logic
        self,
        deployment: NodeDeployment,
        playbooks: list[str] | None = None,
        extra_vars: dict[str, Any] | None = None,
        user: User | None = None,
    ) -> Result[list[AnsibleResult], str]:
        """
        Run maintenance playbooks on a deployed node.

        Args:
            deployment: NodeDeployment instance
            playbooks: List of playbook names to run (default: virtualmin_harden.yml)
            extra_vars: Extra variables to pass to Ansible
            user: User performing the maintenance

        Returns:
            Result with list of AnsibleResult or error
        """
        from apps.infrastructure.models import (  # noqa: PLC0415  # Deferred: avoids circular import
            NodeDeploymentLog,  # Circular: cross-app  # Deferred: avoids circular import
        )

        if deployment.status != "completed":
            return Err(f"Can only run maintenance on completed deployments, current status: {deployment.status}")

        if not deployment.ipv4_address:
            return Err("Deployment has no IP address")

        actions = playbooks or ["security"]
        try:
            playbooks = resolve_maintenance_playbooks(deployment.panel_type.panel_type, actions)
        except ValueError as exc:
            return Err(str(exc))

        logger.info(f"[Maintenance:{deployment.hostname}] Running playbooks: {playbooks}")

        NodeDeploymentLog.objects.create(
            deployment=deployment,
            level="INFO",
            message=f"Starting maintenance: {', '.join(playbooks)}",
            phase="maintenance",
        )

        audit_ctx = InfrastructureAuditContext(user=user)

        # Audit: maintenance started
        try:
            InfrastructureAuditService.log_node_maintenance_started(deployment, playbooks, audit_ctx)
        except Exception:
            logger.warning(f"[Maintenance:{deployment.hostname}] Failed to log audit: maintenance started")

        results = []
        try:
            for playbook in playbooks:
                result = self._ansible.run_playbook(
                    deployment=deployment,
                    playbook=playbook,
                    extra_vars=extra_vars,
                )

                if result.is_err():
                    error_msg = f"Playbook {playbook} failed: {result.unwrap_err()}"
                    NodeDeploymentLog.objects.create(
                        deployment=deployment,
                        level="ERROR",
                        message=error_msg,
                        phase="maintenance",
                    )
                    try:
                        InfrastructureAuditService.log_node_maintenance_failed(
                            deployment, playbooks, error_msg, audit_ctx
                        )
                    except Exception:
                        logger.warning(f"[Maintenance:{deployment.hostname}] Failed to log audit: maintenance failed")
                    return Err(error_msg, retriability=retriability_of(result))

                ansible_result = result.unwrap()
                results.append(ansible_result)

                if not ansible_result.success:
                    error_msg = f"Playbook {playbook} failed: {ansible_result.stderr[:500]}"
                    NodeDeploymentLog.objects.create(
                        deployment=deployment,
                        level="ERROR",
                        message=error_msg,
                        phase="maintenance",
                    )
                    try:
                        InfrastructureAuditService.log_node_maintenance_failed(
                            deployment, playbooks, error_msg, audit_ctx
                        )
                    except Exception:
                        logger.warning(f"[Maintenance:{deployment.hostname}] Failed to log audit: maintenance failed")
                    return Err(error_msg)

                NodeDeploymentLog.objects.create(
                    deployment=deployment,
                    level="INFO",
                    message=f"Playbook {playbook} completed successfully",
                    phase="maintenance",
                )

            NodeDeploymentLog.objects.create(
                deployment=deployment,
                level="INFO",
                message="Maintenance completed successfully",
                phase="completed",
            )

            # Audit: maintenance completed
            try:
                InfrastructureAuditService.log_node_maintenance_completed(deployment, playbooks, audit_ctx)
            except Exception:
                logger.warning(f"[Maintenance:{deployment.hostname}] Failed to log audit: maintenance completed")

            logger.info(f"[Maintenance:{deployment.hostname}] All playbooks completed")
            return Ok(results)

        except Exception as e:
            logger.exception(f"Maintenance failed for {deployment.hostname}: {e}")
            NodeDeploymentLog.objects.create(
                deployment=deployment,
                level="ERROR",
                message=str(e),
                phase="maintenance",
            )
            try:
                InfrastructureAuditService.log_node_maintenance_failed(deployment, playbooks, str(e), audit_ctx)
            except Exception:
                logger.warning(f"[Maintenance:{deployment.hostname}] Failed to log audit: maintenance failed")
            return Err(f"Maintenance failed: {e}")

    def _disable_linked_server_for_stop(
        self,
        deployment: NodeDeployment,
        audit_ctx: InfrastructureAuditContext,
        *,
        force: bool = False,
    ) -> Result[bool, str]:
        """Refuse stopping an undrained Virtualmin node; disable the linked server otherwise."""
        closed = close_node_admission(deployment.virtualmin_server_id, force=force)
        if closed.is_err():
            error_msg = closed.unwrap_err().replace("explicitly force", "explicitly force stop")
            InfrastructureAuditService.log_node_stop_failed(deployment, error_msg, audit_ctx)
            logger.warning("⚠️ [NodeDrain] Stop refused: %s", deployment.hostname)
            return Err(error_msg)
        return Ok(True)

    def stop_node(  # noqa: PLR0911
        self,
        deployment: NodeDeployment,
        credentials: dict[str, str],
        user: User | None = None,
        *,
        force: bool = False,
    ) -> Result[bool, str]:
        """
        Stop (power off) a deployed node.

        Args:
            deployment: NodeDeployment instance
            credentials: Provider credentials dict
            user: User performing the action

        Returns:
            Result with success status or error
        """
        from apps.infrastructure.models import (  # noqa: PLC0415  # Deferred: avoids circular import
            NodeDeploymentLog,  # Circular: cross-app  # Deferred: avoids circular import
        )

        logger.info(f"[Stop:{deployment.hostname}] Stopping node")

        if deployment.status not in ("completed", "stopped"):
            return Err(f"Can only stop completed nodes, current status: {deployment.status}")

        if deployment.status == "stopped":
            return Ok(True)  # Already stopped

        audit_ctx = InfrastructureAuditContext(user=user, metadata={"force": force})

        # Audit: stop started
        try:
            InfrastructureAuditService.log_node_stop_started(deployment, audit_ctx)
        except Exception:
            logger.warning(f"[Stop:{deployment.hostname}] Failed to log audit: stop started")

        try:
            disable_result = self._disable_linked_server_for_stop(deployment, audit_ctx, force=force)
            if disable_result.is_err():
                return disable_result
            provider_type = deployment.provider.provider_type
            result = run_provider_command(
                provider_type=provider_type,
                operation="power_off",
                credentials=credentials,
                server_id=str(deployment.external_node_id),
            )

            if result.is_err():
                error_msg = f"Failed to stop node: {result.unwrap_err()}"
                try:
                    InfrastructureAuditService.log_node_stop_failed(deployment, error_msg, audit_ctx)
                except Exception:
                    logger.warning(f"[Stop:{deployment.hostname}] Failed to log audit: stop failed")
                return Err(error_msg, retriability=retriability_of(result))

            cmd_result = result.unwrap()
            if not cmd_result.success:
                error_msg = f"Failed to stop node: {cmd_result.stderr}"
                try:
                    InfrastructureAuditService.log_node_stop_failed(deployment, error_msg, audit_ctx)
                except Exception:
                    logger.warning(f"[Stop:{deployment.hostname}] Failed to log audit: stop failed")
                return Err(error_msg)

            deployment.transition_to("stopped")

            NodeDeploymentLog.objects.create(
                deployment=deployment,
                level="INFO",
                message="Node stopped (powered off)",
                phase="stopped",
            )

            # Audit: stop completed
            try:
                InfrastructureAuditService.log_node_stop_completed(deployment, audit_ctx)
            except Exception:
                logger.warning(f"[Stop:{deployment.hostname}] Failed to log audit: stop completed")

            logger.info(f"[Stop:{deployment.hostname}] Node stopped successfully")
            return Ok(True)

        except Exception as e:
            logger.exception(f"Stop failed for {deployment.hostname}: {e}")
            try:
                InfrastructureAuditService.log_node_stop_failed(deployment, str(e), audit_ctx)
            except Exception:
                logger.warning(f"[Stop:{deployment.hostname}] Failed to log audit: stop failed")
            return Err(f"Stop failed: {e}")

    def start_node(
        self,
        deployment: NodeDeployment,
        credentials: dict[str, str],
        user: User | None = None,
    ) -> Result[bool, str]:
        """
        Start (power on) a stopped node.

        Args:
            deployment: NodeDeployment instance
            credentials: Provider credentials dict
            user: User performing the action

        Returns:
            Result with success status or error
        """
        from apps.infrastructure.models import (  # noqa: PLC0415  # Deferred: avoids circular import
            NodeDeploymentLog,  # Circular: cross-app  # Deferred: avoids circular import
        )

        logger.info(f"[Start:{deployment.hostname}] Starting node")

        if deployment.status != "stopped":
            return Err(f"Can only start stopped nodes, current status: {deployment.status}")

        audit_ctx = InfrastructureAuditContext(user=user)

        try:
            provider_type = deployment.provider.provider_type
            result = run_provider_command(
                provider_type=provider_type,
                operation="power_on",
                credentials=credentials,
                server_id=str(deployment.external_node_id),
            )

            if result.is_err():
                error_msg = f"Failed to start node: {result.unwrap_err()}"
                try:
                    InfrastructureAuditService.log_node_start_failed(deployment, error_msg, audit_ctx)
                except Exception:
                    logger.warning(f"[Start:{deployment.hostname}] Failed to log audit: start failed")
                return Err(error_msg, retriability=retriability_of(result))

            cmd_result = result.unwrap()
            if not cmd_result.success:
                error_msg = f"Failed to start node: {cmd_result.stderr}"
                try:
                    InfrastructureAuditService.log_node_start_failed(deployment, error_msg, audit_ctx)
                except Exception:
                    logger.warning(f"[Start:{deployment.hostname}] Failed to log audit: start failed")
                return Err(error_msg)

            deployment.transition_to("completed")

            NodeDeploymentLog.objects.create(
                deployment=deployment,
                level="INFO",
                message="Node started (powered on)",
                phase="completed",
            )

            if deployment.virtualmin_server_id:
                from apps.provisioning.virtualmin_models import VirtualminServer  # noqa: PLC0415  # Circular

                server = VirtualminServer.objects.get(pk=deployment.virtualmin_server_id)
                if server.status == "disabled":
                    activation = get_registration_service().verify_and_activate(server)
                    if activation.is_err():
                        raise ValueError(f"Powered on; Virtualmin activation failed: {activation.unwrap_err()}")
                    # Clear the drain exclusion ONLY when no non-terminal drain
                    # owns it — a drain admitted between activation and this
                    # update must keep the server out of placement.
                    VirtualminServer.objects.filter(pk=server.pk, status="active").exclude(
                        drains__status__in=("pending", "running", "paused_needs_review")
                    ).update(is_draining=False, updated_at=timezone.now())

            # Audit: start completed
            try:
                InfrastructureAuditService.log_node_start_completed(deployment, audit_ctx)
            except Exception:
                logger.warning(f"[Start:{deployment.hostname}] Failed to log audit: start completed")

            logger.info(f"[Start:{deployment.hostname}] Node started successfully")
            return Ok(True)

        except Exception as e:
            logger.exception(f"Start failed for {deployment.hostname}: {e}")
            try:
                InfrastructureAuditService.log_node_start_failed(deployment, str(e), audit_ctx)
            except Exception:
                logger.warning(f"[Start:{deployment.hostname}] Failed to log audit: start failed")
            return Err(f"Start failed: {e}")

    def reboot_node(
        self,
        deployment: NodeDeployment,
        credentials: dict[str, str],
        user: User | None = None,
    ) -> Result[bool, str]:
        """
        Reboot a deployed node.

        Args:
            deployment: NodeDeployment instance
            credentials: Provider credentials dict
            user: User performing the action

        Returns:
            Result with success status or error
        """
        from apps.infrastructure.models import (  # noqa: PLC0415  # Deferred: avoids circular import
            NodeDeploymentLog,  # Circular: cross-app  # Deferred: avoids circular import
        )

        logger.info(f"[Reboot:{deployment.hostname}] Rebooting node")

        if deployment.status != "completed":
            return Err(f"Can only reboot running nodes, current status: {deployment.status}")

        audit_ctx = InfrastructureAuditContext(user=user)

        try:
            provider_type = deployment.provider.provider_type
            result = run_provider_command(
                provider_type=provider_type,
                operation="reboot",
                credentials=credentials,
                server_id=str(deployment.external_node_id),
            )

            if result.is_err():
                error_msg = f"Failed to reboot node: {result.unwrap_err()}"
                try:
                    InfrastructureAuditService.log_node_reboot_failed(deployment, error_msg, audit_ctx)
                except Exception:
                    logger.warning(f"[Reboot:{deployment.hostname}] Failed to log audit: reboot failed")
                return Err(error_msg, retriability=retriability_of(result))

            cmd_result = result.unwrap()
            if not cmd_result.success:
                error_msg = f"Failed to reboot node: {cmd_result.stderr}"
                try:
                    InfrastructureAuditService.log_node_reboot_failed(deployment, error_msg, audit_ctx)
                except Exception:
                    logger.warning(f"[Reboot:{deployment.hostname}] Failed to log audit: reboot failed")
                return Err(error_msg)

            NodeDeploymentLog.objects.create(
                deployment=deployment,
                level="INFO",
                message="Node rebooted",
                phase="completed",
            )

            # Audit: reboot completed
            try:
                InfrastructureAuditService.log_node_reboot_completed(deployment, audit_ctx)
            except Exception:
                logger.warning(f"[Reboot:{deployment.hostname}] Failed to log audit: reboot completed")

            logger.info(f"[Reboot:{deployment.hostname}] Node rebooted successfully")
            return Ok(True)

        except Exception as e:
            logger.exception(f"Reboot failed for {deployment.hostname}: {e}")
            try:
                InfrastructureAuditService.log_node_reboot_failed(deployment, str(e), audit_ctx)
            except Exception:
                logger.warning(f"[Reboot:{deployment.hostname}] Failed to log audit: reboot failed")
            return Err(f"Reboot failed: {e}")

    @staticmethod
    def _dns_owner_tag(deployment: NodeDeployment) -> str:
        """Ownership marker stamped on every DNS record this deployment creates.

        The tag its records already carry, never a recomputed one, so records written under the
        legacy integer tag stay reconcilable; otherwise one derived from correlation_id, which is
        unique across PRAHO databases sharing a zone.
        """
        for entry in deployment.dns_record_ids or []:
            if isinstance(entry, dict) and entry.get("owner_tag"):
                return str(entry["owner_tag"])
        return NodeDeploymentService._unique_dns_owner_tag(deployment)

    @staticmethod
    def _unique_dns_owner_tag(deployment: NodeDeployment) -> str:
        return f"praho:node-deploy:{deployment.correlation_id}"

    def _resolve_dns_config(
        self, deployment: NodeDeployment, token_override: str | None
    ) -> Result[tuple[str, str], str]:
        """Resolve the Cloudflare token + zone and validate PRESENCE before provisioning.

        The token param is an optional override for async callers that already resolved it;
        sync callers (management commands) rely on the settings lookup here. This runs at
        preflight so a *missing* DNS config fails before a paid VM is created (#347 GAP 3;
        codex C2/C3). The read-only zone-access + fqdn-containment check runs in
        ``_configure_dns`` (after the VM exists) — a wrong/unauthorized zone there fails
        closed and the VM is compensated.
        """
        token = (token_override or "").strip() or str(
            SettingsService.get_setting("node_deployment.dns_cloudflare_api_token") or ""
        ).strip()
        zone_id = str(SettingsService.get_setting("node_deployment.dns_cloudflare_zone_id") or "").strip()
        if not token:
            return Err("Cloudflare API token is not configured (node_deployment.dns_cloudflare_api_token)")
        if not zone_id:
            return Err("Cloudflare zone id is not configured (node_deployment.dns_cloudflare_zone_id)")
        return Ok((token, zone_id))

    def _configure_dns(
        self,
        deployment: NodeDeployment,
        token: str,
        zone_id: str,
        log: Callable[[str, str], None],
        lease: OperationLease,
    ) -> Result[None, str]:
        """Create/reconcile the node's A (+AAAA) records; persist ids immediately.

        Applied records are persisted with their own ``update_fields`` save BEFORE any error
        is returned, so a created A record is never leaked when a later record fails (#347
        GAP 3; codex C5 / reviewer H5 — the update_fields-drop trap).
        """
        owner_tag = self._dns_owner_tag(deployment)
        fqdn = deployment.fqdn
        try:
            gateway = get_dns_gateway("cloudflare", token)
        except ValueError as exc:
            return Err(f"DNS provider unavailable: {exc}")

        # Read-only zone check: confirm the token has access and the zone actually contains
        # the node fqdn. Fails closed — the caller compensates the just-provisioned VM
        # (#347 GAP 3; codex M11).
        zone_name_result = gateway.get_zone_name(zone_id)
        if zone_name_result.is_err():
            return Err(f"Cloudflare zone check failed: {zone_name_result.unwrap_err()}")
        zone_name = zone_name_result.unwrap().lower().strip(".")
        if not (fqdn.lower().strip(".") == zone_name or fqdn.lower().strip(".").endswith(f".{zone_name}")):
            return Err(f"fqdn '{fqdn}' is not within Cloudflare zone '{zone_name}'")

        ipv4 = deployment.ipv4_address
        if not ipv4:
            return Err("Cannot configure DNS: node has no IPv4 address")
        specs = [DnsRecordSpec(record_type="A", name=fqdn, content=ipv4, owner_tag=owner_tag)]
        ipv6 = deployment.ipv6_address
        if ipv6:
            specs.append(DnsRecordSpec(record_type="AAAA", name=fqdn, content=ipv6, owner_tag=owner_tag))

        # Persist cleanup provenance BEFORE the first mutation: a create can be replayed by
        # safe_request's DNS fallback, so a POST may reach Cloudflare even when the call ends in
        # an error with no returned id. This intent marker gives owner-tag teardown a zone to
        # sweep even when reconcile returns no applied records (codex P1).
        intent = {
            "provider": "cloudflare",
            "zone_id": zone_id,
            "record_id": "",
            "type": "intent",
            "name": fqdn,
            "owner_tag": owner_tag,
        }
        # Records already stored keep their ids: a legacy-tag record without its id could only be
        # withdrawn by a zone-wide tag sweep, which another database sharing the tag would feel.
        stored = [e for e in deployment.dns_record_ids or [] if isinstance(e, dict) and e.get("record_id")]
        owned_update(lease, deployment, dns_record_ids=[*stored, intent])

        outcome = gateway.reconcile_records(zone_id, specs, owner_tag)
        applied = [r.as_provenance() for r in outcome.applied]
        if outcome.error:
            # A partial outcome proves only the applied records: every other stored record, and the
            # intent marker, stay until a later run proves them converged or gone.
            applied_ids = {entry["record_id"] for entry in applied}
            unresolved = [e for e in [*stored, intent] if e.get("record_id") not in applied_ids]
            owned_update(lease, deployment, dns_record_ids=[*applied, *unresolved])
        elif applied:
            owned_update(lease, deployment, dns_record_ids=applied)
        if outcome.applied:
            log("info", f"DNS configured: {', '.join(r.record_type for r in outcome.applied)} for {fqdn}")
        if outcome.error:
            return Err(f"DNS configuration failed: {outcome.error}")
        return Ok(None)

    @staticmethod
    def _delete_owned_dns(deployment: NodeDeployment, lease: OperationLease | None = None) -> Result[None, str]:
        """Withdraw this deployment's DNS records and clear only what is proven gone.

        Records under the deployment's own correlation tag are deleted by tag and confirmed by listing
        the tag again. Records under any other stored tag (the legacy integer tag, which two databases
        sharing a zone can both use) are deleted only by their stored id, after the record still
        matches its stored name, type and address. An entry with no record id under such a tag is
        ambiguous: it is kept and the deployment is flagged for reconciliation, never swept by tag.
        Everything unresolved stays in dns_record_ids with a durable orphan marker. Static so the
        scheduled teardown task can call it without building the whole service.
        """
        entries = [e for e in deployment.dns_record_ids or [] if isinstance(e, dict)]
        if not entries:
            return Ok(None)
        token = str(SettingsService.get_setting("node_deployment.dns_cloudflare_api_token") or "").strip()
        if not token:
            return NodeDeploymentService._dns_unresolved(deployment, entries, "no Cloudflare token", lease)
        try:
            gateway = get_dns_gateway("cloudflare", token)
        except ValueError as exc:
            return NodeDeploymentService._dns_unresolved(deployment, entries, f"provider unavailable: {exc}", lease)

        unique_tag = NodeDeploymentService._unique_dns_owner_tag(deployment)
        remaining: list[dict[str, Any]] = []
        ambiguous: list[dict[str, Any]] = []
        groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
        for entry in entries:
            groups.setdefault((str(entry.get("zone_id") or ""), str(entry.get("owner_tag") or "")), []).append(entry)
        for (zone_id, tag), group in groups.items():
            if not zone_id or not tag:
                ambiguous.extend(group)
            elif tag == unique_tag:
                if NodeDeploymentService._withdraw_by_unique_tag(gateway, zone_id, tag).is_err():
                    remaining.extend(group)
            else:
                concrete, unclear = NodeDeploymentService._legacy_expectations(deployment, group)
                ambiguous.extend(unclear)
                if concrete and gateway.delete_validated_records(zone_id, list(concrete.values())).is_err():
                    remaining.extend(e for e in group if str(e.get("record_id")) in concrete)
        if remaining or ambiguous:
            return NodeDeploymentService._dns_unresolved(
                deployment, [*remaining, *ambiguous], "withdrawal incomplete", lease, ambiguous=bool(ambiguous)
            )
        NodeDeploymentService._write_dns_record_ids(deployment, [], lease)
        return Ok(None)

    @staticmethod
    def _withdraw_by_unique_tag(gateway: Any, zone_id: str, tag: str) -> Result[None, str]:
        deleted = gateway.delete_owned_records(zone_id, tag)
        if deleted.is_err():
            return Err(deleted.unwrap_err())
        confirmed = gateway.confirm_no_owned_records(zone_id, tag)
        if confirmed.is_err() or not confirmed.unwrap():
            return Err(f"records tagged {tag} still present in zone {zone_id}")
        return Ok(None)

    @staticmethod
    def _legacy_expectations(
        deployment: NodeDeployment, group: list[dict[str, Any]]
    ) -> tuple[dict[str, ExpectedDnsRecord], list[dict[str, Any]]]:
        """Split legacy-tag entries into ones provable by id/name/type/address and ambiguous ones."""
        addresses = {"A": deployment.ipv4_address or "", "AAAA": deployment.ipv6_address or ""}
        concrete: dict[str, ExpectedDnsRecord] = {}
        unclear: list[dict[str, Any]] = []
        for entry in group:
            record_type = str(entry.get("type") or "")
            content = str(entry.get("content") or addresses.get(record_type, ""))
            if not entry.get("record_id") or record_type not in addresses or not content or not entry.get("name"):
                unclear.append(entry)
                continue
            concrete[str(entry["record_id"])] = ExpectedDnsRecord(
                record_id=str(entry["record_id"]),
                name=str(entry["name"]),
                record_type=record_type,
                content=content,
                owner_tag=str(entry["owner_tag"]),
            )
        return concrete, unclear

    @staticmethod
    def _dns_unresolved(
        deployment: NodeDeployment,
        entries: list[dict[str, Any]],
        reason: str,
        lease: OperationLease | None = None,
        *,
        ambiguous: bool = False,
    ) -> Result[None, str]:
        """Keep the unresolved entries, leave a durable orphan marker, and say why."""
        from apps.infrastructure.models import NodeDeploymentLog  # noqa: PLC0415

        message = f"DNS teardown {reason}; {len(entries)} orphaned record(s) need reconciliation"
        logger.warning(f"⚠️ [Deployment:{deployment.hostname}] {message}")
        NodeDeploymentLog.objects.create(deployment=deployment, level="WARNING", message=message, phase="destroy")
        reconcile = message if ambiguous else ""
        NodeDeploymentService._write_dns_record_ids(deployment, entries, lease, reconcile_reason=reconcile)
        return Err(message)

    @staticmethod
    def _write_dns_record_ids(
        deployment: NodeDeployment,
        entries: list[dict[str, Any]],
        lease: OperationLease | None,
        *,
        reconcile_reason: str = "",
    ) -> None:
        """Record the DNS entries still unresolved; owned when the caller holds a lease."""
        fields: dict[str, Any] = {"dns_record_ids": entries}
        if reconcile_reason:
            fields.update(needs_reconciliation=True, reconciliation_reason=reconcile_reason)
        if lease is not None:
            owned_update(lease, deployment, **fields)
        else:
            for name, value in fields.items():
                setattr(deployment, name, value)
            deployment.save(update_fields=[*fields, "updated_at"])

    def _cleanup_resources(
        self,
        gateway: CloudProviderGateway,
        resources: list[tuple[str, str]],
        deployment: NodeDeployment,
        lease: OperationLease | None = None,
    ) -> None:
        """
        Best-effort cleanup of cloud resources created during a failed deployment.

        Processes resources in reverse creation order (server → firewall → ssh_key)
        so dependencies are respected. Never raises; logs all outcomes.

        Args:
            gateway: The cloud provider gateway to use for deletions
            resources: List of (resource_type, resource_id) tuples in creation order
            deployment: The NodeDeployment instance (used for logging only)
        """
        hostname = deployment.hostname
        if lease is not None and not still_owns(lease):
            # The row belongs to another owner now; its resources are no longer ours to delete.
            logger.warning(f"⚠️ [Deployment:{hostname}] Cleanup skipped: this operation no longer owns the deployment")
            return
        # DNS first: no record may point at an address about to be released. Unconfirmed, the server is
        # kept (the row fails with its id) and the teardown sweep finishes the job.
        try:
            dns = self._delete_owned_dns(deployment, lease)
        except OperationOwnershipLostError as lost:
            logger.warning(f"⚠️ [Deployment:{hostname}] Cleanup stopped: {lost}")
            return
        if dns.is_err():
            logger.warning(f"⚠️ [Deployment:{hostname}] Cleanup kept the server: {dns.unwrap_err()}")
            return
        logger.info(f"[Deployment:{hostname}] Starting best-effort cleanup of {len(resources)} resource(s)")

        for resource_type, resource_id in reversed(resources):
            try:
                self._delete_created_resource(gateway, resource_type, resource_id, hostname)
            except Exception as exc:
                logger.warning(
                    f"[Deployment:{hostname}] Cleanup: exception deleting {resource_type} '{resource_id}': {exc}"
                )

        # The node is gone: its Virtualmin API credential, stored before the panel install, goes too.
        deactivate_api_credential(deployment)
        logger.info(f"[Deployment:{hostname}] Cleanup complete")

    @staticmethod
    def _delete_created_resource(
        gateway: CloudProviderGateway, resource_type: str, resource_id: str, hostname: str
    ) -> None:
        """Delete one resource this deployment created; logs the outcome, raises only what the SDK raises."""
        deleters = {
            "server": ("server id", gateway.delete_server),
            "firewall": ("firewall id", gateway.delete_firewall),
            "ssh_key": ("SSH key name", gateway.delete_ssh_key),
        }
        if resource_type not in deleters:
            logger.warning(f"[Deployment:{hostname}] Cleanup: unknown resource type '{resource_type}'")
            return
        label, delete = deleters[resource_type]
        logger.info(f"[Deployment:{hostname}] Cleanup: deleting {label}={resource_id}")
        result = delete(resource_id)
        if result.is_err():
            logger.warning(f"[Deployment:{hostname}] Cleanup: {resource_type} deletion failed: {result.unwrap_err()}")
        else:
            logger.info(f"[Deployment:{hostname}] Cleanup: {label}={resource_id} deleted ✅")

    def _mark_failed(
        self,
        deployment: NodeDeployment,
        error_message: str,
        stage: str = "",
        audit_ctx: InfrastructureAuditContext | None = None,
        lease: OperationLease | None = None,
    ) -> None:
        """Mark deployment as failed with error message.

        With a lease, the failure settles the operation and is written only while the lease still owns
        the row; a worker that lost ownership writes no status, log or audit.
        """
        from apps.infrastructure.models import (  # noqa: PLC0415  # Deferred: avoids circular import
            NodeDeploymentLog,  # Circular: cross-app  # Deferred: avoids circular import
        )

        # Capture the current stage before transitioning to failed
        failed_stage = stage or deployment.status

        if lease is not None:
            try:
                owned_transition(lease, deployment, "failed", error_message, release=True)
            except OperationOwnershipLostError as lost:
                logger.warning(f"⚠️ [Deployment:{deployment.hostname}] Failure not recorded: {lost}")
                return
        elif not self._force_failed(deployment, error_message):
            return

        NodeDeploymentLog.objects.create(
            deployment=deployment,
            level="ERROR",
            message=error_message,
            phase=failed_stage,
        )

        # Audit: deployment failed (with user context if available)
        try:
            InfrastructureAuditService.log_deployment_failed(
                deployment,
                error_message,
                stage=failed_stage,
                context=audit_ctx,
            )
        except Exception:
            logger.warning(f"[Deployment:{deployment.hostname}] Failed to log audit: deployment failed")

        logger.error(f"[Deployment:{deployment.hostname}] Failed at stage '{failed_stage}': {error_message}")

    @staticmethod
    def _force_failed(deployment: NodeDeployment, error_message: str) -> bool:
        """Unowned failure write for callers that hold no lease.

        Only a valid transition is written: forcing "failed" over "destroyed" (or any status another
        worker just wrote) would offer Retry on a half-destroyed node.
        """
        try:
            deployment.transition_to("failed", error_message)
        except ValidationError as refused:
            logger.warning(f"⚠️ [Deployment:{deployment.hostname}] Failure not recorded: {refused}")
            return False
        return True


# Module-level singleton
_deployment_service: NodeDeploymentService | None = None


def get_deployment_service() -> NodeDeploymentService:
    """Get global deployment service instance"""
    global _deployment_service  # noqa: PLW0603  # Module-level singleton pattern
    if _deployment_service is None:
        _deployment_service = NodeDeploymentService()
    return _deployment_service
