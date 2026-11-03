"""
Virtualmin Business Logic Service - PRAHO Platform
High-level service operations for Virtualmin provisioning and management.

Implements:
- Idempotency: Provisioning operations can be safely retried
- Rollback Mechanisms: Failed provisioning attempts are cleaned up
"""

from __future__ import annotations

import logging
import re
import secrets
import string
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models, transaction
from django.db.models.functions import Greatest
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from apps.common.transactions import is_outside_transaction
from apps.common.types import Err, Ok, Result, Retriability, retriability_of
from apps.common.validators import SecureInputValidator

from .account_hostname_lifecycle import on_account_ready
from .domain_veto import domain_disables_hosting
from .placement import order_placement_candidates
from .security_utils import IdempotencyManager
from .virtualmin_backup_service import (
    CHAIN_ROLE_BASE,
    CHAIN_ROLE_DIFFERENTIAL,
    CHAIN_ROLE_STANDALONE,
    BackupConfig,
    RestoreConfig,
    VirtualminBackupService,
)
from .virtualmin_create_node_identity import lock_create_retry_node
from .virtualmin_create_retry_binding import (
    CreateRetryBinding,
    binding_current,
    park_changed_binding,
    password_fingerprint,
    retry_binding,
    settle_retry_created,
)
from .virtualmin_create_retry_policy import create_retry_policy, creation_intent
from .virtualmin_domain_state import DOMAIN_STATE_PROGRAMS, domain_state_params
from .virtualmin_drain_service import coordinate_health_failure
from .virtualmin_gateway import (
    VirtualminConfig,
    VirtualminGateway,
    classify_virtualmin_application_error,
    get_virtualmin_config,
    get_virtualmin_timeouts,
    is_customer_domain_row,
)
from .virtualmin_models import (
    VirtualminAccount,
    VirtualminProvisioningJob,
    VirtualminServer,
)
from .virtualmin_node_capability import destination_refusal
from .virtualmin_revoked_create import (
    OFF_SOURCE_KEY,
    OffClaim,
    off_authority,
    off_claim,
    owns_off_claim,
    queue_revoked_create_off,
    retire_closed_off_claim,
    settle_off,
)
from .virtualmin_security import connection_identity
from .virtualmin_units import quota_parameters
from .virtualmin_validators import DEFAULT_VIRTUALMIN_TEMPLATE, WEB_ONLY_VIRTUALMIN_FEATURES, VirtualminValidator

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from .virtualmin_migration_service import MigrationResumeOutcome

from .virtualmin_chain import ROLE_STANDALONE, admit_chain_role, invalidate_chain
from .virtualmin_migration_models import (
    ACCOUNT_BUSY_REFUSAL,
    account_has_active_migration,
    account_has_active_operation,
)

logger = logging.getLogger(__name__)

# Expected tries are about 1.003; the bound only guards against a validator that rejects everything
_MAX_PASSWORD_ATTEMPTS = 100

# Username generation defaults
MIN_USERNAME_LENGTH = 3
_DEFAULT_MAX_USERNAME_UNIQUENESS_ATTEMPTS = 1000


def generate_virtualmin_parameter_secret(candidate: Callable[[], str]) -> str:
    """A random secret from ``candidate`` that Virtualmin's parameter validation accepts.

    Every remote.cgi parameter value is checked against SecureInputValidator's injection
    heuristics, and a random secret can match one (two adjacent "-" read as an SQL comment).
    A candidate the validator would reject is drawn again instead of failing the call permanently.
    """
    for _attempt in range(_MAX_PASSWORD_ATTEMPTS):
        secret = candidate()
        # The side-effect-free check: a discarded candidate is not an attack to alert on
        if SecureInputValidator.first_malicious_pattern(secret) is None:
            return secret
    raise RuntimeError("Could not generate a Virtualmin password that passes parameter validation")


def create_domain_params(  # noqa: PLR0913  # One keyword per remote.cgi parameter
    *,
    domain: str,
    username: str,
    password: str,
    template: str,
    recovery_seed: str,
    disk_quota_mb: int | None,
    bandwidth_quota_mb: int | None,
) -> dict[str, str]:
    """The create-domain parameters for one account (the contract suite sends exactly these)."""
    params = {
        "domain": domain,
        "user": username,
        "pass": password,
        "template": template,
        # The recovery seed, as the server description (8.x has no --comment).
        "desc": recovery_seed,
        "no-email": "",
        # Explicit flags prevent mutable templates/defaults from introducing
        # customer Webmin, mail/DNS or additional plugins on a web destination.
        **dict.fromkeys(WEB_ONLY_VIRTUALMIN_FEATURES, ""),
    }
    # Disk in KiB and bandwidth in bytes; zero and the -1 sentinel mean unlimited (shared with recovery).
    params.update(quota_parameters(disk_quota_mb, bandwidth_quota_mb))
    return params


def _clear_idempotency_key(idempotency_key: str | None, *, operation: str, domain: str) -> None:
    """Best-effort cleanup that preserves and exposes the primary failure."""
    if not idempotency_key:
        return
    try:
        IdempotencyManager.clear(idempotency_key)
    except Exception:
        logger.warning(
            "⚠️ [VirtualminService] Failed to clear idempotency key after %s failure for %s; may stay blocked until TTL",
            operation,
            domain,
            exc_info=True,
        )


def _job_matches_service_state(operation: str, service_status: str, account: VirtualminAccount) -> bool:
    """Whether a lifecycle job still matches what the account should be (ADR-0051).

    The one predicate for both checks in ``_execute_lifecycle_operation``: before the gateway
    call (a stale job is discarded) and after it (a moved Service is re-reconciled). It mirrors
    the reconciler's predicate in both directions (#566):
    - a suspend is also current for an active Service whose bound domain holds hosting off,
      because the reconciler issues exactly that suspend and its retry must not be discarded;
    - an unsuspend is current only while no bound domain holds hosting off, so a domain that
      expires while the retry's gateway call runs is re-reconciled by the check after it.
    """
    if operation == "suspend_domain":
        return service_status in ("suspended", "terminated", "expired") or (
            service_status == "active" and domain_disables_hosting(account)
        )
    if operation == "unsuspend_domain":
        return service_status == "active" and not domain_disables_hosting(account)
    return service_status == "terminated"


def get_max_username_uniqueness_attempts() -> int:
    """Get max username uniqueness attempts from SettingsService (runtime)."""
    from apps.settings.services import (  # Deferred: avoids circular import  # noqa: PLC0415  # Circular
        SettingsService,  # Circular: cross-app  # Deferred: avoids circular import
    )

    return SettingsService.get_integer_setting(
        "provisioning.max_username_uniqueness_attempts", _DEFAULT_MAX_USERNAME_UNIQUENESS_ATTEMPTS
    )


@dataclass
class VirtualminAccountCreationData:
    """Data class to encapsulate Virtualmin account creation parameters"""

    service: Any  # Service
    domain: str
    username: str | None = None
    password: str | None = None
    template: str = DEFAULT_VIRTUALMIN_TEMPLATE
    server: Any | None = None  # VirtualminServer


class VirtualminProvisioningService:
    """
    High-level Virtualmin provisioning service.

    Handles business logic for account creation, management, and lifecycle.
    Integrates with PRAHO's service management and customer billing.
    """

    def __init__(self, server: VirtualminServer | None = None, *, task_budget_seconds: int | None = None) -> None:
        self.server = server
        self._gateway: VirtualminGateway | None = None
        self._task_budget_seconds = task_budget_seconds

    def _job_parameters(self, parameters: dict[str, object], *, soft_limit: bool = False) -> dict[str, object]:
        """Persist the worker's enqueue snapshot; direct callers resolve before job creation."""
        from .virtualmin_tasks import get_task_soft_time_limit, get_task_time_limit  # noqa: PLC0415

        budget = self._task_budget_seconds
        if budget is None:
            budget = get_task_soft_time_limit() if soft_limit else get_task_time_limit()
        return {**parameters, "task_budget_seconds": budget}

    def _get_gateway(
        self, server: VirtualminServer | None = None, *, use_credential_vault: bool = True
    ) -> VirtualminGateway:
        """Get or create gateway for server.

        use_credential_vault=False forces the gateway to authenticate with the server object's own
        encrypted field instead of the vault — required by the staff "test these supplied
        credentials" flow, which must probe the operator-entered password, not whatever the vault
        happens to hold for that hostname. A non-vault gateway is never cached.
        """
        target_server = server or self.server

        if not target_server:
            raise ValidationError(_("No server specified for gateway"))

        if not use_credential_vault:
            config_data = get_virtualmin_config()
            config = VirtualminConfig(
                server=target_server,
                timeout=config_data["timeout"],
                verify_ssl=target_server.ssl_verify,
                cert_fingerprint=target_server.ssl_cert_fingerprint or config_data.get("pinned_cert_sha256", ""),
                use_credential_vault=False,
            )
            return VirtualminGateway(config)

        if not self._gateway or (server and server != self.server):
            # Get configuration from SystemSettings + environment
            config_data = get_virtualmin_config()

            # Create VirtualminConfig with server and override SSL settings
            config = VirtualminConfig(
                server=target_server,
                timeout=config_data["timeout"],
                verify_ssl=target_server.ssl_verify,
                cert_fingerprint=target_server.ssl_cert_fingerprint or config_data.get("pinned_cert_sha256", ""),
            )

            self._gateway = VirtualminGateway(config)

        return self._gateway

    @staticmethod
    def _lock_open_server(server: VirtualminServer) -> Result[VirtualminServer, str]:
        """Lock the server row teardown's guard locks and admit only an active, undrained server.

        Called inside the transaction that inserts the account, so the refusal comes before any row
        exists: a closing node is never left holding an account, not even an error one.
        """
        locked = VirtualminServer.objects.select_for_update().get(pk=server.pk)
        from apps.infrastructure.node_maintenance_gate import (  # noqa: PLC0415  # Shared server admission
            maintenance_refusal,
        )

        if locked.security_operation:
            return Err("Target server has an unresolved hardening operation", retriability=Retriability.RETRIABLE)
        if refusal := maintenance_refusal(locked.pk):
            return Err(refusal, retriability=Retriability.RETRIABLE)
        if locked.is_draining:
            return Err("Target server is draining", retriability=Retriability.RETRIABLE)
        if locked.status != "active":
            return Err(f"Server {locked.name} is not accepting new accounts")
        if refusal := destination_refusal(locked):
            return Err(refusal, retriability=Retriability.NOT_RETRIABLE)
        return Ok(locked)

    def create_virtualmin_account(  # noqa: PLR0911, PLR0912  # One refusal per admission check
        self, creation_data: VirtualminAccountCreationData
    ) -> Result[VirtualminAccount, str]:
        """
        Create new Virtualmin account for PRAHO service.

        Args:
            creation_data: VirtualminAccountCreationData object containing all creation parameters

        Returns:
            Result with created VirtualminAccount or error message
        """
        try:
            # Input validation
            domain = VirtualminValidator.validate_domain_name(creation_data.domain)
            template = VirtualminValidator.validate_template_name(creation_data.template)

            # Auto-generate username if not provided
            if not creation_data.username:
                username = self._generate_username_from_domain(domain)
            else:
                username = VirtualminValidator.validate_username(creation_data.username)

            # Auto-generate password if not provided
            if not creation_data.password:
                password = self._generate_secure_password()
            else:
                password = VirtualminValidator.validate_password(creation_data.password)

            # Select server if not provided
            if not creation_data.server:
                server_result = self._select_best_server()
                if server_result.is_err():
                    return Err(
                        f"Server selection failed: {server_result.unwrap_err()}",
                        retriability=retriability_of(server_result),
                    )
                server = server_result.unwrap()
            else:
                server = creation_data.server

            # Check if domain already exists
            existing_account = VirtualminAccount.objects.filter(domain=domain).first()
            if existing_account:
                return Err(f"Domain {domain} already exists in PRAHO")

            # Create account record
            with transaction.atomic():
                # Admission under the server row lock that node teardown's guard takes: once the guard
                # found the node empty and closed it, no account can land on it afterwards.
                admission = self._lock_open_server(server)
                if admission.is_err():
                    return Err(admission.unwrap_err(), retriability=retriability_of(admission))
                server = admission.unwrap()
                account = VirtualminAccount(
                    domain=domain,
                    service=creation_data.service,
                    server=server,
                    virtualmin_username=username,
                    template_name=template,
                    status="provisioning",
                    praho_customer_id=creation_data.service.customer.id,
                    praho_service_id=uuid.UUID(int=creation_data.service.id),
                )
                # SECURITY: generated by _generate_secure_password, or a caller-supplied value that
                # VirtualminValidator.validate_password checked above
                account.set_password(  # nosemgrep: unvalidated-password
                    password
                )
                account.save()

                # Create provisioning job
                job = VirtualminProvisioningJob(
                    operation="create_domain",
                    server=server,
                    account=account,
                    parameters=self._job_parameters(
                        {
                            "domain": domain,
                            "username": username,
                            "template": template,
                            "recovery_seed": account.get_recovery_seed(),
                            "node_connection_identity": connection_identity(server),
                            "creation_intent": creation_intent(creation_data.service.pk, purpose="create"),
                            "creation_credential_generation": password_fingerprint(account),
                        }
                    ),
                    correlation_id=f"create_domain_{account.id}",
                )
                job.save()

            # Execute provisioning
            provisioning_result = self._execute_domain_creation(account, job)

            if provisioning_result.is_ok():
                logger.info(
                    f"✅ [VirtualminService] Created account {domain} for customer {creation_data.service.customer.id}"
                )
                return Ok(account)
            else:
                error_msg = provisioning_result.unwrap_err()
                logger.error(f"❌ [VirtualminService] Failed to create account {domain}: {error_msg}")

                # Update account status
                account.status = "error"  # fsm-bypass: CharField status
                account.status_message = error_msg
                account.save(update_fields=["status", "status_message", "updated_at"])

                return Err(error_msg, retriability=retriability_of(provisioning_result))

        except ValidationError as e:
            return Err(f"Validation error: {e}")
        except Exception as e:
            logger.exception(f"Unexpected error creating Virtualmin account: {e}")
            return Err(f"Internal error: {e}")

    def reprovision_virtualmin_account(  # noqa: PLR0911 -- Refuse stale ownership/native operations before credential rotation.
        self, account: VirtualminAccount, target_server: VirtualminServer | None = None
    ) -> Result[VirtualminAccount, str]:
        """Re-create an EXISTING PRAHO account's domain on a Virtualmin server.

        Disaster recovery (#326): create_virtualmin_account() rejects any domain that
        already has a VirtualminAccount row ("already exists in PRAHO"), so driving a
        rebuild through it fails for 100% of surviving rows — the row being rebuilt is
        the collision. Rebuild must REUSE the existing row, not insert a new one (which
        would also violate the OneToOne `service` and unique `domain`/`virtualmin_username`
        constraints).

        This re-runs the same server-side create-domain workflow used by new provisioning
        (`_execute_domain_creation`) against the existing account: it rotates to a fresh
        password (the old one is unrecoverable after a server loss), optionally retargets
        the server, resets the account to `provisioning`, and drives a new provisioning job.

        The target server is only staged on the instance while the domain is created; it is stored
        (with the account turning active, in one transaction) once the create is verified. A failed
        create leaves the stored server, and the caller's instance, on the node that held the domain.
        """
        previous_server = account.server
        committed = False
        try:
            # account.server is a non-nullable FK, so this is always a real server.
            server = target_server or previous_server

            with transaction.atomic():
                locked_account = VirtualminAccount.objects.select_for_update(of=("self",)).get(pk=account.pk)
                if (
                    locked_account.service_id != account.service_id
                    or locked_account.domain != account.domain
                    or locked_account.virtualmin_username != account.virtualmin_username
                    or locked_account.server_id != previous_server.pk
                ):
                    return Err("Reprovision ownership changed; reload and review the current native binding.")
                if account_has_active_operation(locked_account):
                    return Err(ACCOUNT_BUSY_REFUSAL, retriability=Retriability.RETRIABLE)
                previous_server = locked_account.server
                list(
                    VirtualminServer.objects.select_for_update(of=("self",))
                    .filter(
                        pk__in=(locked_account.server_id, server.pk),
                    )
                    .order_by("pk")
                )
                admitted = self._lock_open_server(server)
                if admitted.is_err():
                    return Err(admitted.unwrap_err(), retriability=retriability_of(admitted))
                server = admitted.unwrap()
                # Rotate password — the pre-loss secret cannot be recovered.
                from apps.infrastructure.node_maintenance_gate import (  # noqa: PLC0415  # Shared server admission
                    maintenance_refusal,
                )

                for node in (
                    VirtualminServer.objects.select_for_update(of=("self",))
                    .filter(pk__in=(previous_server.pk, server.pk))
                    .order_by("pk")
                ):
                    if refusal := maintenance_refusal(node.pk):
                        return Err(refusal, retriability=Retriability.RETRIABLE)
                account.set_password(self._generate_secure_password())  # nosemgrep: unvalidated-password
                account.server = server  # staged: not in update_fields below
                # fsm-bypass: CharField status
                account.status = "provisioning"
                account.status_message = "Reprovisioning from PRAHO (disaster recovery)"
                account.save(update_fields=["encrypted_password", "status", "status_message", "updated_at"])

                job = VirtualminProvisioningJob(
                    operation="create_domain",
                    server=server,
                    account=account,
                    parameters=self._job_parameters(
                        {
                            "domain": account.domain,
                            "username": account.virtualmin_username,
                            "template": account.template_name or DEFAULT_VIRTUALMIN_TEMPLATE,
                            "recovery_seed": account.get_recovery_seed(),
                            "node_connection_identity": connection_identity(server),
                            "creation_intent": creation_intent(account.service_id, purpose="reprovision"),
                            "creation_credential_generation": password_fingerprint(account),
                            "reprovision_source_server_id": str(
                                VirtualminAccount.objects.values_list("server_id", flat=True).get(pk=account.pk)
                            ),
                        }
                    ),
                    correlation_id=f"reprovision_domain_{account.id}",
                )
                job.save()

            provisioning_result = self._execute_domain_creation(account, job)
            if provisioning_result.is_ok():
                # The create already stored the server with the active state, in its own transaction.
                committed = True
                logger.info(f"✅ [VirtualminService] Reprovisioned account {account.domain}")
                return Ok(account)

            error_msg = provisioning_result.unwrap_err()
            logger.error(f"❌ [VirtualminService] Failed to reprovision {account.domain}: {error_msg}")
            account.status = "error"  # fsm-bypass: CharField status
            account.status_message = error_msg
            account.save(update_fields=["status", "status_message", "updated_at"])
            return Err(error_msg, retriability=retriability_of(provisioning_result))

        except ValidationError as e:
            return Err(f"Validation error: {e}")
        except Exception as e:
            logger.exception(f"Unexpected error reprovisioning Virtualmin account: {e}")
            return Err(f"Internal error: {e}")
        finally:
            if not committed:
                account.server = previous_server

    @staticmethod
    def _domain_created(account: VirtualminAccount) -> None:
        """A verified create: say so, and let the account's name follow (ADR-0061 P1.7)."""
        logger.info(f"✅ [VirtualminService] Successfully created domain {account.domain}")
        on_account_ready(account)

    def _prepare_creation(
        self, account: VirtualminAccount, job: VirtualminProvisioningJob, *, retry: bool
    ) -> Err[str] | None:
        account.server.refresh_from_db(fields=["is_draining"])
        if account.server.is_draining:
            job.mark_failed("Target server is draining", retriability=Retriability.RETRIABLE)
            return Err("Target server is draining", retriability=Retriability.RETRIABLE)
        from apps.infrastructure.node_maintenance_gate import begin_account_job  # noqa: PLC0415  # Native admission

        capability_refusal = destination_refusal(account.server)
        if refusal := capability_refusal or begin_account_job(account, job, preserve_claim=retry):
            retriability = Retriability.NOT_RETRIABLE if capability_refusal else Retriability.RETRIABLE
            return self._creation_refusal(account, job, refusal, retry=retry, retriability=retriability)
        if job.hosting_limit_application_id is None:
            self._apply_default_quotas(account)
        return None

    @staticmethod
    def _creation_refusal(
        account: VirtualminAccount,
        job: VirtualminProvisioningJob,
        refusal: str,
        *,
        retry: bool,
        retriability: Retriability,
    ) -> Err[str]:
        if retry:
            with transaction.atomic():
                VirtualminAccount.objects.select_for_update(of=("self",)).get(pk=account.pk)
                current = VirtualminProvisioningJob.objects.select_for_update(of=("self",)).get(pk=job.pk)
                if (
                    current.status == job.status == "running"
                    and current.claimed_at == job.claimed_at
                    and current.started_at == job.started_at
                    and current.account_id == job.account_id
                    and current.server_id == job.server_id
                    and current.operation == job.operation
                ):
                    current.mark_failed(refusal, retriability=retriability)
        else:
            job.mark_failed(refusal, retriability=retriability)
        return Err(refusal, retriability=retriability)

    def _creation_dispatch_refusal(
        self,
        account: VirtualminAccount,
        job: VirtualminProvisioningJob,
        *,
        retry: bool,
        before_create: Callable[[], Err[str] | None] | None,
    ) -> Err[str] | None:
        target = lock_create_retry_node(account, job)
        if target.is_err():
            return Err(target.unwrap_err())
        if refusal := destination_refusal(target.unwrap()):
            return self._creation_refusal(
                account,
                job,
                refusal,
                retry=retry,
                retriability=Retriability.NOT_RETRIABLE,
            )
        # The original account/service/generation callback is the final DB check.
        if before_create is not None and (creation_refusal := before_create()) is not None:
            return creation_refusal
        from .hosting_parent_limits import mark_parent_limits_issued  # noqa: PLC0415

        if not mark_parent_limits_issued(job):
            return self._creation_refusal(
                account,
                job,
                "The native create no longer owns its resource dispatch claim.",
                retry=retry,
                retriability=Retriability.NOT_RETRIABLE,
            )
        return None

    @staticmethod
    def _creation_parameters(account: VirtualminAccount, job: VirtualminProvisioningJob) -> dict[str, Any]:
        params = create_domain_params(
            domain=account.domain,
            username=account.virtualmin_username,
            password=account.get_password(),
            template=account.template_name,
            recovery_seed=account.get_recovery_seed(),
            disk_quota_mb=account.effective_disk_quota_mb
            if account.effective_disk_quota_mb is not None
            else account.disk_quota_mb,
            bandwidth_quota_mb=account.bandwidth_quota_mb,
        )
        if job.hosting_limit_application_id is not None:
            from .hosting_limit_policy import effective_disk_limit  # noqa: PLC0415
            from .hosting_limit_review import reviewed_job_application  # noqa: PLC0415

            frozen = reviewed_job_application(job)
            params.update(
                quota_parameters(
                    effective_disk_limit(frozen.disk_allowance_mib, extra_mib=frozen.overlay_extra_mib),
                    frozen.bandwidth_allowance_mib,
                )
            )
        return params

    def _execute_domain_creation(  # noqa: PLR0911, PLR0912, PLR0915 -- Verified create, native quota and canonical ownership commit.
        self,
        account: VirtualminAccount,
        job: VirtualminProvisioningJob,
        *,
        before_create: Callable[[], Err[str] | None] | None = None,
        settle_created: Callable[[dict[str, Any]], Result[dict[str, Any], str]] | None = None,
    ) -> Result[dict[str, Any], str]:
        """Execute domain creation on Virtualmin server with validation and rollback"""
        try:
            refusal = self._prepare_creation(account, job, retry=settle_created is not None)
            if refusal is not None:
                return refusal
            gateway = self._get_gateway(account.server)

            # ===============================================================================
            # PHASE 1: PRE-FLIGHT VALIDATION 🚀 (Quick Win)
            # ===============================================================================
            logger.info(f"🔍 [VirtualminService] Pre-flight validation for {account.domain}")

            validation_result = self._validate_provisioning_preconditions(account, gateway, quota_job=job)
            if validation_result.is_err():
                error_msg = validation_result.unwrap_err()
                retriability = retriability_of(validation_result)
                job.mark_failed(f"Validation failed: {error_msg}", retriability=retriability)
                return Err(f"Pre-flight validation failed: {error_msg}", retriability=retriability)

            logger.info(f"✅ [VirtualminService] Pre-flight validation passed for {account.domain}")

            # ===============================================================================
            # PHASE 2: ROLLBACK TRACKING SETUP 🔄
            # ===============================================================================
            rollback_operations: list[dict[str, Any]] = []

            params = self._creation_parameters(account, job)

            provisioning_timeout = get_virtualmin_timeouts()["PROVISIONING_TIMEOUT"]
            refusal = self._creation_dispatch_refusal(
                account,
                job,
                retry=settle_created is not None,
                before_create=before_create,
            )
            if refusal is not None:
                return refusal
            result = gateway.call(
                "create-domain",
                params,
                correlation_id=job.correlation_id,
                timeout_seconds=provisioning_timeout,
            )

            if result.is_ok():
                response = result.unwrap()

                if response.success:
                    from .hosting_limit_execution import ensure_managed_limits, publish_managed_limits  # noqa: PLC0415

                    quotas = ensure_managed_limits(account, parent_job=job, native_server=account.server)
                    if quotas.is_err():
                        job.mark_attention(quotas.unwrap_err(), response.data)
                        return Err(quotas.unwrap_err(), retriability=Retriability.UNKNOWN)
                    if settle_created is not None:
                        # Retry settlement owns its fresh binding/claim checks.
                        # A post-acceptance bookkeeping failure must never delete
                        # the actual resource or replay the creation command.
                        settled = settle_created(response.data)
                        if settled.is_ok():
                            account.refresh_from_db()
                            publish_managed_limits(account)
                        return settled
                    # Track successful domain creation for potential rollback
                    rollback_operations.append(
                        {
                            "operation": "delete-domain",
                            "params": {"domain": account.domain},
                            "description": f"Delete domain {account.domain}",
                        }
                    )

                    try:
                        # One transaction: recovery reads an active account as "already counted",
                        # so the account must never be active without the server's count raised.
                        with transaction.atomic():
                            VirtualminAccount.objects.select_for_update(no_key=True).get(pk=account.pk)
                            # fsm-bypass: CharField status
                            account.status = "active"
                            account.provisioned_at = timezone.now()
                            # "server" is stored here, with the active state: a reprovision stages its
                            # target on the instance and only a verified create may persist it.
                            account.save(update_fields=["status", "provisioned_at", "server", "updated_at"])
                            # The held target receipt becomes current only with this
                            # exact canonical ownership commit, never from a source receipt.
                            account.refresh_from_db(fields=["quota_generation"])
                            publish_managed_limits(account)

                            # Update server stats (track for rollback)
                            old_domain_count = account.server.current_domains
                            VirtualminServer.objects.filter(pk=account.server_id).update(
                                current_domains=models.F("current_domains") + 1, updated_at=timezone.now()
                            )
                            account.server.refresh_from_db(fields=["current_domains"])

                            # Recorded for a later rollback of the completed job only. If this block
                            # fails, the transaction has already undone the increment, so the error
                            # path below must not revert it a second time.
                            completed_rollback = [
                                *rollback_operations,
                                {
                                    "operation": "revert_server_stats",
                                    "params": {"domain_count": old_domain_count},
                                    "description": f"Revert server domain count to {old_domain_count}",
                                },
                            ]

                            job.mark_completed(response.data, completed_rollback)

                        self._domain_created(account)
                        return Ok(response.data)

                    except Exception as db_error:
                        # Database update failed - rollback Virtualmin domain creation
                        logger.error(f"🔥 [VirtualminService] Database update failed for {account.domain}: {db_error}")
                        rollback_status, rollback_details = self._execute_rollback(
                            rollback_operations, gateway, account
                        )
                        if rollback_status == "failed":
                            logger.error(f"🚨 [VirtualminService] CRITICAL: Rollback failed for {account.domain}")

                        job.mark_failed(
                            f"Database update failed: {db_error}",
                            rollback_executed=True,
                            rollback_status=rollback_status,
                            rollback_details=rollback_details,
                        )
                        return Err(f"Provisioning failed during database update: {db_error}")

                else:
                    error_msg = response.data.get("error", "Domain creation failed")
                    retriability = classify_virtualmin_application_error(response)
                    job.mark_failed(error_msg, response.data, retriability=retriability)
                    return Err(error_msg, retriability=retriability)

            else:
                error = result.unwrap_err()
                error_msg = str(error)
                job.mark_failed(error_msg, retriability=retriability_of(result))
                return Err(error_msg, retriability=retriability_of(result))

        except Exception as e:
            logger.exception(f"Error executing domain creation: {e}")
            job.mark_failed(str(e))
            return Err(str(e))

    def _apply_default_quotas(self, account: VirtualminAccount) -> None:
        """Load the creation-time assignment; never resolve a live catalog/default here."""
        from .hosting_limit_models import ServiceHostingLimits  # noqa: PLC0415 -- Policy boundary.
        from .hosting_limit_policy import effective_disk_limit  # noqa: PLC0415 -- Policy boundary.

        limits = ServiceHostingLimits.objects.using(account._state.db).filter(service_id=account.service_id).first()
        if limits is None:
            # Imported historical accounts have no authority to change their native caps.
            return
        fields: list[str] = []
        if account.disk_quota_mb is None:
            account.disk_quota_mb = limits.disk_allowance_mib
            fields.append("disk_quota_mb")
        if account.effective_disk_quota_mb is None:
            account.effective_disk_quota_mb = (
                effective_disk_limit(account.disk_quota_mb)
                if account.disk_quota_mb == limits.disk_allowance_mib
                else account.disk_quota_mb
            )
            fields.append("effective_disk_quota_mb")
        if account.bandwidth_quota_mb is None:
            account.bandwidth_quota_mb = limits.bandwidth_allowance_mib
            fields.append("bandwidth_quota_mb")
        if fields:
            account.save(update_fields=[*fields, "updated_at"])

    @staticmethod
    def _available_disk_mb(server_data: object) -> int | None:
        """Virtualmin info's disk_free text value is bytes, not MiB."""
        if not isinstance(server_data, dict):
            return None
        output = server_data.get("output")
        if isinstance(output, str):
            match = re.search(r"(?m)^disk_free:[ \t]*(\d+)[ \t]*$", output)
            if match:
                return int(match.group(1)) // (1024 * 1024)
        # Retain compatibility with already-normalized callers.
        available = server_data.get("available_disk_mb")
        if isinstance(available, int) and not isinstance(available, bool) and available >= 0:
            return available
        return None

    def _check_server_capacity(
        self, account: VirtualminAccount, health_result: Result[dict[str, object], str]
    ) -> Result[None, str]:
        """Check server capacity and disk space."""
        # Check server capacity
        if account.server.max_domains and account.server.current_domains >= account.server.max_domains:
            return Err(
                f"Server {account.server.name} at capacity ({account.server.current_domains}/{account.server.max_domains} domains)"
            )

        # Check disk space if quota specified
        requested_mb = (
            account.effective_disk_quota_mb if account.effective_disk_quota_mb is not None else account.disk_quota_mb
        )
        if requested_mb and health_result.is_ok():
            server_info = health_result.unwrap()
            # test_connection() wraps the info response under "data".
            server_data = server_info.get("data", server_info)
            available_mb = self._available_disk_mb(server_data)
            if available_mb is None:
                logger.warning(
                    "⚠️ [VirtualminService] Server %s free disk space is unknown; skipping disk capacity check",
                    account.server.hostname,
                )
            elif available_mb < requested_mb:
                return Err(
                    _("Insufficient disk space: %(available)sMB available, %(requested)sMB requested")
                    % {"available": available_mb, "requested": requested_mb}
                )

        return Ok(None)

    def _check_domain_conflicts(self, account: VirtualminAccount, gateway: VirtualminGateway) -> Result[None, str]:
        """Check for domain and username conflicts via the normalized listing.

        The raw response payloads never carried 'domains'/'users' keys (#325),
        so the listing is normalized. A listing FAILURE fails closed with its
        retriability (#253/#254) — a transient error retries rather than
        proceeding blind to a possible conflict.
        """
        listing = gateway.list_domains_with_owners()
        if listing.is_err():
            return Err(
                f"Domain conflict check failed: {listing.unwrap_err()}",
                retriability=retriability_of(listing),
            )

        domains = listing.unwrap()
        if any(d["domain"] == account.domain for d in domains):
            return Err(f"Domain {account.domain} already exists on server", retriability=Retriability.NOT_RETRIABLE)
        if any(d["username"] and d["username"] == account.virtualmin_username for d in domains):
            return Err(
                f"Username {account.virtualmin_username} already exists on server",
                retriability=Retriability.NOT_RETRIABLE,
            )

        return Ok(None)

    def _check_template_availability(self, account: VirtualminAccount, gateway: VirtualminGateway) -> Result[None, str]:
        """Check the required template exists via the normalized listing (#325),
        failing closed with retriability so a transient listing error retries
        rather than passing the gate blind (#253/#254)."""
        template_check = gateway.list_templates()
        if template_check.is_err():
            return Err(
                f"Template availability check failed: {template_check.unwrap_err()}",
                retriability=retriability_of(template_check),
            )
        if account.template_name not in template_check.unwrap():
            return Err(
                f"Template {account.template_name} not found on server",
                retriability=Retriability.NOT_RETRIABLE,
            )

        return Ok(None)

    def _validate_provisioning_preconditions(  # Pre-flight gate: one exit per precondition  # noqa: PLR0911  # Complexity: cohesive workflow
        self,
        account: VirtualminAccount,
        gateway: VirtualminGateway,
        *,
        quota_job: VirtualminProvisioningJob | None = None,
    ) -> Result[bool, str]:
        """
        Validate all preconditions before provisioning (Phase 1 - Quick Win).

        Checks:
        - Server capacity and health
        - Domain availability
        - Resource limits
        - Template existence
        - User conflicts
        """
        try:
            # 1. Server connectivity (the gateway is already bound to the
            # target server; no status side effects, unlike the management
            # service's health_check_server)
            health_result = gateway.test_connection()
            if health_result.is_err():
                return Err(
                    f"Server health check failed: {health_result.unwrap_err()}",
                    retriability=retriability_of(health_result),
                )
            if health_result.unwrap().get("healthy") is not True:
                # Require AFFIRMATIVE health (#325): a missing/malformed/non-bool
                # "healthy" is not proof of health, so it blocks provisioning.
                return Err(f"Server reported unhealthy: {health_result.unwrap()}")

            # 2. Check server capacity and disk space
            capacity_result = self._check_server_capacity(account, health_result)
            if capacity_result.is_err():
                return Err(capacity_result.unwrap_err(), retriability=retriability_of(capacity_result))

            # 3. Check domain and username conflicts
            conflict_result = self._check_domain_conflicts(account, gateway)
            if conflict_result.is_err():
                return Err(conflict_result.unwrap_err(), retriability=retriability_of(conflict_result))

            # 4. Check template availability
            template_result = self._check_template_availability(account, gateway)
            if template_result.is_err():
                return Err(template_result.unwrap_err(), retriability=retriability_of(template_result))

            if quota_job is not None:
                from .hosting_limit_execution import reserve_managed_creation  # noqa: PLC0415 -- Shared capacity lane.

                server_info = health_result.unwrap()
                available_mib = self._available_disk_mb(server_info.get("data", server_info))
                reservation = reserve_managed_creation(
                    account,
                    quota_job,
                    None if available_mib is None else available_mib * 1024**2,
                )
                if reservation.is_err():
                    return Err(reservation.unwrap_err(), retriability=Retriability.NOT_RETRIABLE)

            logger.info(f"✅ [VirtualminService] All preconditions validated for {account.domain}")
            return Ok(True)

        except Exception as e:
            logger.exception(f"🔥 [VirtualminService] Validation error for {account.domain}: {e}")
            return Err(f"Validation error: {e}")

    def _execute_rollback(  # Complexity: Virtualmin workflow  # Complexity: multi-step business logic  # noqa: C901, PLR0912, PLR0915  # Complexity: cohesive workflow
        self,
        rollback_operations: list[dict[str, Any]],
        gateway: VirtualminGateway,
        account: VirtualminAccount,
        *,
        previous_status: str | None = None,
        previous_status_message: str = "",
    ) -> tuple[str, dict[str, Any]]:
        """
        Execute rollback operations in reverse order (Phase 2).

        Args:
            rollback_operations: List of operations to rollback
            gateway: Virtualmin gateway for API calls
            account: Account being rolled back

        Returns:
            Tuple of (rollback_status, rollback_details) where:
            - rollback_status: "success", "partial", or "failed"
            - rollback_details: Dict with operation results
        """
        rollback_details: dict[str, Any] = {
            "operations": [],
            "total_operations": len(rollback_operations),
            "successful_operations": 0,
            "failed_operations": 0,
        }

        try:
            logger.warning(f"⚠️ [VirtualminService] Starting rollback for {account.domain}")

            # Execute rollback operations in reverse order
            for operation in reversed(rollback_operations):
                op_result = {"operation": operation["operation"], "description": operation.get("description", "")}
                try:
                    if operation["operation"] == "delete-domain":
                        result = gateway.call("delete-domain", operation["params"])
                        if result.is_err() or not result.unwrap().success:
                            logger.error(f"🔥 [VirtualminService] Failed to rollback domain deletion: {operation}")
                            op_result["status"] = "failed"
                            op_result["error"] = str(result.unwrap_err()) if result.is_err() else "API returned failure"
                            rollback_details["failed_operations"] += 1
                        else:
                            op_result["status"] = "success"
                            rollback_details["successful_operations"] += 1

                    elif operation["operation"] == "revert_server_stats":
                        # Relative decrement, not the snapshotted absolute — an
                        # absolute write would destroy a concurrent creator's
                        # F() increment (lost update).
                        VirtualminServer.objects.filter(pk=account.server_id).update(
                            current_domains=Greatest(models.F("current_domains") - 1, 0),
                            updated_at=timezone.now(),
                        )
                        account.server.refresh_from_db(fields=["current_domains"])
                        op_result["status"] = "success"
                        rollback_details["successful_operations"] += 1

                    elif operation["operation"] == "enable-domain":
                        # Rollback for suspend operation - re-enable the domain
                        result = gateway.call("enable-domain", operation["params"])
                        if result.is_err() or not result.unwrap().success:
                            op_result["status"] = "failed"
                            op_result["error"] = str(result.unwrap_err()) if result.is_err() else "API returned failure"
                            rollback_details["failed_operations"] += 1
                        else:
                            op_result["status"] = "success"
                            rollback_details["successful_operations"] += 1

                    elif operation["operation"] == "disable-domain":
                        # Rollback for unsuspend operation - re-disable the domain
                        result = gateway.call("disable-domain", operation["params"])
                        if result.is_err() or not result.unwrap().success:
                            op_result["status"] = "failed"
                            op_result["error"] = str(result.unwrap_err()) if result.is_err() else "API returned failure"
                            rollback_details["failed_operations"] += 1
                        else:
                            op_result["status"] = "success"
                            rollback_details["successful_operations"] += 1

                    else:
                        op_result["status"] = "skipped"
                        op_result["reason"] = f"Unknown operation type: {operation['operation']}"

                    logger.info(
                        f"✅ [VirtualminService] Rolled back: {operation.get('description', operation['operation'])}"
                    )

                except Exception as op_error:
                    logger.error(
                        f"🔥 [VirtualminService] Rollback operation failed: {operation.get('description', '')} - {op_error}"
                    )
                    op_result["status"] = "failed"
                    op_result["error"] = str(op_error)
                    rollback_details["failed_operations"] += 1
                    # Continue with other rollback operations even if one fails

                rollback_details["operations"].append(op_result)

            # Determine overall rollback status before restoring lifecycle state.
            if rollback_details["failed_operations"] == 0:
                rollback_status = "success"
                logger.warning(f"⚠️ [VirtualminService] Rollback completed successfully for {account.domain}")
            elif rollback_details["successful_operations"] > 0:
                rollback_status = "partial"
                logger.warning(f"⚠️ [VirtualminService] Rollback partially completed for {account.domain}")
            else:
                rollback_status = "failed"
                logger.error(f"🚨 [VirtualminService] Rollback failed for {account.domain}")

            restored = rollback_status == "success" and previous_status is not None
            # fsm-bypass: CharField status
            account.status = previous_status if restored and previous_status is not None else "error"
            account.status_message = (
                previous_status_message if restored else str(_("Provisioning failed - rollback executed"))
            )
            account.save(update_fields=["status", "status_message", "updated_at"])
            return rollback_status, rollback_details

        except Exception as e:
            logger.exception(f"🚨 [VirtualminService] CRITICAL: Rollback execution failed for {account.domain}: {e}")
            rollback_details["error"] = str(e)
            return "failed", rollback_details

    def suspend_account(  # Complexity: multi-step workflow with rollback + cache self-heal + migration lock  # noqa: PLR0911, PLR0912, PLR0915  # Complexity: cohesive workflow
        self, account: VirtualminAccount, reason: str = ""
    ) -> Result[bool, str]:  # Complexity: Virtualmin workflow  # Complexity: multi-step business logic
        """
        Suspend Virtualmin account with idempotency and rollback support.

        Args:
            account: VirtualminAccount to suspend
            reason: Reason for suspension

        Returns:
            Result with success status or error message

        Idempotency:
            Safe to retry - will return success if already suspended.

        Rollback:
            If database update fails after API call succeeds, will attempt
            to re-enable the domain in Virtualmin.
        """
        if account_has_active_migration(account):
            logger.info("✅ [VirtualminService] Migration lock blocks suspension: %s", account.pk)
            return Err("Account has an active migration")
        idempotency_key: str | None = None
        try:
            # Idempotency check - already suspended
            if account.status == "suspended":
                logger.info(f"⏭️ [VirtualminService] Account {account.domain} already suspended (idempotent)")
                return Ok(True)

            # Generate idempotency key for this operation
            idempotency_key = IdempotencyManager.generate_key(
                str(account.id), "suspend_account", {"domain": account.domain, "reason": reason}
            )

            # Check if operation is already in progress
            is_new, existing_result = IdempotencyManager.check_and_set(idempotency_key)
            if not is_new:
                cached_success = isinstance(existing_result, dict) and existing_result.get("success")
                account.refresh_from_db(fields=["status"])
                if cached_success and account.status == "suspended":
                    logger.info(f"✅ [VirtualminService] Returning cached suspend result for {account.domain}")
                    return Ok(True)
                if cached_success:
                    # Cached success no longer matches reality (flip-flop inside
                    # the TTL) — self-heal: clear and execute for real.
                    _clear_idempotency_key(idempotency_key, operation="suspend", domain=account.domain)
                    is_new, _ = IdempotencyManager.check_and_set(idempotency_key)
                    if not is_new:
                        return Err("Operation already in progress")
                else:
                    logger.warning(f"⚠️ [VirtualminService] Suspend operation already in progress for {account.domain}")
                    return Err("Operation already in progress")

            gateway = self._get_gateway(account.server)

            # Create provisioning job
            job = VirtualminProvisioningJob(
                operation="suspend_domain",
                server=account.server,
                account=account,
                parameters=self._job_parameters({"domain": account.domain, "reason": reason}, soft_limit=True),
                correlation_id=f"suspend_domain_{account.id}",
            )
            from apps.infrastructure.node_maintenance_gate import begin_account_job  # noqa: PLC0415  # Native admission

            if refusal := begin_account_job(account, job):
                _clear_idempotency_key(idempotency_key, operation="suspend", domain=account.domain)
                return Err(refusal, retriability=Retriability.RETRIABLE)

            # Snapshot the lifecycle state before the remote mutation.
            previous_status = account.status
            previous_status_message = account.status_message
            result = gateway.call(
                "disable-domain", domain_state_params(account.domain), correlation_id=job.correlation_id
            )

            if result.is_ok():
                response = result.unwrap()

                if response.success:
                    # Prepare rollback operation in case DB update fails
                    rollback_operations = [
                        {
                            "operation": "enable-domain",
                            "params": domain_state_params(account.domain),
                            "description": f"Re-enable domain {account.domain} if DB update fails",
                        }
                    ]

                    try:
                        with transaction.atomic():
                            account.status = "suspended"  # fsm-bypass: CharField status
                            account.status_message = reason
                            account.save(update_fields=["status", "status_message", "updated_at"])
                            job.mark_completed(response.data)

                        # Mark idempotency as complete
                        IdempotencyManager.complete(idempotency_key, {"success": True})

                        logger.info(f"✅ [VirtualminService] Suspended account {account.domain}")
                        return Ok(True)

                    except Exception as db_error:
                        # Database update failed - rollback the API operation
                        logger.error(
                            f"🔥 [VirtualminService] DB update failed for suspend {account.domain}: {db_error}"
                        )
                        with transaction.atomic():
                            rollback_status, rollback_details = self._execute_rollback(
                                rollback_operations,
                                gateway,
                                account,
                                previous_status=previous_status,
                                previous_status_message=previous_status_message,
                            )
                            job.mark_failed(
                                f"Database update failed: {db_error}",
                                rollback_executed=True,
                                rollback_status=rollback_status,
                                rollback_details=rollback_details,
                            )
                        _clear_idempotency_key(idempotency_key, operation="suspend", domain=account.domain)
                        return Err(f"Suspension failed during database update: {db_error}")
                else:
                    error_msg = response.data.get("error", "Suspension failed")
                    retriability = classify_virtualmin_application_error(response)
                    job.mark_failed(error_msg, response.data, retriability=retriability)
                    _clear_idempotency_key(idempotency_key, operation="suspend", domain=account.domain)
                    return Err(error_msg, retriability=retriability)

            else:
                error = result.unwrap_err()
                error_msg = str(error)
                job.mark_failed(error_msg, retriability=retriability_of(result))
                _clear_idempotency_key(idempotency_key, operation="suspend", domain=account.domain)
                return Err(error_msg, retriability=retriability_of(result))

        except Exception as e:
            _clear_idempotency_key(idempotency_key, operation="suspend", domain=account.domain)
            logger.exception(f"Error suspending account {account.domain}: {e}")
            return Err(str(e))

    def unsuspend_account(  # Complexity: multi-step workflow with rollback + cache self-heal + migration lock  # noqa: PLR0911, PLR0912, PLR0915  # Complexity: cohesive workflow
        self, account: VirtualminAccount
    ) -> Result[bool, str]:  # Complexity: Virtualmin workflow  # Complexity: multi-step business logic
        """
        Unsuspend (reactivate) Virtualmin account with idempotency and rollback support.

        Args:
            account: VirtualminAccount to unsuspend

        Returns:
            Result with success status or error message

        Idempotency:
            Safe to retry - will return success if already active.

        Rollback:
            If database update fails after API call succeeds, will attempt
            to re-disable the domain in Virtualmin.
        """
        if account_has_active_migration(account):
            logger.info("✅ [VirtualminService] Migration lock blocks activation: %s", account.pk)
            return Err("Account has an active migration")
        idempotency_key: str | None = None
        try:
            # Idempotency check - already active
            if account.status == "active":
                logger.info(f"⏭️ [VirtualminService] Account {account.domain} already active (idempotent)")
                return Ok(True)

            # Generate idempotency key for this operation
            idempotency_key = IdempotencyManager.generate_key(
                str(account.id), "unsuspend_account", {"domain": account.domain}
            )

            # Check if operation is already in progress
            is_new, existing_result = IdempotencyManager.check_and_set(idempotency_key)
            if not is_new:
                cached_success = isinstance(existing_result, dict) and existing_result.get("success")
                account.refresh_from_db(fields=["status"])
                if cached_success and account.status == "active":
                    logger.info(f"✅ [VirtualminService] Returning cached unsuspend result for {account.domain}")
                    return Ok(True)
                if cached_success:
                    _clear_idempotency_key(idempotency_key, operation="unsuspend", domain=account.domain)
                    is_new, _ = IdempotencyManager.check_and_set(idempotency_key)
                    if not is_new:
                        return Err("Operation already in progress")
                else:
                    logger.warning(
                        f"⚠️ [VirtualminService] Unsuspend operation already in progress for {account.domain}"
                    )
                    return Err("Operation already in progress")

            gateway = self._get_gateway(account.server)

            # Create provisioning job
            job = VirtualminProvisioningJob(
                operation="unsuspend_domain",
                server=account.server,
                account=account,
                parameters=self._job_parameters({"domain": account.domain}, soft_limit=True),
                correlation_id=f"unsuspend_domain_{account.id}",
            )
            from apps.infrastructure.node_maintenance_gate import begin_account_job  # noqa: PLC0415  # Native admission

            if refusal := begin_account_job(account, job):
                _clear_idempotency_key(idempotency_key, operation="unsuspend", domain=account.domain)
                return Err(refusal, retriability=Retriability.RETRIABLE)

            # Snapshot the lifecycle state before the remote mutation.
            previous_status = account.status
            previous_status_message = account.status_message
            result = gateway.call(
                "enable-domain", domain_state_params(account.domain), correlation_id=job.correlation_id
            )

            if result.is_ok():
                response = result.unwrap()

                if response.success:
                    # Prepare rollback operation in case DB update fails
                    rollback_operations = [
                        {
                            "operation": "disable-domain",
                            "params": domain_state_params(account.domain),
                            "description": f"Re-disable domain {account.domain} if DB update fails",
                        }
                    ]

                    try:
                        with transaction.atomic():
                            # fsm-bypass: CharField status
                            account.status = "active"
                            account.status_message = ""
                            account.save(update_fields=["status", "status_message", "updated_at"])
                            job.mark_completed(response.data)

                        # Mark idempotency as complete
                        IdempotencyManager.complete(idempotency_key, {"success": True})

                        logger.info(f"✅ [VirtualminService] Unsuspended account {account.domain}")
                        return Ok(True)

                    except Exception as db_error:
                        # Database update failed - rollback the API operation
                        logger.error(
                            f"🔥 [VirtualminService] DB update failed for unsuspend {account.domain}: {db_error}"
                        )
                        with transaction.atomic():
                            rollback_status, rollback_details = self._execute_rollback(
                                rollback_operations,
                                gateway,
                                account,
                                previous_status=previous_status,
                                previous_status_message=previous_status_message,
                            )
                            job.mark_failed(
                                f"Database update failed: {db_error}",
                                rollback_executed=True,
                                rollback_status=rollback_status,
                                rollback_details=rollback_details,
                            )
                        _clear_idempotency_key(idempotency_key, operation="unsuspend", domain=account.domain)
                        return Err(f"Unsuspension failed during database update: {db_error}")
                else:
                    error_msg = response.data.get("error", "Unsuspension failed")
                    retriability = classify_virtualmin_application_error(response)
                    job.mark_failed(error_msg, response.data, retriability=retriability)
                    _clear_idempotency_key(idempotency_key, operation="unsuspend", domain=account.domain)
                    return Err(error_msg, retriability=retriability)

            else:
                error = result.unwrap_err()
                error_msg = str(error)
                job.mark_failed(error_msg, retriability=retriability_of(result))
                _clear_idempotency_key(idempotency_key, operation="unsuspend", domain=account.domain)
                return Err(error_msg, retriability=retriability_of(result))

        except Exception as e:
            _clear_idempotency_key(idempotency_key, operation="unsuspend", domain=account.domain)
            logger.exception(f"Error unsuspending account {account.domain}: {e}")
            return Err(str(e))

    @staticmethod
    def _delete_refusal(account: VirtualminAccount) -> Result[bool, str] | None:
        """The deletion preconditions that depend only on the account row, or None to proceed.

        Evaluated twice: cheaply before the idempotency key is taken, and again on the
        row-locked account, so a status change in between cannot slip past.
        """
        # ⚠️ SAFETY CHECK: Prevent deletion of protected accounts
        if account.protected_from_deletion:
            error_msg = f"Account {account.domain} is protected from deletion. Disable protection first."
            logger.warning(f"🛡️ [VirtualminService] {error_msg}")
            return Err(error_msg)

        # Idempotency check - already terminated
        if account.status == "terminated":
            logger.info(f"⏭️ [VirtualminService] Account {account.domain} already terminated (idempotent)")
            return Ok(True)

        # Additional safety check - only allow deletion of terminated/error accounts
        # Note: We check for 'error' status separately since terminated is handled above
        if account.status not in ["error"]:
            error_msg = f"Account {account.domain} must be terminated or in error state before deletion (current: {account.status})"
            logger.warning(f"🛡️ [VirtualminService] {error_msg}")
            return Err(error_msg)
        return None

    def delete_account(  # noqa: C901, PLR0911, PLR0912, PLR0915  # Keep deletion admission and its durable job in one workflow.
        self, account: VirtualminAccount
    ) -> Result[bool, str]:  # Complexity: Virtualmin workflow  # Complexity: multi-step business logic
        """
        Delete Virtualmin account permanently with idempotency and rollback support.

        Args:
            account: VirtualminAccount to delete

        Returns:
            Result with success status or error message

        Idempotency:
            Safe to retry - will return success if already terminated.

        Rollback:
            If database update fails after API call succeeds, logs the inconsistency
            (domain deleted in Virtualmin but not marked as such in DB).
            Note: Domain deletion cannot be rolled back - data loss is irreversible.
        """
        if account_has_active_migration(account):
            logger.info("✅ [VirtualminService] Migration lock blocks deletion: %s", account.pk)
            return Err("Account has an active migration")

        refusal = self._delete_refusal(account)
        if refusal is not None:
            return refusal

        idempotency_key: str | None = None
        try:
            # Generate idempotency key for this operation
            idempotency_key = IdempotencyManager.generate_key(
                str(account.id), "delete_account", {"domain": account.domain}
            )

            # Check if operation is already in progress
            is_new, existing_result = IdempotencyManager.check_and_set(idempotency_key)
            if not is_new:
                if isinstance(existing_result, dict) and existing_result.get("success"):
                    logger.info(f"✅ [VirtualminService] Returning cached delete result for {account.domain}")
                    return Ok(True)
                else:
                    logger.warning(f"⚠️ [VirtualminService] Delete operation already in progress for {account.domain}")
                    return Err("Operation already in progress")

            # Admission joins the account exclusion: the row lock serialises it against
            # backup/restore/migration admission, and the job row is created inside the
            # same transaction so no competing operation can slip in before it exists.
            job: VirtualminProvisioningJob | None = None
            with transaction.atomic():
                VirtualminAccount.objects.select_for_update().get(pk=account.pk)
                account.refresh_from_db()  # decisions below use the locked, current row
                VirtualminServer.objects.select_for_update(of=("self",)).get(pk=account.server_id)
                from apps.infrastructure.node_maintenance_gate import (  # noqa: PLC0415  # Native admission
                    maintenance_refusal,
                    native_account_observation_refusal,
                )

                if node_refusal := maintenance_refusal(account.server_id) or native_account_observation_refusal(
                    account.pk
                ):
                    _clear_idempotency_key(idempotency_key, operation="delete", domain=account.domain)
                    return Err(node_refusal, retriability=Retriability.RETRIABLE)
                admission_refusal: Result[bool, str] | None
                if account_has_active_operation(account):
                    admission_refusal = Err(ACCOUNT_BUSY_REFUSAL)
                else:
                    admission_refusal = self._delete_refusal(account)
                if admission_refusal is None:
                    invalidate_chain(account)  # the domain and its snapshot are about to go
                    job = VirtualminProvisioningJob(
                        operation="delete_domain",
                        server=account.server,
                        account=account,
                        parameters=self._job_parameters({"domain": account.domain}),
                        correlation_id=f"delete_domain_{account.id}",
                    )
                    job.save()
            if admission_refusal is not None or job is None:
                _clear_idempotency_key(idempotency_key, operation="delete", domain=account.domain)
                return admission_refusal if admission_refusal is not None else Err("Delete admission failed")

            gateway = self._get_gateway(account.server)
            job.mark_started()

            # Make API call
            result = gateway.call("delete-domain", {"domain": account.domain}, correlation_id=job.correlation_id)

            if result.is_ok():
                response = result.unwrap()

                if response.success:
                    try:
                        # One transaction: the count, the terminated status and the job move
                        # together, so a crash between them can never leave the domain uncounted
                        # while the account still looks live for a retry to decrement again.
                        with transaction.atomic():
                            VirtualminServer.objects.filter(pk=account.server_id, current_domains__gt=0).update(
                                current_domains=models.F("current_domains") - 1, updated_at=timezone.now()
                            )
                            account.server.refresh_from_db(fields=["current_domains"])

                            # Mark account as terminated (don't delete for audit trail)
                            account.status = "terminated"  # fsm-bypass: CharField status
                            account.save(update_fields=["status", "updated_at"])

                            job.mark_completed(response.data)

                        # Mark idempotency as complete
                        IdempotencyManager.complete(idempotency_key, {"success": True})

                        logger.info(f"✅ [VirtualminService] Deleted account {account.domain}")
                        return Ok(True)

                    except Exception as db_error:
                        # Database update failed - domain is already deleted in Virtualmin
                        # This is a critical inconsistency - log it but can't rollback deletion
                        logger.error(
                            f"🚨 [VirtualminService] CRITICAL: DB update failed after domain deletion for {account.domain}: {db_error}"
                        )

                        # Track the rollback attempt (even though we can't restore the domain)
                        rollback_details = {
                            "operations": [
                                {
                                    "operation": "restore-domain",
                                    "status": "not_possible",
                                    "description": "Domain deletion cannot be rolled back - data is irreversibly lost",
                                }
                            ],
                            "total_operations": 1,
                            "successful_operations": 0,
                            "failed_operations": 1,
                            "critical_note": f"Domain {account.domain} deleted in Virtualmin but DB not updated",
                        }

                        job.mark_failed(
                            f"Database update failed after domain deletion: {db_error}",
                            rollback_executed=True,
                            rollback_status="failed",
                            rollback_details=rollback_details,
                        )
                        _clear_idempotency_key(idempotency_key, operation="delete", domain=account.domain)

                        return Err(
                            f"Deletion failed during database update (CRITICAL: domain already deleted): {db_error}"
                        )

                else:
                    error_msg = response.data.get("error", "Deletion failed")
                    retriability = classify_virtualmin_application_error(response)
                    job.settle_failure(error_msg, response.data, retriability=retriability)
                    _clear_idempotency_key(idempotency_key, operation="delete", domain=account.domain)
                    return Err(error_msg, retriability=retriability)

            else:
                error = result.unwrap_err()
                error_msg = str(error)
                job.settle_failure(error_msg, retriability=retriability_of(result))
                _clear_idempotency_key(idempotency_key, operation="delete", domain=account.domain)
                return Err(error_msg, retriability=retriability_of(result))

        except Exception as e:
            _clear_idempotency_key(idempotency_key, operation="delete", domain=account.domain)
            logger.exception(f"Error deleting account {account.domain}: {e}")
            return Err(str(e))

    def retry_job(self, job: VirtualminProvisioningJob) -> Result[bool, str] | Result[MigrationResumeOutcome, str]:  # noqa: PLR0911  # Dispatch existing operation-specific owners.
        """
        Re-run a failed job on its EXISTING account and job rows.

        A fresh create is a structural no-op for create_domain (the account row
        survives failure with status='error', so the existing-account check
        early-exits), and calling the public suspend/unsuspend/delete methods
        would mint a NEW job each — exponential fan-out under the retry sweep.
        """
        account = job.account
        if account is None:
            return Err("Job has no account to retry against")

        if job.operation == "create_domain":
            return self._retry_create_domain(account, job)
        if job.operation in ("suspend_domain", "unsuspend_domain", "delete_domain"):
            if OFF_SOURCE_KEY in (job.parameters or {}):
                claim = off_claim(job)
                if claim is None:
                    return Err("Receipt-bound OFF delivery no longer owns its claim")
                try:
                    return self._execute_revoked_create_off(account, job, claim)
                except Exception:
                    # The native OFF may have succeeded. Never compensate by
                    # enabling/deleting or replaying an unknown command.
                    settle_off(
                        job,
                        claim,
                        phase="uncertain",
                        message="Receipt-bound OFF settlement failed; verify native state before resolution",
                    )
                    return Err("Receipt-bound OFF needs operator verification")
            return self._execute_lifecycle_operation(account, job)
        if job.operation == "migrate_domain":
            from .virtualmin_migration_service import resume_migration  # noqa: PLC0415  # Circular

            return resume_migration(job)
        return Err(f"Unsupported retry operation '{job.operation}'")

    def _retry_create_domain(self, account: VirtualminAccount, job: VirtualminProvisioningJob) -> Result[bool, str]:  # noqa: PLR0911  # Complexity: cohesive workflow
        """
        Convergent create retry: a timed-out-but-remotely-successful
        create-domain must finalize local state, never re-create or rotate
        credentials; an absent remote domain re-runs creation on the same rows.
        """
        binding = retry_binding(account, job)
        if binding is None:
            return Err("Original create target/account binding changed")
        account.server = job.server
        account.server.refresh_from_db(fields=["is_draining"])
        if account.server.is_draining:
            job.mark_failed("Target server is draining", retriability=Retriability.RETRIABLE)
            return Err("Target server is draining", retriability=Retriability.RETRIABLE)
        target = lock_create_retry_node(account, job)
        if target.is_err():
            return Err(target.unwrap_err())
        account.server = target.unwrap()
        gateway = self._get_gateway(account.server)
        owner_result = gateway.get_domain_owner(account.domain)
        if not binding_current(binding, job.pk):
            park_changed_binding(
                binding,
                job.pk,
                native_outcome="adopted"
                if owner_result.is_ok() and owner_result.unwrap() == binding.owner
                else "unknown",
            )
            return Err("Create retry lost its original account/claim binding during observation")
        if owner_result.is_err():
            # An unreachable probe is NOT evidence of absence — creating here
            # could double-create. Keep the job failed for a later attempt.
            job.mark_attention("Original create ownership observation unavailable; no absence or mutation authority")
            return Err(f"Ownership probe failed: {owner_result.unwrap_err()}")

        owner = owner_result.unwrap()
        if owner == "":
            # Present but owner indeterminate: never adopt blindly, never
            # re-create over it — retry later.
            job.mark_attention("Original create ownership is indeterminate; native review required")
            return Err(f"Remote domain {account.domain} exists but ownership is indeterminate")
        if owner is not None and owner != account.virtualmin_username:
            # Same name, different owner: never adopt. Terminal conflict.
            job.mark_failed(f"Remote domain {account.domain} is owned by '{owner}' — manual resolution required")
            VirtualminProvisioningJob.terminalize(job.pk)
            return Err(f"Remote domain {account.domain} owned by another account")

        if owner is not None:
            # Remote domain exists on OUR server for OUR account row: the
            # original create succeeded past the response. Finalize in place.
            settled = self._settle_observed_create(account, job, binding)
            if settled.is_err():
                return Err(settled.unwrap_err())
            logger.info(f"✅ [VirtualminService] Retry converged existing remote domain {account.domain}")
            return self._finish_create_retry(account, job, native_outcome="adopted")

        refusal = self._create_retry_refusal(account, job)
        if refusal is not None:
            return refusal

        creation_result = self._execute_domain_creation(
            account,
            job,
            before_create=lambda: self._retry_dispatch_refusal(account, job, binding),
            settle_created=lambda data: settle_retry_created(binding, job.pk, data, native_outcome="created"),
        )
        if creation_result.is_err():
            return Err(creation_result.unwrap_err())
        return self._finish_create_retry(account, job, native_outcome="created")

    @staticmethod
    def _settle_observed_create(
        account: VirtualminAccount,
        job: VirtualminProvisioningJob,
        binding: CreateRetryBinding,
    ) -> Result[dict[str, Any], str]:
        from .hosting_limit_execution import (  # noqa: PLC0415 -- Same native gate as fresh creation.
            ensure_managed_limits,
            publish_managed_limits,
        )

        verified: Result[bool, str] = Ok(False)
        if create_retry_policy(account, job).allowed:
            verified = ensure_managed_limits(account, parent_job=job, native_server=job.server)
            if verified.is_err() and create_retry_policy(account, job).allowed:
                job.mark_attention(verified.unwrap_err())
                return Err(verified.unwrap_err(), retriability=Retriability.UNKNOWN)
        with transaction.atomic():
            target = lock_create_retry_node(account, job)
            if target.is_err():
                return Err(target.unwrap_err())
            settled = settle_retry_created(
                binding,
                job.pk,
                {"recovered": "remote domain already present"},
                native_outcome="adopted",
            )
            if settled.is_ok() and verified.is_ok() and verified.unwrap():
                account.refresh_from_db()
                publish_managed_limits(account)
            return settled

    def _retry_dispatch_refusal(
        self, account: VirtualminAccount, job: VirtualminProvisioningJob, binding: CreateRetryBinding
    ) -> Err[str] | None:
        if not binding_current(binding, job.pk):
            park_changed_binding(binding, job.pk, native_outcome="not_issued")
            return Err("Create retry lost its account/claim binding before native dispatch")
        return self._create_retry_refusal(account, job)

    @staticmethod
    def _finish_create_retry(
        account: VirtualminAccount, job: VirtualminProvisioningJob, *, native_outcome: str
    ) -> Result[bool, str]:
        # This is deliberately after the common create executor returned, outside
        # its database-error compensation that deletes a freshly created domain.
        account = VirtualminAccount.objects.select_related("server").get(pk=account.pk)
        job.refresh_from_db()
        policy = create_retry_policy(account, job)
        if policy.allowed:
            on_account_ready(account)
            return Ok(True)
        try:
            if (
                policy.revoked
                and native_outcome != "adopted"
                and not policy.customer_held
                and policy.service_status in ("active", "suspended", "terminated", "expired")
            ):
                from .virtualmin_tasks import reconcile_virtualmin_service_state_async  # noqa: PLC0415

                reconcile_virtualmin_service_state_async(str(account.service_id))
            elif policy.revoked:
                queue_revoked_create_off(
                    account.pk, job.pk, native_outcome="adopted" if native_outcome == "adopted" else "created"
                )
            else:
                job.mark_attention(
                    policy.reason,
                    {
                        **job.result,
                        "creation_review": {
                            "domain": account.domain,
                            "owner": account.virtualmin_username,
                            "server_id": str(account.server_id),
                            "native_outcome": native_outcome,
                        },
                    },
                )
        except Exception:
            job.mark_attention(
                "Native create succeeded; policy recovery publication needs review",
                {
                    **job.result,
                    "creation_review": {
                        "domain": account.domain,
                        "owner": account.virtualmin_username,
                        "server_id": str(account.server_id),
                        "native_outcome": native_outcome,
                    },
                },
            )
        return Err("Native creation succeeded after hosting intent changed; recovery/review required")

    @staticmethod
    def _create_retry_refusal(
        account: VirtualminAccount, job: VirtualminProvisioningJob, *, owned_remote: bool = False
    ) -> Err[str] | None:
        policy = create_retry_policy(account, job)
        if policy.allowed:
            return None
        unknown_original = (job.result or {}).get(
            "retriability", Retriability.UNKNOWN.value
        ) == Retriability.UNKNOWN.value
        if policy.review or owned_remote or unknown_original:
            evidence = dict(job.result or {})
            if owned_remote:
                evidence["creation_review"] = {
                    "domain": account.domain,
                    "owner": account.virtualmin_username,
                    "server_id": str(account.server_id),
                    "phase": "owned_remote_review",
                    "service_status": policy.service_status,
                }
            job.mark_attention(policy.reason, evidence)
        else:
            job.mark_failed(
                policy.reason,
                retriability=Retriability.RETRIABLE if policy.customer_held else Retriability.NOT_RETRIABLE,
            )
        return Err(policy.reason)

    @staticmethod
    def _lifecycle_exclusion_refusal(account: VirtualminAccount, job: VirtualminProvisioningJob) -> Err[str] | None:
        """A retry is an admission like any other.

        The account row lock serialises it against backup/restore/delete admission, and
        only ANOTHER active operation refuses it (the retried job is itself the account's
        operation). Refused, the job returns to the retry pool instead of staying running.
        """
        with transaction.atomic():
            VirtualminAccount.objects.select_for_update().get(pk=account.pk)
            VirtualminServer.objects.select_for_update(of=("self",)).get(pk=account.server_id)
            from apps.infrastructure.node_maintenance_gate import (  # noqa: PLC0415  # Native admission
                maintenance_refusal,
            )

            refusal = maintenance_refusal(account.server_id)
            busy = account_has_active_operation(account, ignore_job_id=job.pk)
            if not busy and job.operation == "delete_domain":
                invalidate_chain(account)
        if not busy and not refusal:
            return None
        logger.info("✅ [VirtualminService] Active operation blocks lifecycle retry: %s", account.pk)
        message = refusal or ACCOUNT_BUSY_REFUSAL
        job.mark_failed(message, retriability=Retriability.RETRIABLE)
        return Err(message, retriability=Retriability.RETRIABLE)

    def _execute_lifecycle_operation(  # noqa: C901, PLR0911, PLR0915  # Keep same-job retry, admission and native settlement together.
        self, account: VirtualminAccount, job: VirtualminProvisioningJob
    ) -> Result[bool, str]:
        """Run suspend/unsuspend/delete against the gateway reusing the SAME job."""
        if account_has_active_migration(account):
            logger.info("✅ [VirtualminService] Migration lock blocks lifecycle retry: %s", account.pk)
            return Err("Account has an active migration")
        exclusion = self._lifecycle_exclusion_refusal(account, job)
        if exclusion is not None:
            return exclusion
        operations = {
            "suspend_domain": ("disable-domain", "suspended"),
            "unsuspend_domain": ("enable-domain", "active"),
            "delete_domain": ("delete-domain", "terminated"),
        }
        program, target_status = operations[job.operation]

        # Same veto as the reconciler (#566): an unsuspend retry must not re-enable an
        # account its bound domain is holding off. Terminal — retrying cannot change it.
        # Checked first so this, not the generic stale-state message below, explains it.
        if job.operation == "unsuspend_domain" and domain_disables_hosting(account):
            job.mark_failed("Superseded: a bound domain disables hosting")
            VirtualminProvisioningJob.terminalize(job.pk)
            return Err("Job superseded: a bound domain disables hosting")

        # Stale-intent guard: a job minted under an older Service state must
        # not replay against the current desired state (e.g. an old unsuspend
        # re-enabling hosting for a since-suspended customer).
        service_status = account.service.status if account.service_id else None
        if service_status is not None and not _job_matches_service_state(job.operation, service_status, account):
            job.mark_failed(f"Superseded by current service state '{service_status}'")
            VirtualminProvisioningJob.terminalize(job.pk)
            from apps.provisioning.virtualmin_tasks import (  # Deferred: avoids circular import  # noqa: PLC0415  # Circular
                reconcile_virtualmin_service_state_async,  # Circular: cross-app
            )

            reconcile_virtualmin_service_state_async(str(account.service_id))
            return Err(f"Job superseded by current service state '{service_status}'")

        if job.operation == "delete_domain" and account.protected_from_deletion:
            job.mark_failed("Account is protected from deletion")
            job.next_retry_at = None  # terminal — retrying cannot help
            job.save(update_fields=["next_retry_at", "updated_at"])
            return Err("Account is protected from deletion")

        if account.status == target_status:
            job.mark_completed({"idempotent": f"account already {target_status}"})
            return Ok(True)

        from apps.infrastructure.node_maintenance_gate import begin_account_job  # noqa: PLC0415  # Native admission

        if refusal := begin_account_job(account, job):
            job.mark_failed(refusal, retriability=Retriability.RETRIABLE)
            return Err(refusal, retriability=Retriability.RETRIABLE)
        gateway = self._get_gateway(account.server)
        params = domain_state_params(account.domain) if program in DOMAIN_STATE_PROGRAMS else {"domain": account.domain}
        result = gateway.call(program, params, correlation_id=job.correlation_id)

        if result.is_err():
            error_msg = str(result.unwrap_err())
            # Thread the gateway's retriability so a RETRIABLE failure during a
            # retry keeps next_retry_at armed instead of stranding the job.
            job.settle_failure(error_msg, retriability=retriability_of(result))
            return Err(error_msg, retriability=retriability_of(result))

        response = result.unwrap()
        if not response.success:
            error_msg = response.data.get("error", f"{program} failed")
            retriability = classify_virtualmin_application_error(response)
            job.settle_failure(error_msg, response.data, retriability=retriability)
            return Err(error_msg, retriability=retriability)

        previous_status = account.status
        with transaction.atomic():
            # fsm-bypass: CharField status
            account.status = target_status
            reason = (job.parameters or {}).get("reason", "")
            account.status_message = reason
            account.save(update_fields=["status", "status_message", "updated_at"])
            if job.operation == "delete_domain" and previous_status != "terminated":
                # Clamped: counter drift must never underflow the PositiveInteger
                VirtualminServer.objects.filter(pk=account.server_id, current_domains__gt=0).update(
                    current_domains=models.F("current_domains") - 1, updated_at=timezone.now()
                )
            job.mark_completed(response.data)

        # The remote op is done; if the Service moved while it was in flight,
        # converge on the new truth instead of leaving divergent state.
        if account.service_id:
            current = (
                account.service.__class__.objects.filter(pk=account.service_id).values_list("status", flat=True).first()
            )
            if current is not None and not _job_matches_service_state(job.operation, current, account):
                from apps.provisioning.virtualmin_tasks import (  # Deferred: avoids circular import  # noqa: PLC0415  # Circular
                    reconcile_virtualmin_service_state_async,  # Circular: cross-app
                )

                reconcile_virtualmin_service_state_async(str(account.service_id))
        logger.info(f"✅ [VirtualminService] Retry completed {job.operation} for {account.domain}")
        return Ok(True)

    def _execute_revoked_create_off(  # noqa: PLR0911  # Distinct binding, native and claim outcomes.
        self, account: VirtualminAccount, job: VirtualminProvisioningJob, claim: OffClaim
    ) -> Result[bool, str]:
        """Only the validated receipt owner may disable a pipeline-owned resource.

        Ordinary lifecycle eligibility is unchanged. Like its retry executor this
        path has no native enable/delete compensation after an accepted OFF.
        """
        retired = retire_closed_off_claim(job, claim=claim)
        if retired.is_err():
            return Err(retired.unwrap_err())
        if retired.unwrap():
            return Err("Receipt-bound OFF recovery is already closed; this delivery cannot replay")
        account = VirtualminAccount.objects.select_related("server").get(pk=account.pk)
        if account_has_active_migration(account):
            job.mark_failed("Account has an active migration", retriability=Retriability.RETRIABLE)
            return Err("Account has an active migration")
        exclusion = self._receipt_off_exclusion(account, job, claim)
        if exclusion is not None:
            return exclusion
        checked = self._receipt_off_preflight(account, job, claim)
        if checked.is_err():
            return Err(checked.unwrap_err())
        account, enabled = checked.unwrap()
        data: dict[str, Any] = {"observed_disabled": True}
        if enabled:
            if not owns_off_claim(claim):
                return Err("Receipt-bound OFF claim expired before dispatch")
            result = self._get_gateway(account.server).call(
                "disable-domain", domain_state_params(account.domain), correlation_id=job.correlation_id
            )
            if result.is_err():
                return self._off_failed(job, claim, str(result.unwrap_err()), retriability_of(result))
            response = result.unwrap()
            if not response.success:
                return self._off_failed(
                    job,
                    claim,
                    str(response.data.get("error", "OFF failed")),
                    classify_virtualmin_application_error(response),
                )
            data = response.data
        if not settle_off(job, claim, phase="disabled", data=data):
            return Err("Receipt-bound OFF completed after its claim was superseded; review retained")
        # A legitimate policy restoration during I/O owns the final enabled state.
        current = VirtualminAccount.objects.select_related("server").get(pk=account.pk)
        authority = off_authority(job, current)
        if authority is not None and authority[2].allowed:
            from .virtualmin_tasks import reconcile_virtualmin_service_state_async  # noqa: PLC0415

            reconcile_virtualmin_service_state_async(str(current.service_id))
        return Ok(True)

    def _receipt_off_exclusion(
        self, account: VirtualminAccount, job: VirtualminProvisioningJob, claim: OffClaim
    ) -> Err[str] | None:
        from apps.infrastructure.node_maintenance_gate import begin_account_job  # noqa: PLC0415  # Native admission

        if refusal := begin_account_job(account, job, preserve_claim=True):
            settle_off(job, claim, phase="pending", message=refusal)
            return Err(refusal, retriability=Retriability.RETRIABLE)
        return self._lifecycle_exclusion_refusal(account, job)

    @staticmethod
    def _off_failed(
        job: VirtualminProvisioningJob, claim: OffClaim, message: str, retriability: Retriability
    ) -> Err[str]:
        phase: Literal["uncertain", "pending", "refused"] = "uncertain"
        if retriability is Retriability.RETRIABLE:
            phase = "pending"
        elif retriability is Retriability.NOT_RETRIABLE:
            phase = "refused"
        settle_off(
            job,
            claim,
            phase=phase,
            message=message,
            data={"native_failure_retriability": retriability.value, "native_failure_reason": message},
        )
        return Err(message, retriability=retriability)

    def _receipt_off_preflight(
        self, account: VirtualminAccount, job: VirtualminProvisioningJob, claim: OffClaim
    ) -> Result[tuple[VirtualminAccount, bool], str]:
        account = VirtualminAccount.objects.select_related("server").get(pk=account.pk)
        refusal = self._receipt_off_refusal(account, job, claim)
        if refusal is not None:
            return refusal
        observed = self._get_gateway(account.server).get_domain_state(account.domain)
        if observed.is_err():
            settle_off(job, claim, phase="uncertain", message="Cannot verify exact native ownership before OFF")
            return Err("Cannot verify exact native ownership before OFF")
        state = observed.unwrap()
        if (
            state.get("exists") is not True
            or state.get("owner") != account.virtualmin_username
            or type(state.get("enabled")) is not bool
        ):
            settle_off(
                job, claim, phase="uncertain", message="Native resource identity/state does not match OFF receipt"
            )
            return Err("Native resource identity/state does not match OFF receipt")
        # The native observation may have taken time; re-read binding and policy
        # before the command, never use account.service cached before that I/O.
        refreshed = VirtualminAccount.objects.select_related("server").get(pk=account.pk)
        refusal = self._receipt_off_refusal(refreshed, job, claim)
        if refusal is not None:
            return refusal
        return Ok((refreshed, state["enabled"]))

    @staticmethod
    def _receipt_off_refusal(
        account: VirtualminAccount, job: VirtualminProvisioningJob, claim: OffClaim
    ) -> Err[str] | None:
        if not owns_off_claim(claim):
            return Err("Receipt-bound OFF delivery was superseded")
        authority = off_authority(job, account)
        if authority is not None and authority[2].revoked:
            return None
        restored = authority is not None and authority[2].allowed
        settled = settle_off(
            job,
            claim,
            phase="restored" if restored else "uncertain",
            message="OFF intent superseded" if restored else "OFF authority needs verification",
        )
        if restored and settled:
            from .virtualmin_tasks import reconcile_virtualmin_service_state_async  # noqa: PLC0415

            reconcile_virtualmin_service_state_async(str(account.service_id))
        return Err("Receipt-bound OFF is no longer authorized")

    def _select_best_server(
        self,
        preferred_region: str | None = None,
        required_tags: Sequence[str] | None = None,
        exclude_server_ids: Sequence[Any] = (),
    ) -> Result[VirtualminServer, str]:
        """Select an admissible server using the shared placement policy."""
        available_servers = (
            VirtualminServer.objects.filter(status="active", is_draining=False)
            .exclude(current_domains__gte=models.F("max_domains"))
            .exclude(pk__in=exclude_server_ids)
        )
        for server in order_placement_candidates(available_servers, preferred_region, required_tags):
            if server.can_host_domain() and destination_refusal(server) is None:
                return Ok(server)

        return Err(str(_("No available servers can host new domains")))

    def _generate_username_from_domain(self, domain: str) -> str:
        """
        Generate Virtualmin username from domain name.

        Args:
            domain: Domain name

        Returns:
            Valid Virtualmin username
        """
        # Remove TLD and special characters
        base = domain.split(".", maxsplit=1)[0]
        username = "".join(c for c in base if c.isalnum())

        # Ensure minimum length and uniqueness
        if len(username) < MIN_USERNAME_LENGTH:
            username = f"user{username}"

        # Truncate to maximum length
        username = username[:32]

        # Resolve once for the collision loop, preserving the counter and UUID fallback boundary.
        max_attempts = get_max_username_uniqueness_attempts()
        original_username = username
        counter = 1

        while VirtualminAccount.objects.filter(virtualmin_username=username).exists():
            username = f"{original_username}{counter}"[:32]
            counter += 1

            # Prevent infinite loop
            if counter > max_attempts:
                username = f"user_{uuid.uuid4().hex[:8]}"
                break

        return username

    def _generate_secure_password(self, length: int = 16) -> str:
        """
        Generate secure password for Virtualmin account.

        The password travels as a Virtualmin API parameter, and every parameter value is checked
        against SecureInputValidator's injection heuristics. A random password can match one (two
        adjacent "-" read as an SQL comment), which failed about 1 in 350 provisions permanently,
        so a candidate the validator would reject is regenerated.

        Args:
            length: Password length

        Returns:
            Secure password string
        """
        return generate_virtualmin_parameter_secret(lambda: self._password_candidate(length))

    def _password_candidate(self, length: int) -> str:
        """One random password with at least one lowercase, uppercase, digit and special character."""
        # Character sets for password generation
        lowercase = string.ascii_lowercase
        uppercase = string.ascii_uppercase
        digits = string.digits
        special = "!@#$%^&*()_+-="

        # Ensure at least one character from each set
        password = [
            secrets.choice(lowercase),
            secrets.choice(uppercase),
            secrets.choice(digits),
            secrets.choice(special),
        ]

        # Fill remaining length with random characters
        all_chars = lowercase + uppercase + digits + special
        password.extend([secrets.choice(all_chars) for _ in range(length - 4)])

        # Shuffle the password list
        secrets.SystemRandom().shuffle(password)

        return "".join(password)

    def test_server_connection(
        self, server: VirtualminServer, *, use_credential_vault: bool = True
    ) -> Result[dict[str, Any], str]:
        """
        Test connection to Virtualmin server.

        Args:
            server: Server to test
            use_credential_vault: when False, authenticate with the server object's own encrypted
                field instead of the vault — used by the staff "test these supplied credentials"
                flow so it probes the operator-entered password, not the vault entry for that host.

        Returns:
            Result with connection info or error message
        """
        try:
            gateway = self._get_gateway(server, use_credential_vault=use_credential_vault)
            return gateway.test_connection()
        except Exception as e:
            # Gateway setup failures (no server configured, credential decryption)
            # are not transient — stay at the UNKNOWN default.
            return Err(f"Connection test failed: {e}")


class VirtualminServerManagementService:
    """Service for managing Virtualmin servers and health monitoring"""

    def health_check_server(self, server: VirtualminServer, *, scheduled: bool = False) -> Result[dict[str, Any], str]:
        """Verify a captured configuration and fence every resulting health mutation."""
        from apps.common.status_observations import Observation, claim_check, finish_check  # noqa: PLC0415
        from apps.common.system_status import node_input_identity  # noqa: PLC0415

        try:
            server.refresh_from_db()
        except VirtualminServer.DoesNotExist:
            return Err("Node was removed before its health check")
        claim = claim_check("virtualmin", node_id=server.pk, identity=node_input_identity(server))
        if claim is None:
            return Err("A check is already running or the node was removed")
        try:
            result = VirtualminProvisioningService(server).test_server_connection(server)
            if result.is_ok() and result.unwrap().get("healthy") is not True:
                result = Err("Server did not affirm a healthy connection")
            resources = None
            if result.is_ok():
                raw = result.unwrap().get("data", {})
                if isinstance(raw, dict):
                    resources = VirtualminGateway.resource_snapshot(raw)
            observation = Observation(
                "green" if result.is_ok() else "red",
                "connected" if result.is_ok() else "connection_failed",
                resources.details() if resources is not None else {},
                resources,
                scheduled,
            )

            def publish() -> None:
                server.refresh_from_db()
                applied = self._apply_health_result(server, result)
                if result.is_ok() and applied.is_err():
                    raise RuntimeError("Node health mutation failed")

            accepted = finish_check(
                claim,
                identity=lambda: node_input_identity(VirtualminServer.objects.get(pk=server.pk)),
                observation=observation,
                on_accept=publish,
            )
            if not accepted:
                return Err("Node configuration changed or the check was superseded")
            from apps.settings.setup_checklist import clear_setup_cache  # noqa: PLC0415

            transaction.on_commit(clear_setup_cache)
            return result
        except Exception:  # Diagnostic boundary: do not expose gateway/vault exception payloads.
            logger.error("🔥 [ServerManagement] Health check could not complete for node %s", server.pk)
            finish_check(
                claim,
                identity=lambda: node_input_identity(VirtualminServer.objects.get(pk=server.pk)),
                observation=Observation("unknown", "check_failed"),
            )
            return Err("Node check could not complete; inspect the private operational logs")

    def _apply_health_result(
        self, server: VirtualminServer, result: Result[dict[str, Any], str]
    ) -> Result[dict[str, Any], str]:
        """
        Perform health check on Virtualmin server.

        Args:
            server: Server to check

        Returns:
            Result with health data or error message
        """
        try:
            if result.is_ok():
                health_data = result.unwrap()

                # Success: stamp the (success-only) timestamp, clear the error
                # and streak, and auto-recover a server WE auto-failed —
                # operator-set "failed" is never touched by health checks.
                server.last_health_check = timezone.now()
                server.health_check_error = ""
                server.consecutive_health_failures = 0
                update_fields = [
                    "last_health_check",
                    "health_check_error",
                    "consecutive_health_failures",
                    "updated_at",
                ]
                server.save(update_fields=update_fields)
                recovered = VirtualminServer.objects.filter(
                    pk=server.pk, status="failed", failed_by_health_check=True
                ).update(  # fsm-bypass: CharField status
                    status="active", failed_by_health_check=False, updated_at=timezone.now()
                )
                if recovered:
                    server.refresh_from_db()
                    logger.info(f"✅ [ServerManagement] Auto-recovered {server.hostname} to active")

                logger.info(f"✅ [ServerManagement] Health check passed for {server.hostname}")
                return Ok(health_data)
            else:
                error_msg = result.unwrap_err()

                # Failure: record the error and the streak. last_health_check
                # is NOT stamped (it means "last verified"), and a single
                # strike no longer evicts the server — only a sustained
                # streak auto-fails it, reversibly.
                VirtualminServer.objects.filter(pk=server.pk).update(
                    health_check_error=error_msg,
                    consecutive_health_failures=models.F("consecutive_health_failures") + 1,
                    updated_at=timezone.now(),
                )
                server.refresh_from_db()
                coordinate_health_failure(server)
                server.refresh_from_db()

                logger.warning(f"⚠️ [ServerManagement] Health check failed for {server.hostname}: {error_msg}")
                return Err(error_msg, retriability=retriability_of(result))

        except Exception:
            # The caller publishes evidence and mutations in one transaction. Propagate so
            # a partial health write rolls back instead of recording a successful check.
            logger.exception("🔥 [ServerManagement] Health mutation failed for node %s", server.pk)
            raise

    def update_server_statistics(self, server: VirtualminServer) -> Result[dict[str, Any], str]:
        """
        Update server usage statistics from Virtualmin.

        Args:
            server: Server to update

        Returns:
            Result with statistics or error message
        """
        try:
            from .virtualmin_drain_service import server_has_active_migration  # Circular  # noqa: PLC0415  # Circular

            if server_has_active_migration(server):
                # A migration in flight can complete between our remote read and
                # this absolute write — the stale snapshot would erase the
                # completion's capacity accounting. Skip; next sweep reconciles.
                logger.info("✅ [ServerManagement] Stats skipped (active migration): %s", server.hostname)
                return Ok({"skipped": "active_migration"})

            provisioning_service = VirtualminProvisioningService(server)
            gateway = provisioning_service._get_gateway(server)

            # Get server info
            info_result = gateway.get_server_info()
            if info_result.is_err():
                return Err(
                    f"Failed to get server info: {info_result.unwrap_err()}",
                    retriability=retriability_of(info_result),
                )

            # Customer domains only: the name-only listing cannot tell an account name (its
            # customer's sub-server) from a domain, and counting it would halve a node's capacity.
            domains_result = gateway.list_domains_with_owners()
            if domains_result.is_err():
                return Err(
                    f"Failed to list domains: {domains_result.unwrap_err()}",
                    retriability=retriability_of(domains_result),
                )

            domain_count = sum(1 for row in domains_result.unwrap() if is_customer_domain_row(row))

            # Update server statistics
            server.current_domains = domain_count
            server.save(update_fields=["current_domains", "updated_at"])

            stats = {"domain_count": domain_count, "server_info": info_result.unwrap()}

            logger.info(f"📊 [ServerManagement] Updated stats for {server.hostname}: {domain_count} domains")
            return Ok(stats)

        except Exception as e:
            logger.exception(f"Error updating statistics for {server.hostname}: {e}")
            return Err(str(e))


class VirtualminBackupManagementService:
    """
    High-level backup management service for Virtualmin accounts.

    Integrates VirtualminBackupService with PRAHO's job tracking and audit systems.
    """

    def __init__(self, server: VirtualminServer):
        self.server = server

    def create_backup_job(
        self,
        account: VirtualminAccount,
        config: BackupConfig | None = None,
        initiated_by: str = "system",
        *,
        execute_inline: bool = False,
    ) -> Result[VirtualminProvisioningJob, str]:
        """
        Create and execute backup job for Virtualmin account.

        Args:
            account: Virtualmin account to backup
            backup_type: Type of backup (full, incremental, config_only)
            include_email: Include email data
            include_databases: Include database data
            include_files: Include web files
            include_ssl: Include SSL certificates
            initiated_by: User or system that initiated the backup

        Returns:
            Result with provisioning job or error message
        """
        try:
            # Import here to avoid circular imports
            from .virtualmin_backup_service import (  # Circular: same-app  # Deferred: avoids circular import  # noqa: PLC0415  # Circular
                BackupConfig,
            )

            # Use default config if none provided
            if config is None:
                config = BackupConfig()
            role_error = config.chain_role_error()
            if role_error is not None:
                return Err(role_error)
            if config.chain_role != CHAIN_ROLE_STANDALONE and not self.incremental_backups_enabled():
                return Err("Differential backups are disabled (provisioning.incremental_backups_enabled)")

            parameters = {
                "backup_type": config.backup_type,
                "include_email": config.include_email,
                "include_databases": config.include_databases,
                "include_files": config.include_files,
                "include_ssl": config.include_ssl,
                "chain_role": config.chain_role,
                "initiated_by": initiated_by,
            }
            return self._admit_job(
                account,
                operation="backup_domain",
                parameters=parameters,
                task_path="apps.provisioning.virtualmin_tasks.run_virtualmin_backup",
                execute_inline=execute_inline,
                source_bound=True,
            )
        except Exception as e:
            logger.error(f"Backup job creation failed: {e}")
            return Err(f"Backup job failed: {e!s}")

    @staticmethod
    def incremental_backups_enabled() -> bool:
        """Whether base and differential backups may be created (provisioning.incremental_backups_enabled)."""
        from apps.settings.services import SettingsService  # noqa: PLC0415  # Cross-app: avoids circular imports

        return SettingsService.get_boolean_setting("provisioning.incremental_backups_enabled", False)

    def take_base_backup(
        self, account: VirtualminAccount, *, initiated_by: str = "system", execute_inline: bool = False
    ) -> Result[VirtualminProvisioningJob, str]:
        """Start a new differential chain: a full backup that resets the node's snapshot."""
        return self._take_chain_backup(account, CHAIN_ROLE_BASE, initiated_by, execute_inline)

    def take_differential_backup(
        self, account: VirtualminAccount, *, initiated_by: str = "system", execute_inline: bool = False
    ) -> Result[VirtualminProvisioningJob, str]:
        """Back up only what changed since the account's live base."""
        return self._take_chain_backup(account, CHAIN_ROLE_DIFFERENTIAL, initiated_by, execute_inline)

    def _take_chain_backup(
        self, account: VirtualminAccount, role: str, initiated_by: str, execute_inline: bool
    ) -> Result[VirtualminProvisioningJob, str]:
        return self.create_backup_job(
            account, BackupConfig(chain_role=role), initiated_by=initiated_by, execute_inline=execute_inline
        )

    @staticmethod
    def _backup_server_refusal(
        account: VirtualminAccount, server: VirtualminServer, operation: str, parameters: dict[str, Any]
    ) -> str | None:
        from .virtualmin_restore_policy import restore_destination_refusal  # noqa: PLC0415 -- archive admission

        if server.security_operation:
            return "Node hardening is unresolved; reconcile it before backup or restore"
        if operation != "restore_domain":
            return None
        return restore_destination_refusal(account, server, force=parameters.get("force_restore") is True)

    def _admit_job(  # noqa: C901, PLR0911, PLR0912, PLR0913 -- Distinct account, node and managed-restore budget refusals.
        self,
        account: VirtualminAccount,
        *,
        operation: str,
        parameters: dict[str, Any],
        task_path: str,
        execute_inline: bool,
        source_bound: bool,
        task_budget: int | None = None,
    ) -> Result[VirtualminProvisioningJob, str]:
        """Durable admission: account lock + exclusion + pending row + queued task.

        ``source_bound`` jobs (backups) run where the account lives: the node comes
        from the LOCKED account row, and admission refuses when the account moved
        since this service was built. A restore names its target node explicitly
        (``self.server``), so it is not source-bound.

        The job row and its queue message commit in one transaction (the ORM
        broker shares the business DB); sync=False keeps django-q's sync mode
        from executing the mutation INSIDE this transaction. Inline execution
        (CLI) requires autocommit, commits admission first, then runs the task
        function in-process under the same token-claim protocol.
        """
        from django_q.tasks import async_task  # noqa: PLC0415  # Circular

        from .spool import estimated_transfer_bytes  # noqa: PLC0415  # Circular
        from .virtualmin_backup_service import backup_task_timeout  # noqa: PLC0415  # Circular

        estimated = estimated_transfer_bytes(account.current_disk_usage_mb or 0)
        budget = task_budget or backup_task_timeout(
            estimated, chain=parameters.get("chain_role", CHAIN_ROLE_STANDALONE) != CHAIN_ROLE_STANDALONE
        )
        retry_window = int(str(settings.Q_CLUSTER.get("retry", 0)))
        if budget + 60 >= retry_window:
            return Err(
                f"Task budget {budget}s does not fit under the broker visibility timeout {retry_window}s; "
                "raise Q_CLUSTER retry or provisioning.backup_min_transfer_mib_s"
            )
        if execute_inline and not is_outside_transaction():
            return Err("Inline execution requires autocommit; run outside any transaction")

        parameters = {**parameters, "estimated_bytes": estimated, "task_budget_seconds": budget}
        with transaction.atomic():
            # Lock only the account row: a select_related join would also lock the server row
            # (PostgreSQL locks joined rows), out of order with migration admission.
            locked = VirtualminAccount.objects.select_for_update().get(pk=account.pk)
            if source_bound and locked.server_id != self.server.pk:
                return Err("Account moved to another server since this request began; retry")
            from apps.infrastructure.node_maintenance_gate import (  # noqa: PLC0415  # Shared server admission
                maintenance_refusal,
                native_account_observation_refusal,
            )

            node_id = locked.server_id if source_bound else self.server.pk
            target_server = VirtualminServer.objects.select_for_update(of=("self",)).get(pk=node_id)
            if refusal := self._backup_server_refusal(locked, target_server, operation, parameters):
                return Err(refusal)
            if refusal := maintenance_refusal(node_id):
                return Err(refusal)
            if refusal := native_account_observation_refusal(locked.pk):
                return Err(refusal)
            if account_has_active_operation(locked):
                return Err(ACCOUNT_BUSY_REFUSAL)
            role = str(parameters.get("chain_role", ROLE_STANDALONE))
            if operation == "restore_domain":
                if locked.quota_managed:
                    budget += 960  # Fenced quota probe/application and canonical observation after restoration.
                    if budget + 60 >= retry_window:
                        return Err(
                            "Managed restore plus quota verification exceeds broker visibility; review the configured task budget."
                        )
                    parameters["task_budget_seconds"] = budget
                if locked.quota_managed and parameters.get("restore_mode") != "pair":
                    parameters = {**parameters, "managed_single_restore": True, "pair_token": str(uuid.uuid4())}
                invalidate_chain(locked)  # a restore deletes the node's snapshot (contract Q8)
            elif role != ROLE_STANDALONE:
                pins = admit_chain_role(locked, role)
                if pins.is_err():
                    return Err(pins.unwrap_err())
                parameters = {**parameters, **pins.unwrap()}
            job = VirtualminProvisioningJob.objects.create(
                operation=operation,
                account=locked,
                server=locked.server if source_bound else self.server,
                parameters=parameters,
                status="pending",
            )
            if not execute_inline:
                async_task(task_path, str(job.pk), timeout=budget, sync=False)
        if execute_inline:
            from . import virtualmin_tasks  # noqa: PLC0415  # Circular

            runner = getattr(virtualmin_tasks, task_path.rsplit(".", 1)[1])
            runner(str(job.pk))
            job.refresh_from_db()
            if job.status != "completed":
                return Err(f"{operation} failed: {job.status_message or job.status}")
        logger.info("✅ [BackupJobs] Admitted %s job %s (budget %ss)", operation, job.pk, budget)
        return Ok(job)

    def create_pair_restore_job(  # noqa: PLR0913  # Pair identity, target, actor and execution seams
        self,
        account: VirtualminAccount,
        base_backup_id: str,
        differential_backup_id: str,
        target_server: VirtualminServer | None = None,
        initiated_by: str = "system",
        *,
        force_restore: bool = False,
        execute_inline: bool = False,
        step_hold_seconds: int = 0,
    ) -> Result[VirtualminProvisioningJob, str]:
        """Admit a pair restore: a base and its differential, restored as one workflow.

        Refuses early what the workflow would refuse later (exact lineage, from the manifests), so
        no job is created for a pair that cannot be restored. It follows
        ``provisioning.incremental_backups_enabled`` like creating a base or a differential. The budget covers both archives and
        every stage of the workflow, and is checked against the broker visibility window by
        ``_admit_job`` like any other job. A pair restore always overwrites the live domain, so
        the caller must say so (``force_restore``).
        """
        from .spool import estimated_transfer_bytes  # noqa: PLC0415  # Circular
        from .virtualmin_pair_restore import (  # noqa: PLC0415  # Circular
            RESTORE_MODE_PAIR,
            pair_lineage_refusal,
            pair_restore_task_timeout,
        )

        if not self.incremental_backups_enabled():
            # Differential backups are one feature: a pair restore follows the flag, like creation, in
            # the staff page and the CLI alike (ADR-0059).
            return Err("Differential backups are disabled (provisioning.incremental_backups_enabled)")
        if not force_restore:
            return Err("A pair restore overwrites the live domain; it must be confirmed explicitly")
        try:
            target_server = target_server or self.server
            backups = VirtualminBackupService(target_server)
            manifests: dict[str, dict[str, Any]] = {}
            for label, backup_id in (("base", base_backup_id), ("differential", differential_backup_id)):
                read = backups.read_manifest(backup_id)
                if read.is_err():
                    return Err(f"The {label} backup could not be read: {read.unwrap_err()}")
                manifests[label] = read.unwrap()
            refusal = pair_lineage_refusal(
                manifests["base"], manifests["differential"], service_id=account.service_id, domain=account.domain
            )
            if refusal is not None:
                return Err(refusal)
            sizes = [int(manifests[label].get("file_size_bytes") or 0) for label in ("base", "differential")]
            budget = pair_restore_task_timeout(
                estimated_transfer_bytes(account.current_disk_usage_mb or 0), sizes[0], sizes[1]
            )
            parameters = {
                "restore_mode": RESTORE_MODE_PAIR,
                "base_backup_id": base_backup_id,
                "differential_backup_id": differential_backup_id,
                "pair_token": str(uuid.uuid4()),
                "pair_step_hold_seconds": step_hold_seconds,
                "restore_email": True,
                "restore_databases": True,
                "restore_files": True,
                "restore_ssl": True,
                "force_restore": True,
                "target_server_id": str(target_server.id),
                "initiated_by": initiated_by,
            }
            original_server = self.server
            self.server = target_server
            try:
                return self._admit_job(
                    account,
                    operation="restore_domain",
                    parameters=parameters,
                    task_path="apps.provisioning.virtualmin_tasks.run_virtualmin_restore",
                    execute_inline=execute_inline,
                    source_bound=False,
                    task_budget=budget,
                )
            finally:
                self.server = original_server
        except Exception as e:
            logger.error(f"Pair restore job creation failed: {e}")
            return Err(f"Pair restore job failed: {e!s}")

    def create_restore_job(
        self,
        account: VirtualminAccount,
        config: RestoreConfig,
        target_server: VirtualminServer | None = None,
        initiated_by: str = "system",
        *,
        execute_inline: bool = False,
    ) -> Result[VirtualminProvisioningJob, str]:
        """
        Create and execute restore job for Virtualmin account.

        Args:
            account: Target account for restore
            config: Restore configuration object
            target_server: Target server (defaults to account's server)
            initiated_by: User or system that initiated the restore

        Returns:
            Result with provisioning job or error message
        """
        try:
            target_server = target_server or self.server
            parameters = {
                "backup_id": config.backup_id,
                "restore_email": config.restore_email,
                "restore_databases": config.restore_databases,
                "restore_files": config.restore_files,
                "restore_ssl": config.restore_ssl,
                "force_restore": config.force_restore,
                "target_server_id": str(target_server.id),
                "initiated_by": initiated_by,
            }
            task_budget = None
            if VirtualminAccount.objects.filter(pk=account.pk, quota_managed=True).exists():
                from .spool import estimated_transfer_bytes  # noqa: PLC0415
                from .virtualmin_pair_restore import pair_restore_task_timeout  # noqa: PLC0415

                manifest = VirtualminBackupService(target_server).read_manifest(config.backup_id)
                if manifest.is_err():
                    return Err("The managed restore archive could not be inspected: " + manifest.unwrap_err())
                size = manifest.unwrap().get("file_size_bytes")
                if type(size) is not int or size <= 0:
                    return Err("The managed restore archive has no bounded size evidence.")
                task_budget = pair_restore_task_timeout(
                    estimated_transfer_bytes(account.current_disk_usage_mb or 0), size, 0
                )
            original_server = self.server
            self.server = target_server
            try:
                return self._admit_job(
                    account,
                    operation="restore_domain",
                    parameters=parameters,
                    task_path="apps.provisioning.virtualmin_tasks.run_virtualmin_restore",
                    execute_inline=execute_inline,
                    source_bound=False,
                    task_budget=task_budget,
                )
            finally:
                self.server = original_server
        except Exception as e:
            logger.error(f"Restore job creation failed: {e}")
            return Err(f"Restore job failed: {e!s}")
