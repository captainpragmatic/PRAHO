"""
Virtualmin Django-Q2 Tasks - PRAHO Platform
Asynchronous provisioning tasks for Virtualmin operations.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import timedelta
from typing import Any, TypedDict
from uuid import UUID

from django.conf import settings
from django.core.cache import cache
from django.db import models, transaction
from django.utils import timezone
from django_q.models import Schedule as ScheduleModel
from django_q.tasks import async_task, schedule

from apps.audit.services import AuditContext, AuditEventData, AuditService
from apps.common.types import Retriability, retriability_of
from apps.provisioning.models import Service

from .security_utils import (
    IdempotencyManager,
    ProvisioningErrorClassifier,
    ProvisioningParametersValidator,
    SecureTaskParameters,
    log_security_event_safe,
    sanitize_log_parameters,
)
from .virtualmin_drain_service import NodeDrainService
from .virtualmin_migration_models import NodeDrain
from .virtualmin_models import (
    VirtualminAccount,
    VirtualminProvisioningJob,
    VirtualminServer,
)
from .virtualmin_service import (
    VirtualminAccountCreationData,
    VirtualminProvisioningService,
    VirtualminServerManagementService,
)

logger = logging.getLogger(__name__)


class RetryableProvisioningError(RuntimeError):
    """Raised only when a Result explicitly marks a task replay as safe."""


# ===============================================================================
# TASK CONFIGURATION - Externalized Timeouts
# ===============================================================================


def get_task_timeouts() -> dict[str, int]:
    """
    Get task timeout configurations from Django settings.

    Supports runtime configuration updates and environment variable overrides.
    Uses the centralized VIRTUALMIN_TIMEOUTS configuration system.

    Returns:
        Dictionary of task timeout values in seconds
    """

    # Get Virtualmin timeout configuration
    virtualmin_timeouts = getattr(settings, "VIRTUALMIN_TIMEOUTS", {})

    return {
        "TASK_RETRY_DELAY": virtualmin_timeouts.get("RETRY_DELAY", 5) * 60,  # Convert to minutes
        "TASK_MAX_RETRIES": virtualmin_timeouts.get("MAX_RETRIES", 3),
        "TASK_SOFT_TIME_LIMIT": virtualmin_timeouts.get("PROVISIONING_TIMEOUT", 180) * 2,  # 2x provisioning timeout
        "TASK_TIME_LIMIT": virtualmin_timeouts.get("PROVISIONING_TIMEOUT", 180) * 3,  # 3x provisioning timeout
        "BACKUP_TIME_LIMIT": virtualmin_timeouts.get("API_BACKUP_TIMEOUT", 300),
        "BULK_OPERATION_TIME_LIMIT": virtualmin_timeouts.get("API_BULK_TIMEOUT", 600),
        "HEALTH_CHECK_TIME_LIMIT": virtualmin_timeouts.get("API_HEALTH_CHECK_TIMEOUT", 10) * 6,  # 1 minute total
    }


# Legacy constants for backward compatibility
TASK_RETRY_DELAY = 300  # 5 minutes - DEPRECATED: Use get_task_timeouts()['TASK_RETRY_DELAY']
TASK_MAX_RETRIES = 3  # DEPRECATED: Use get_task_timeouts()['TASK_MAX_RETRIES']
_DEFAULT_TASK_SOFT_TIME_LIMIT = 600  # 10 minutes - DEPRECATED: Use get_task_timeouts()['TASK_SOFT_TIME_LIMIT']
TASK_SOFT_TIME_LIMIT = _DEFAULT_TASK_SOFT_TIME_LIMIT
_DEFAULT_TASK_TIME_LIMIT = 900  # 15 minutes - DEPRECATED: Use get_task_timeouts()['TASK_TIME_LIMIT']
TASK_TIME_LIMIT = _DEFAULT_TASK_TIME_LIMIT


def get_task_soft_time_limit() -> int:
    """Get task soft time limit from SettingsService (runtime)."""
    from apps.settings.services import (  # noqa: PLC0415  # Deferred: avoids circular import
        SettingsService,  # Circular: cross-app  # Deferred: avoids circular import
    )

    return SettingsService.get_integer_setting("provisioning.task_soft_time_limit", _DEFAULT_TASK_SOFT_TIME_LIMIT)


def get_task_time_limit() -> int:
    """Get task time limit from SettingsService (runtime)."""
    from apps.settings.services import (  # noqa: PLC0415  # Deferred: avoids circular import
        SettingsService,  # Circular: cross-app  # Deferred: avoids circular import
    )

    return SettingsService.get_integer_setting("provisioning.task_time_limit", _DEFAULT_TASK_TIME_LIMIT)


@dataclass
class VirtualminProvisioningConfig:
    """Configuration for Virtualmin provisioning task."""

    service_id: str
    domain: str
    username: str | None = None
    password: str | None = None
    template: str = "Default"
    server_id: str | None = None


@dataclass
class ProvisioningContext:
    """Context for provisioning operations with validated parameters."""

    service_id: str
    domain: str
    username: str | None
    template: str
    correlation_id: str
    safe_log_ctx: dict[str, Any]
    idempotency_key: str


@dataclass
class ProvisioningExecutionParams:
    """Parameters for executing Virtualmin provisioning."""

    service: Service
    domain: str
    username: str | None
    template: str
    server: Any | None  # VirtualminServer
    correlation_id: str
    safe_log_ctx: dict[str, Any]


class VirtualminProvisioningParams(TypedDict, total=False):
    """Parameters for Virtualmin account provisioning"""

    service_id: str
    domain: str
    username: str | None
    password: str | None
    template: str
    server_id: str | None


def _decrypt_and_extract_parameters(
    params: VirtualminProvisioningParams | SecureTaskParameters,
) -> tuple[dict[str, Any], str, str] | tuple[None, None, None]:
    """
    Decrypt and extract core parameters from provisioning params.

    Returns:
        Tuple of (decrypted_params, service_id, domain) or (None, None, None) on error
    """
    try:
        if isinstance(params, SecureTaskParameters):
            decrypted_params = params.decrypt()
            logger.info(f"🔓 [VirtualminTask] Decrypted secure parameters (hash: {params.parameter_hash[:16]}...)")
        else:
            # Legacy parameter format - still validate
            decrypted_params = dict(params)  # Convert TypedDict to regular dict

        # Extract and validate core parameters
        service_id = decrypted_params["service_id"]
        domain = decrypted_params["domain"]

        return decrypted_params, service_id, domain

    except Exception as decrypt_error:
        logger.error(f"🔥 [VirtualminTask] Parameter decryption/extraction failed: {decrypt_error}")
        log_security_event_safe("virtualmin_task_parameter_decryption_failed", {"error": str(decrypt_error)}, None)
        return None, None, None


def _validate_provisioning_parameters(
    decrypted_params: dict[str, Any], service_id: str, domain: str
) -> ProvisioningContext | None:
    """
    Validate provisioning parameters and create context.

    Returns:
        ProvisioningContext with validated parameters or None on error
    """
    try:
        validated_service_id = ProvisioningParametersValidator.validate_service_id(service_id)
        validated_domain = ProvisioningParametersValidator.validate_domain(domain)
        validated_username = ProvisioningParametersValidator.validate_username(decrypted_params.get("username"))
        validated_template = ProvisioningParametersValidator.validate_template(
            decrypted_params.get("template", "Default")
        )

        # Initialize correlation and logging context
        correlation_id = f"provision_{validated_service_id}_{validated_domain}"
        safe_log_ctx = {
            "service_id": validated_service_id,
            "domain": validated_domain,
            "template": validated_template,
            "correlation_id": correlation_id,
        }

        # Step 3: Idempotency check
        idempotency_key = IdempotencyManager.generate_key(
            validated_service_id,
            "provision_account",
            {"domain": validated_domain, "template": validated_template, "correlation_id": correlation_id},
        )

        return ProvisioningContext(
            service_id=validated_service_id,
            domain=validated_domain,
            username=validated_username,
            template=validated_template,
            correlation_id=correlation_id,
            safe_log_ctx=safe_log_ctx,
            idempotency_key=idempotency_key,
        )

    except Exception as validation_error:
        logger.error(f"❌ [VirtualminTask] Parameter validation failed: {validation_error}")
        log_security_event_safe(
            "virtualmin_task_validation_failed",
            {"error": str(validation_error), "original_params": sanitize_log_parameters(decrypted_params)},
            service_id,
            domain,
        )
        return None


def _check_idempotency(context: ProvisioningContext) -> tuple[bool, dict[str, Any] | None]:
    """
    Check idempotency for provisioning operation.

    Returns:
        Tuple of (should_continue, existing_result)
    """
    is_new, existing_result = IdempotencyManager.check_and_set(context.idempotency_key)
    if not is_new:
        if isinstance(existing_result, dict) and existing_result.get("success"):
            logger.info(f"✅ [VirtualminTask] Returning cached result (key: {context.idempotency_key[:16]}...)")
            return False, existing_result
        else:
            logger.info(f"⏭️ [VirtualminTask] Operation already in progress (key: {context.idempotency_key[:16]}...)")
            return False, {"success": False, "error": "Operation already in progress", "retry": True}

    return True, None


def _execute_provisioning_transaction(context: ProvisioningContext, server_id: str | None) -> dict[str, Any]:
    """
    Execute provisioning within atomic transaction.

    Args:
        context: Provisioning context with validated parameters
        server_id: Optional server ID from decrypted params

    Returns:
        Provisioning result dictionary
    """
    try:
        with transaction.atomic():
            # Validate and get service with lock
            validation_result = _validate_service_for_provisioning_secure(context.service_id)
            if not validation_result["success"]:
                IdempotencyManager.clear(context.idempotency_key)
                return validation_result
            service = validation_result["service"]

            # Check for existing account within transaction
            existing_check = _check_existing_virtualmin_account_secure(service)
            if existing_check:
                IdempotencyManager.complete(context.idempotency_key, existing_check)
                return existing_check

            # Get server for provisioning
            server = _get_provisioning_server_secure(server_id)

            # Create execution params
            exec_params = ProvisioningExecutionParams(
                service=service,
                domain=context.domain,
                username=context.username,
                template=context.template,
                server=server,
                correlation_id=context.correlation_id,
                safe_log_ctx=context.safe_log_ctx,
            )

            # Execute provisioning with rollback capability
            result = _execute_virtualmin_provisioning_with_params(exec_params)

            # Update idempotency with result
            if result["success"]:
                IdempotencyManager.complete(context.idempotency_key, result)
            else:
                IdempotencyManager.clear(context.idempotency_key)

            return result

    except RetryableProvisioningError as retry_error:
        IdempotencyManager.clear(context.idempotency_key)
        logger.warning(f"🔄 [VirtualminTask] Explicitly retryable error, will retry: {retry_error}")
        raise

    except Exception as provisioning_error:
        logger.error(f"🔥 [VirtualminTask] Provisioning transaction failed: {provisioning_error}")
        IdempotencyManager.clear(context.idempotency_key)
        return {
            "success": False,
            "error": f"Provisioning error: {provisioning_error}",
            "retriability": Retriability.UNKNOWN.value,
        }


def provision_virtualmin_account(params: VirtualminProvisioningParams | SecureTaskParameters) -> dict[str, Any]:
    """
    Sync task to provision Virtualmin account with comprehensive security fixes.

    SECURITY ENHANCEMENTS:
    1. Idempotency protection against duplicate operations
    2. Secure parameter handling with encryption/decryption
    3. Comprehensive input validation and sanitization
    4. Proper error classification and state management
    5. Atomic database operations with rollback capability
    6. Sensitive data protection in logs and audit trails

    Args:
        params: Either VirtualminProvisioningParams or SecureTaskParameters containing provisioning data

    Returns:
        Dictionary with provisioning result

    Raises:
        Exception: On retryable errors (triggers retry)
    """
    # Step 1: Decrypt and extract parameters
    decrypted_params, service_id, domain = _decrypt_and_extract_parameters(params)
    if decrypted_params is None or service_id is None or domain is None:
        return {"success": False, "error": "Parameter processing failed"}

    logger.info(f"🔄 [VirtualminTask] Starting secure provisioning for {domain}")

    try:
        # Step 2: Validate parameters and create context
        context = _validate_provisioning_parameters(decrypted_params, service_id, domain)
        if context is None:
            return {"success": False, "error": "Validation failed"}

        # Step 3: Check idempotency
        should_continue, existing_result = _check_idempotency(context)
        if not should_continue:
            return existing_result or {"success": False, "error": "Idempotency check failed"}

        # Step 4: Execute provisioning in transaction
        return _execute_provisioning_transaction(context, decrypted_params.get("server_id"))

    except RetryableProvisioningError:
        raise

    except Exception as e:
        # Use context values if available, otherwise use original parameters
        try:
            validated_domain = context.domain if "context" in locals() and context else (domain or "unknown")
            validated_service_id = (
                context.service_id if "context" in locals() and context else (service_id or "unknown")
            )
            correlation_id = (
                context.correlation_id
                if "context" in locals() and context
                else f"provision_{validated_service_id}_{validated_domain}"
            )
            safe_log_ctx = (
                context.safe_log_ctx
                if "context" in locals() and context
                else {"service_id": validated_service_id, "domain": validated_domain, "correlation_id": correlation_id}
            )

            return _handle_critical_provisioning_error_secure(
                e, validated_domain, validated_service_id, correlation_id, safe_log_ctx
            )
        except Exception:
            # Fallback for any issues with context access
            return {"success": False, "error": f"Critical error: {e}"}


def _validate_service_for_provisioning_secure(service_id: str) -> dict[str, Any]:
    """Validate service exists and is ready for provisioning with atomic locking."""
    try:
        # Use select_for_update to prevent race conditions
        service = Service.objects.select_for_update().select_related("customer", "service_plan").get(id=service_id)
    except Service.DoesNotExist:
        error_msg = f"Service {service_id} not found"
        logger.error(f"❌ [VirtualminTask] {error_msg}")
        log_security_event_safe("virtualmin_task_service_not_found", {"service_id": service_id}, service_id)
        return {"success": False, "error": error_msg}

    # Validate service status for provisioning
    if service.status != "active":
        error_msg = f"Service {service.service_name} is not active (status: {service.status})"
        logger.warning(f"⚠️ [VirtualminTask] {error_msg}")
        return {"success": False, "error": error_msg}

    return {"success": True, "service": service}


def _validate_service_for_provisioning(service_id: str) -> dict[str, Any]:
    """Legacy function - kept for backward compatibility."""
    return _validate_service_for_provisioning_secure(service_id)


def _check_existing_virtualmin_account_secure(service: Service) -> dict[str, Any] | None:
    """Check if VirtualMin account already exists for service with enhanced logging."""
    if hasattr(service, "virtualmin_account") and service.virtualmin_account:
        account = service.virtualmin_account
        logger.info(f"⏭️ [VirtualminTask] VirtualMin account already exists for {service.service_name}")

        # Log idempotency event
        log_security_event_safe(
            "virtualmin_task_account_already_exists",
            {
                "service_id": str(service.id),
                "account_id": str(account.id),
                "domain": account.domain,
                "status": account.status,
            },
            str(service.id),
            account.domain,
        )

        return {
            "success": True,
            "account_id": str(account.id),
            "domain": account.domain,
            "status": account.status,
            "message": "Account already exists",
        }
    return None


def _check_existing_virtualmin_account(service: Service) -> dict[str, Any] | None:
    """Legacy function - kept for backward compatibility."""
    return _check_existing_virtualmin_account_secure(service)


def _get_provisioning_server_secure(server_id: str | None) -> VirtualminServer | None:
    """Get server for provisioning with enhanced security checks."""
    if not server_id:
        logger.info("🔄 [VirtualminTask] No specific server requested, will use load balancer")
        return None

    try:
        # Validate server ID format first
        validated_server_id = ProvisioningParametersValidator.validate_service_id(server_id)

        server = VirtualminServer.objects.get(id=validated_server_id)

        # Enhanced server validation
        if not server.can_host_domain():
            logger.warning(f"⚠️ [VirtualminTask] Server {server.hostname} cannot host new domains")
            log_security_event_safe(
                "virtualmin_server_capacity_exceeded",
                {
                    "server_id": str(server.id),
                    "hostname": server.hostname,
                    "current_domains": server.current_domains,
                    "max_domains": server.max_domains,
                },
                None,
            )
            return None

        if server.status != "active":
            logger.warning(f"⚠️ [VirtualminTask] Server {server.hostname} is not active (status: {server.status})")
            return None

        return server

    except Exception as e:
        logger.warning(f"⚠️ [VirtualminTask] Server validation failed for {server_id}: {e}")
        return None


def _get_provisioning_server(server_id: str | None) -> VirtualminServer | None:
    """Legacy function - kept for backward compatibility."""
    return _get_provisioning_server_secure(server_id)


def _execute_virtualmin_provisioning_with_params(exec_params: ProvisioningExecutionParams) -> dict[str, Any]:
    """Execute VirtualMin provisioning with enhanced security and error handling."""
    try:
        # Create provisioning service
        provisioning_service = VirtualminProvisioningService(exec_params.server)

        # Prepare creation data with validated parameters
        creation_data = VirtualminAccountCreationData(
            service=exec_params.service,
            domain=exec_params.domain,
            username=exec_params.username,
            password=None,  # Let service generate secure password
            template=exec_params.template,
            server=exec_params.server,
        )

        # Execute provisioning with comprehensive logging
        logger.info(f"🔧 [VirtualminTask] Executing provisioning: {sanitize_log_parameters(exec_params.safe_log_ctx)}")
        result = provisioning_service.create_virtualmin_account(creation_data)

        if result.is_ok():
            return _handle_successful_provisioning_secure(
                result.unwrap(), exec_params.service, exec_params.correlation_id, exec_params.safe_log_ctx
            )
        else:
            return _handle_failed_provisioning_secure(
                result.unwrap_err(),
                exec_params.service,
                exec_params.domain,
                exec_params.correlation_id,
                exec_params.safe_log_ctx,
                retriability=retriability_of(result),
            )

    except Exception as exec_error:
        logger.error(f"🔥 [VirtualminTask] Provisioning execution failed: {exec_error}")

        # Classify and handle error
        error_type = ProvisioningErrorClassifier.classify_error(str(exec_error))

        log_security_event_safe(
            "virtualmin_provisioning_execution_failed",
            {
                "error": str(exec_error),
                "error_type": error_type.value,
                "context": exec_params.safe_log_ctx,
            },
            str(exec_params.service.id),
            exec_params.domain,
        )

        if isinstance(exec_error, RetryableProvisioningError):
            raise
        return {
            "success": False,
            "error": f"Execution failed: {exec_error}",
            "retriability": Retriability.UNKNOWN.value,
        }


def _execute_virtualmin_provisioning(
    service: Service,
    domain: str,
    params: VirtualminProvisioningParams,
    server: VirtualminServer | None,
    correlation_id: str,
) -> dict[str, Any]:
    """Legacy function - kept for backward compatibility."""
    safe_log_ctx = {
        "service_id": str(service.id),
        "domain": domain,
        "correlation_id": correlation_id,
    }

    # Create execution params and use new function
    exec_params = ProvisioningExecutionParams(
        service=service,
        domain=domain,
        username=params.get("username"),
        template=params.get("template", "Default"),
        server=server,
        correlation_id=correlation_id,
        safe_log_ctx=safe_log_ctx,
    )

    return _execute_virtualmin_provisioning_with_params(exec_params)


def _handle_successful_provisioning_secure(
    account: Any, service: Service, correlation_id: str, safe_log_ctx: dict[str, Any]
) -> dict[str, Any]:
    """Handle successful provisioning with enhanced security logging.

    Note: the AuditEvent for this transition is already emitted by
    VirtualminAccount's own post_save signal (account.status -> "active" is
    saved with update_fields=["status", ...] before this function runs,
    firing "virtualmin_account_status_changed"). An additional explicit
    "virtualmin_account_provisioned" event here was a redundant duplicate
    for the same account (#dedup) — removed in favor of the signal, which
    also covers the manual provisioning path the signal-less call did not.
    """
    # Converge once more after creation: a termination that landed while the
    # gateway was working must not leave a live account for a dead Service.
    service_id = str(service.id)
    transaction.on_commit(lambda: reconcile_virtualmin_service_state_async(service_id))
    try:
        # Log security event for successful provisioning
        log_security_event_safe(
            "virtualmin_account_provisioned_successfully",
            {
                "account_id": str(account.id),
                "domain": account.domain,
                "server_hostname": account.server.hostname,
                "status": account.status,
                "context": safe_log_ctx,
            },
            str(service.id),
            account.domain,
        )

        success_ctx = safe_log_ctx.copy()
        success_ctx.update(
            {
                "account_id": str(account.id),
                "server": account.server.hostname,
                "status": account.status,
            }
        )

        logger.info(f"✅ [VirtualminTask] Secure provisioning successful: {sanitize_log_parameters(success_ctx)}")

        return {
            "success": True,
            "account_id": str(account.id),
            "domain": account.domain,
            "server": account.server.hostname,
            "status": account.status,
            "correlation_id": correlation_id,
            "security_enhanced": True,
        }

    except Exception as audit_error:
        # Don't fail the whole operation if audit logging fails
        logger.warning(f"⚠️ [VirtualminTask] Audit logging failed (non-critical): {audit_error}")

        return {
            "success": True,
            "account_id": str(account.id),
            "domain": account.domain,
            "server": account.server.hostname,
            "status": account.status,
            "correlation_id": correlation_id,
            "security_enhanced": True,
            "audit_warning": "Audit logging partially failed",
        }


def _handle_successful_provisioning(account: Any, service: Service, correlation_id: str) -> dict[str, Any]:
    """Legacy function - kept for backward compatibility."""
    safe_log_ctx = {
        "service_id": str(service.id),
        "domain": account.domain,
        "correlation_id": correlation_id,
    }
    return _handle_successful_provisioning_secure(account, service, correlation_id, safe_log_ctx)


def _handle_failed_provisioning_secure(  # noqa: PLR0913  # Structured audit context is intentionally explicit
    error_msg: str,
    service: Service,
    domain: str,
    correlation_id: str,
    safe_log_ctx: dict[str, Any],
    *,
    retriability: Retriability = Retriability.UNKNOWN,
) -> dict[str, Any]:
    """Handle failure while preserving the service's explicit replay contract."""

    error_type = ProvisioningErrorClassifier.classify_error(error_msg)

    error_ctx = safe_log_ctx.copy()
    error_ctx.update(
        {
            "error": error_msg,
            "error_type": error_type.value,
            "retriability": retriability.value,
        }
    )

    logger.error(f"❌ [VirtualminTask] Secure provisioning failed: {sanitize_log_parameters(error_ctx)}")

    try:
        AuditService.log_event(
            AuditEventData(
                event_type="virtualmin_provisioning_failed",
                content_object=service,
                new_values={
                    "domain": domain,
                    "error": error_msg,
                    "error_type": error_type.value,
                    "service_id": str(service.id),
                    "customer_id": str(service.customer.id),
                    "provisioning_type": "automatic_secure",
                    "correlation_id": correlation_id,
                    "retriability": retriability.value,
                },
                description=f"VirtualMin secure provisioning failed for domain '{domain}': {error_msg}",
            ),
            context=AuditContext(
                actor_type="system",
                metadata={
                    "source_app": "provisioning",
                    "provisioning_event": True,
                    "provisioning_failure": True,
                    "security_enhanced": True,
                    "correlation_id": correlation_id,
                    "domain": domain,
                    "error_type": error_type.value,
                    "customer_id": str(service.customer.id),
                    "retryable": retriability is Retriability.RETRIABLE,
                    "retriability": retriability.value,
                },
            ),
        )

        log_security_event_safe(
            "virtualmin_provisioning_failed",
            {
                "error": error_msg,
                "error_type": error_type.value,
                "retryable": retriability is Retriability.RETRIABLE,
                "retriability": retriability.value,
                "context": error_ctx,
            },
            str(service.id),
            domain,
        )

    except Exception as audit_error:
        logger.warning(f"⚠️ [VirtualminTask] Audit logging failed for error case: {audit_error}")

    if retriability is Retriability.RETRIABLE:
        logger.warning(f"🔄 [VirtualminTask] Explicitly retryable error for {domain}: {error_type.value}")
        raise RetryableProvisioningError(error_msg)

    return {
        "success": False,
        "error": error_msg,
        "error_type": error_type.value,
        "correlation_id": correlation_id,
        "security_enhanced": True,
        "retriability": retriability.value,
    }


def _handle_failed_provisioning(error_msg: str, service: Service, domain: str, correlation_id: str) -> dict[str, Any]:
    """Legacy function - kept for backward compatibility."""
    safe_log_ctx = {
        "service_id": str(service.id),
        "domain": domain,
        "correlation_id": correlation_id,
    }
    return _handle_failed_provisioning_secure(error_msg, service, domain, correlation_id, safe_log_ctx)


def _handle_critical_provisioning_error_secure(
    error: Exception, domain: str, service_id: str, correlation_id: str, safe_log_ctx: dict[str, Any]
) -> dict[str, Any]:
    """Handle unexpected failures without inferring replay safety from text."""
    error_msg = str(error)
    error_type = ProvisioningErrorClassifier.classify_error(error_msg)
    retriability = Retriability.RETRIABLE if isinstance(error, RetryableProvisioningError) else Retriability.UNKNOWN

    critical_ctx = safe_log_ctx.copy()
    critical_ctx.update(
        {
            "error": error_msg,
            "error_type": error_type.value,
            "is_critical": True,
            "retriability": retriability.value,
        }
    )

    logger.exception(f"💥 [VirtualminTask] Critical secure provisioning error: {sanitize_log_parameters(critical_ctx)}")

    try:
        AuditService.log_event(
            AuditEventData(
                event_type="virtualmin_provisioning_critical_error",
                content_object=None,
                new_values={
                    "domain": domain,
                    "service_id": service_id,
                    "error": error_msg,
                    "error_type": error_type.value,
                    "provisioning_type": "automatic_secure",
                    "correlation_id": correlation_id,
                    "requires_investigation": True,
                    "retriability": retriability.value,
                },
                description=f"Critical error during secure VirtualMin provisioning for domain '{domain}': {error_msg}",
            ),
            context=AuditContext(
                actor_type="system",
                metadata={
                    "source_app": "provisioning",
                    "provisioning_event": True,
                    "critical_error": True,
                    "security_enhanced": True,
                    "correlation_id": correlation_id,
                    "domain": domain,
                    "error_type": error_type.value,
                    "requires_investigation": True,
                    "retryable": retriability is Retriability.RETRIABLE,
                    "retriability": retriability.value,
                },
            ),
        )

        log_security_event_safe(
            "virtualmin_provisioning_critical_error",
            {
                "error": error_msg,
                "error_type": error_type.value,
                "requires_investigation": True,
                "retriability": retriability.value,
                "context": critical_ctx,
            },
            service_id,
            domain,
        )

    except Exception as audit_error:
        logger.error(f"🔥 [VirtualminTask] Failed to log critical error audit event: {audit_error}")

    if retriability is Retriability.RETRIABLE:
        logger.warning(f"🔄 [VirtualminTask] Critical error is explicitly retryable: {error_type.value}")
        raise error

    logger.error(f"❌ [VirtualminTask] Critical error requires review: {error_type.value}")
    return {
        "success": False,
        "error": error_msg,
        "error_type": error_type.value,
        "correlation_id": correlation_id,
        "is_critical": True,
        "security_enhanced": True,
        "retriability": retriability.value,
    }


def _handle_critical_provisioning_error(
    error: Exception, domain: str, service_id: str, correlation_id: str
) -> dict[str, Any]:
    """Legacy function - kept for backward compatibility."""
    safe_log_ctx = {
        "service_id": service_id,
        "domain": domain,
        "correlation_id": correlation_id,
    }
    return _handle_critical_provisioning_error_secure(error, domain, service_id, correlation_id, safe_log_ctx)


def run_node_drain(drain_id: str, task_token: str | None = None) -> dict[str, Any]:
    try:
        result = NodeDrainService.run(UUID(drain_id), UUID(task_token) if task_token else None)
    except (ValueError, TypeError, NodeDrain.DoesNotExist) as error:
        return {"success": False, "error": str(error)}
    if result.is_err():
        return {"success": False, "error": result.unwrap_err()}
    drain = result.unwrap()
    return {
        "success": drain.status not in {"failed", "paused_needs_review"},
        "drain_id": str(drain.pk),
        "status": drain.status,
    }


def enqueue_virtualmin_migration(migration_id: str, timeout_seconds: int) -> str:
    return async_task(
        "apps.provisioning.virtualmin_tasks.run_virtualmin_migration",
        migration_id,
        timeout=timeout_seconds,
    )


_RECLAIM_GRACE_MINUTES = 30
_RECLAIM_BATCH = 5

# Backup/restore job recovery clocks: a queued job whose dispatch never arrived
# vs a running job past its own persisted execution deadline.
_JOB_DISPATCH_WINDOW_HOURS = 2
_JOB_DEADLINE_MARGIN_SECONDS = 300


def _audit_job(job_id: Any) -> None:
    """Emit the status-change audit for a CAS-updated backup/restore job."""
    from .virtualmin_signals import audit_job_status_transition  # noqa: PLC0415  # Circular

    job = VirtualminProvisioningJob.objects.filter(pk=job_id).first()
    if job is not None:
        audit_job_status_transition(job)


def _run_backup_restore_job(job_id: str, operation: str) -> dict[str, Any]:  # noqa: C901  # Cohesive claim→run→terminal pipeline
    """Shared token-claimed runner for backup/restore jobs. Never raises."""
    from uuid import uuid4  # noqa: PLC0415

    from .virtualmin_backup_service import BackupConfig, RestoreConfig, VirtualminBackupService  # noqa: PLC0415

    try:
        job = VirtualminProvisioningJob.objects.select_related("server", "account").get(pk=job_id)
    except VirtualminProvisioningJob.DoesNotExist:
        return {"status": "missing", "job_id": job_id}
    if job.account is None:
        if VirtualminProvisioningJob.objects.filter(
            pk=job_id, status="pending"
        ).update(  # fsm-bypass: CharField job status
            status="failed", status_message="Job has no account", next_retry_at=None, updated_at=timezone.now()
        ):
            _audit_job(job_id)
        return {"status": "failed", "job_id": job_id, "error": "no account"}

    token = uuid4()
    budget = int(job.parameters.get("task_budget_seconds", TASK_TIME_LIMIT))
    deadline = timezone.now() + timedelta(seconds=budget)
    if not VirtualminProvisioningJob.claim_execution(job.pk, token, deadline):
        return {"status": "stale", "job_id": job_id}
    # Audit the pending->running claim too, so the trail shows execution began.
    _audit_job(job.pk)

    def owns() -> bool:
        return VirtualminProvisioningJob.owns_execution(job.pk, token)

    service = VirtualminBackupService(job.server)
    params = job.parameters
    if operation == "backup_domain":
        config = BackupConfig(
            backup_type=str(params.get("backup_type", "full")),
            include_email=bool(params.get("include_email", True)),
            include_databases=bool(params.get("include_databases", True)),
            include_files=bool(params.get("include_files", True)),
            include_ssl=bool(params.get("include_ssl", True)),
        )
        result = service.backup_domain(account=job.account, config=config, progress_key=str(job.pk), ownership=owns)
    else:
        restore_config = RestoreConfig(
            backup_id=str(params.get("backup_id", "")),
            restore_email=bool(params.get("restore_email", True)),
            restore_databases=bool(params.get("restore_databases", True)),
            restore_files=bool(params.get("restore_files", True)),
            restore_ssl=bool(params.get("restore_ssl", True)),
            force_restore=bool(params.get("force_restore", False)),
        )

        def persist_note(note: dict[str, Any]) -> None:
            # Token-fenced parameter merge: evidence (e.g. the safety backup id)
            # is durable BEFORE any destructive dispatch, and a superseded
            # runner cannot write it.
            current = (
                VirtualminProvisioningJob.objects.filter(pk=job.pk, execution_token=token)
                .values_list("parameters", flat=True)
                .first()
            )
            if current is None:
                return
            VirtualminProvisioningJob.objects.filter(pk=job.pk, execution_token=token).update(
                parameters={**current, **note}, updated_at=timezone.now()
            )

        result = service.restore_domain(
            account=job.account,
            config=restore_config,
            target_server=job.server,
            progress_key=str(job.pk),
            ownership=owns,
            note_sink=persist_note,
        )

    if result.is_err():
        error = str(result.unwrap_err())
        if operation == "restore_domain" and retriability_of(result) is Retriability.UNKNOWN:
            # Uncertain mutation: park for operator attention; exclusion holds.
            rows = VirtualminProvisioningJob.finish_execution(
                job.pk, token, "attention", error, {"retriability": retriability_of(result).value}
            )
            if rows:
                _audit_job(job.pk)
            logger.warning("⚠️ [BackupJobs] restore job %s parked for attention: %s", job_id, error)
            return {"status": "attention" if rows else "superseded", "job_id": job_id, "error": error}
        rows = VirtualminProvisioningJob.finish_execution(
            job.pk, token, "failed", error, {"retriability": retriability_of(result).value}
        )
        if rows:
            _audit_job(job.pk)
        logger.warning("⚠️ [BackupJobs] %s job %s failed: %s", operation, job_id, error)
        return {"status": "failed" if rows else "superseded", "job_id": job_id, "error": error}
    rows = VirtualminProvisioningJob.finish_execution(job.pk, token, "completed", "", dict(result.unwrap()))
    if rows:
        _audit_job(job.pk)
    logger.info("✅ [BackupJobs] %s job %s completed", operation, job_id)
    return {"status": "completed" if rows else "superseded", "job_id": job_id}


def run_virtualmin_backup(job_id: str) -> dict[str, Any]:
    return _run_backup_restore_job(job_id, "backup_domain")


def run_virtualmin_restore(job_id: str) -> dict[str, Any]:
    return _run_backup_restore_job(job_id, "restore_domain")


_SPOOL_ORPHAN_MAX_AGE_HOURS = 48


def _sweep_spool_orphans(counts: dict[str, int]) -> None:
    """Remove crash-orphaned spool archives of both name families."""
    import re as _re  # noqa: PLC0415
    import time  # noqa: PLC0415
    from pathlib import Path  # noqa: PLC0415

    from apps.settings.services import SettingsService  # noqa: PLC0415

    spool = Path(str(SettingsService.get_setting("provisioning.migration_spool_dir", "/var/lib/praho/migration-spool")))
    if not spool.is_dir():
        return
    pattern = _re.compile(r"^(migration_[0-9a-f-]{36}|virtualmin_backup_[0-9a-f]{32})\.tar\.gz$")
    cutoff = time.time() - _SPOOL_ORPHAN_MAX_AGE_HOURS * 3600
    for path in spool.iterdir():
        try:
            if pattern.match(path.name) and path.is_file() and path.stat().st_mtime < cutoff:
                path.unlink()
                counts["spool_orphans_removed"] += 1
                logger.warning("⚠️ [VirtualminTask] Removed orphaned spool archive %s", path.name)
        except OSError:
            logger.exception("🔥 [VirtualminTask] Spool orphan sweep failed for %s", path)


def _reclaim_backup_restore_jobs(counts: dict[str, int]) -> None:
    """Two-clock recovery: dispatch window for pending, own deadline for running."""
    from .virtualmin_migration_models import SpoolReservation  # noqa: PLC0415

    now = timezone.now()
    dispatch_cutoff = now - timedelta(hours=_JOB_DISPATCH_WINDOW_HOURS)
    stale_pending = VirtualminProvisioningJob.objects.filter(
        operation__in=("backup_domain", "restore_domain"), status="pending", created_at__lt=dispatch_cutoff
    ).values_list("pk", flat=True)[:_RECLAIM_BATCH]
    for job_pk in stale_pending:
        rows = VirtualminProvisioningJob.objects.filter(
            pk=job_pk, status="pending"
        ).update(  # fsm-bypass: CharField job status
            status="failed",
            status_message="Dispatch lost: queued task never arrived",
            next_retry_at=None,
            updated_at=now,
        )
        if rows:
            _audit_job(job_pk)
        counts["jobs_dispatch_lost"] += rows

    overdue = VirtualminProvisioningJob.objects.filter(
        operation__in=("backup_domain", "restore_domain"), status="running"
    ).filter(
        models.Q(execution_deadline__lt=now - timedelta(seconds=_JOB_DEADLINE_MARGIN_SECONDS))
        | models.Q(execution_deadline__isnull=True, updated_at__lt=dispatch_cutoff)
    )[:_RECLAIM_BATCH]
    for job in overdue:
        # A killed restore worker is an UNCERTAIN mutation: park for operator
        # attention (retains the account-operation exclusion). Backups are
        # read-only remotely; failed is honest.
        takeover_status = "attention" if job.operation == "restore_domain" else "failed"
        rows = VirtualminProvisioningJob.take_over_execution(
            job.pk, takeover_status, "Worker interrupted; execution deadline exceeded"
        )
        if rows:
            # The takeover releases the job's spool reservations in the same
            # sweep — the stage-boundary fence stops the old runner first.
            SpoolReservation.objects.filter(owner=f"job:{job.pk}").delete()
            _audit_job(job.pk)
            counts["jobs_taken_over"] += rows
            logger.warning("⚠️ [BackupJobs] Took over %s job %s -> %s", job.operation, job.pk, takeover_status)


def reclaim_stalled_virtualmin_operations() -> dict[str, int]:
    """Recover migrations and drains whose only task delivery was lost.

    Drain-driven migrations run inline (no broker message to redeliver), and a
    checkpoint or enqueue can die between commit and dispatch. Without this
    sweep such rows strand non-terminal forever — holding the account lock and
    the capacity reservation while the source domain stays disabled.
    """
    from .virtualmin_migration_models import _TERMINAL_STATUSES, VirtualminMigration  # noqa: PLC0415  # Circular
    from .virtualmin_migration_service import migration_task_timeout  # noqa: PLC0415  # Circular

    stale = timezone.now() - timedelta(minutes=_RECLAIM_GRACE_MINUTES)
    counts = {
        "migrations_requeued": 0,
        "drains_requeued": 0,
        "drains_reviewed": 0,
        "jobs_dispatch_lost": 0,
        "jobs_taken_over": 0,
        "spool_orphans_removed": 0,
    }
    stalled_migrations = list(
        # needs_review is non-terminal but policy "stop": requeueing it would churn.
        # Oldest-first so newer stalls never starve older rows; the updated_at
        # bump after each dispatch is the per-row retry backoff.
        VirtualminMigration.objects.exclude(status__in=(*_TERMINAL_STATUSES, "needs_review"))
        .filter(updated_at__lt=stale)
        .filter(models.Q(worker_lease_expires_at__isnull=True) | models.Q(worker_lease_expires_at__lt=timezone.now()))
        .order_by("updated_at")
        .values_list("pk", flat=True)[:_RECLAIM_BATCH]
    )
    for migration_id in stalled_migrations:
        try:
            enqueue_virtualmin_migration(str(migration_id), migration_task_timeout())
            counts["migrations_requeued"] += 1
            logger.warning("⚠️ [VirtualminTask] Requeued stalled migration %s", migration_id)
        except Exception:
            logger.exception("🔥 [VirtualminTask] Reclaim enqueue failed: migration=%s", migration_id)
        finally:
            VirtualminMigration.objects.filter(pk=migration_id).update(updated_at=timezone.now())
    stalled_drains = list(
        NodeDrain.objects.filter(status__in=("pending", "running"), updated_at__lt=stale).order_by("updated_at")[
            :_RECLAIM_BATCH
        ]
    )
    for drain in stalled_drains:
        try:
            if drain.status == "pending":
                NodeDrainService._enqueue(drain.pk, drain.task_token)
                counts["drains_requeued"] += 1
            elif NodeDrainService.close_interrupted(drain.pk):
                # Never run() here: the worker may have checkpointed the drain
                # back to pending with a fresh token between selection and now,
                # and run() would execute the whole drain inside this sweep.
                counts["drains_reviewed"] += 1
        except Exception:
            logger.exception("🔥 [VirtualminTask] Reclaim failed: drain=%s", drain.pk)
        finally:
            NodeDrain.objects.filter(pk=drain.pk, status__in=("pending", "running")).update(updated_at=timezone.now())
    _reclaim_backup_restore_jobs(counts)
    _sweep_spool_orphans(counts)
    return counts


def run_virtualmin_migration(migration_id: str) -> dict[str, Any]:
    from uuid import UUID  # noqa: PLC0415

    from .virtualmin_migration_service import VirtualminMigrationService  # noqa: PLC0415

    try:
        result = VirtualminMigrationService().run(UUID(migration_id))
    except (TypeError, ValueError) as error:
        return {"success": False, "error": str(error)}
    if result.is_err():
        return {"success": False, "error": result.unwrap_err()}
    return {"success": True, **result.unwrap()}


def _migration_locked(account: VirtualminAccount) -> bool:
    from .virtualmin_migration_models import account_has_active_migration  # noqa: PLC0415

    locked = account_has_active_migration(account)
    if locked:
        logger.info("✅ [VirtualminTask] Migration lock: account=%s", account.pk)
    return locked


def reconcile_virtualmin_service_state(  # noqa: PLR0911  # Convergence matrix: one exit per state pair
    service_id: str,
) -> dict[str, Any]:
    """
    Idempotent convergence: read the COMMITTED Service + account state and
    make Virtualmin match it (#325 defect 4 — suspension/termination never
    propagated; reactivation was silently absorbed).

    active + no account      -> auto-provision (kill-switch gated, ADR-0019)
    active + suspended acct  -> unsuspend
    suspended/terminated/expired + active acct -> suspend (never delete —
    deletion stays protected/manual)
    """
    from apps.provisioning.virtualmin_service import (  # noqa: PLC0415  # Deferred: avoids circular import
        VirtualminProvisioningService,  # Circular: cross-app
    )

    service = Service.objects.filter(pk=service_id).first()
    if service is None:
        return {"success": False, "error": f"Service {service_id} not found"}

    account = VirtualminAccount.objects.filter(service=service).select_related("server").first()
    if account is not None and _migration_locked(account):
        return {"success": True, "action": "migration_locked"}

    if service.status == "active":
        if account is None:
            if not getattr(settings, "VIRTUALMIN_AUTO_PROVISIONING_ENABLED", True):
                logger.info(f"⏭️ [VirtualminTask] Auto-provisioning disabled — skipping {service_id}")
                return {"success": True, "action": "kill_switch_disabled"}
            from apps.provisioning.signals import (  # noqa: PLC0415  # Deferred: avoids circular import
                _trigger_automatic_virtualmin_provisioning,  # Circular: cross-app
            )

            _trigger_automatic_virtualmin_provisioning(service)
            return {"success": True, "action": "provisioning_triggered"}
        if account.status == "suspended":
            result = VirtualminProvisioningService(account.server).unsuspend_account(account)
            if result.is_err():
                return {"success": False, "action": "unsuspend", "error": str(result.unwrap_err())}
            _reconcile_again_if_state_moved(service, expected_status="active")
            return {"success": True, "action": "unsuspended"}
        return {"success": True, "action": "noop"}

    if service.status in ("suspended", "terminated", "expired"):
        if account is not None and account.status == "active":
            reason = service.suspension_reason or f"service_{service.status}"
            result = VirtualminProvisioningService(account.server).suspend_account(account, reason)
            if result.is_err():
                return {"success": False, "action": "suspend", "error": str(result.unwrap_err())}
            _reconcile_again_if_state_moved(service, expected_status=service.status)
            return {"success": True, "action": "suspended"}
        return {"success": True, "action": "noop"}

    return {"success": True, "action": "noop"}


def _reconcile_again_if_state_moved(service: Service, expected_status: str) -> None:
    """
    Snapshot-race guard: if the Service transitioned while our gateway call was
    in flight (e.g. terminated mid-unsuspend), the state we just converged to
    is already stale — queue one more reconcile to converge on the new truth.
    """
    current = Service.objects.filter(pk=service.pk).values_list("status", flat=True).first()
    if current is None or current == expected_status:
        return
    # For the suspend branch expected_status is the snapshot status; any of the
    # suspended-family statuses still map to the same converged account state.
    suspend_family = ("suspended", "terminated", "expired")
    if expected_status in suspend_family and current in suspend_family:
        return
    logger.info(f"🔄 [VirtualminTask] Service {service.pk} moved to '{current}' mid-reconcile — re-queuing")
    reconcile_virtualmin_service_state_async(str(service.pk))


def reconcile_divergent_services_task() -> dict[str, Any]:
    """
    Durable backstop (every 15 min): a lost reconcile enqueue (broker down at
    on_commit time) must not leave Service and Virtualmin divergent forever.
    Finds the divergence signatures directly and re-queues reconciliation.
    """
    suspended_family = ("suspended", "terminated", "expired")

    divergent_ids: set[str] = set()
    # (a) suspended-family Service with a live account
    for sid in VirtualminAccount.objects.filter(status="active", service__status__in=suspended_family).values_list(
        "service_id", flat=True
    )[:50]:
        divergent_ids.add(str(sid))
    # (b) active Service with a suspended account
    for sid in VirtualminAccount.objects.filter(status="suspended", service__status="active").values_list(
        "service_id", flat=True
    )[:50]:
        divergent_ids.add(str(sid))
    # (c) active hosting Service whose original on_commit enqueue was lost
    # before any VirtualminAccount row existed. Apply the hosting predicates
    # before the safety cap so unrelated services cannot starve this scan.
    for sid in (
        Service.objects.filter(
            status="active",
            virtualmin_account__isnull=True,
            service_plan__plan_type__in=Service.VIRTUALMIN_HOSTING_PLAN_TYPES,
        )
        .exclude(domain="")
        .order_by("pk")
        .values_list("pk", flat=True)[:50]
    ):
        divergent_ids.add(str(sid))

    queued = 0
    failed = 0
    for service_id in divergent_ids:
        try:
            reconcile_virtualmin_service_state_async(service_id)
            queued += 1
        except Exception:
            failed += 1
            logger.warning(
                "⚠️ [VirtualminTask] Failed to queue divergence reconcile for %s",
                service_id,
                exc_info=True,
            )

    if queued:
        logger.info(f"🔄 [VirtualminTask] Divergence backstop queued {queued} reconciliations")
    return {"success": failed == 0, "queued": queued, "failed": failed}


def reconcile_virtualmin_service_state_async(service_id: str) -> str:
    """Queue Virtualmin state reconciliation for a service."""
    return async_task(
        "apps.provisioning.virtualmin_tasks.reconcile_virtualmin_service_state",
        service_id,
        timeout=TASK_SOFT_TIME_LIMIT,
    )


def suspend_virtualmin_account(account_id: str, reason: str = "") -> dict[str, Any]:
    """
    Sync task to suspend Virtualmin account.

    Args:
        account_id: VirtualminAccount UUID
        reason: Suspension reason

    Returns:
        Dictionary with suspension result
    """
    logger.info(f"🔄 [VirtualminTask] Suspending account {account_id}")

    try:
        # Get account
        try:
            account = VirtualminAccount.objects.get(id=account_id)
        except VirtualminAccount.DoesNotExist:
            error_msg = f"Account {account_id} not found"
            logger.error(f"❌ [VirtualminTask] {error_msg}")
            return {"success": False, "error": error_msg}

        # Create provisioning service
        provisioning_service = VirtualminProvisioningService(account.server)

        if _migration_locked(account):
            return {"success": True, "action": "migration_locked"}

        # Execute suspension
        result = provisioning_service.suspend_account(account, reason)

        if result.is_ok():
            logger.info(f"✅ [VirtualminTask] Suspended {account.domain} successfully")
            return {"success": True, "account_id": str(account.id), "domain": account.domain, "reason": reason}
        else:
            error_msg = result.unwrap_err()
            logger.error(f"❌ [VirtualminTask] Suspension failed for {account.domain}: {error_msg}")

            retriability = retriability_of(result)
            if retriability is Retriability.RETRIABLE:
                raise RetryableProvisioningError(error_msg)

            return {"success": False, "error": error_msg, "retriability": retriability.value}

    except RetryableProvisioningError:
        raise

    except Exception as e:
        logger.exception(f"💥 [VirtualminTask] Error suspending account {account_id}: {e}")
        return {"success": False, "error": str(e), "retriability": Retriability.UNKNOWN.value}


def unsuspend_virtualmin_account(account_id: str) -> dict[str, Any]:
    """
    Sync task to unsuspend Virtualmin account.

    Args:
        account_id: VirtualminAccount UUID

    Returns:
        Dictionary with unsuspension result
    """
    logger.info(f"🔄 [VirtualminTask] Unsuspending account {account_id}")

    try:
        # Get account
        try:
            account = VirtualminAccount.objects.get(id=account_id)
        except VirtualminAccount.DoesNotExist:
            error_msg = f"Account {account_id} not found"
            logger.error(f"❌ [VirtualminTask] {error_msg}")
            return {"success": False, "error": error_msg}

        # Create provisioning service
        provisioning_service = VirtualminProvisioningService(account.server)

        if _migration_locked(account):
            return {"success": True, "action": "migration_locked"}

        # Execute unsuspension
        result = provisioning_service.unsuspend_account(account)

        if result.is_ok():
            logger.info(f"✅ [VirtualminTask] Unsuspended {account.domain} successfully")
            return {"success": True, "account_id": str(account.id), "domain": account.domain}
        else:
            error_msg = result.unwrap_err()
            logger.error(f"❌ [VirtualminTask] Unsuspension failed for {account.domain}: {error_msg}")

            retriability = retriability_of(result)
            if retriability is Retriability.RETRIABLE:
                raise RetryableProvisioningError(error_msg)

            return {"success": False, "error": error_msg, "retriability": retriability.value}

    except RetryableProvisioningError:
        raise

    except Exception as e:
        logger.exception(f"💥 [VirtualminTask] Error unsuspending account {account_id}: {e}")
        return {"success": False, "error": str(e), "retriability": Retriability.UNKNOWN.value}


def delete_virtualmin_account(account_id: str) -> dict[str, Any]:
    """
    Sync task to delete Virtualmin account.

    Args:
        account_id: VirtualminAccount UUID

    Returns:
        Dictionary with deletion result
    """
    logger.info(f"🔄 [VirtualminTask] Deleting account {account_id}")

    try:
        # Get account
        try:
            account = VirtualminAccount.objects.get(id=account_id)
        except VirtualminAccount.DoesNotExist:
            error_msg = f"Account {account_id} not found"
            logger.error(f"❌ [VirtualminTask] {error_msg}")
            return {"success": False, "error": error_msg}

        if _migration_locked(account):
            return {"success": True, "action": "migration_locked"}

        # Note: Protection check is handled in the service layer
        domain = account.domain  # Store for logging after deletion

        # Create provisioning service
        provisioning_service = VirtualminProvisioningService(account.server)

        # Execute deletion
        result = provisioning_service.delete_account(account)

        if result.is_ok():
            logger.info(f"✅ [VirtualminTask] Deleted {domain} successfully")
            return {"success": True, "account_id": str(account.id), "domain": domain}
        else:
            error_msg = result.unwrap_err()
            logger.error(f"❌ [VirtualminTask] Deletion failed for {domain}: {error_msg}")

            retriability = retriability_of(result)
            if retriability is Retriability.RETRIABLE:
                raise RetryableProvisioningError(error_msg)

            return {"success": False, "error": error_msg, "retriability": retriability.value}

    except RetryableProvisioningError:
        raise

    except Exception as e:
        logger.exception(f"💥 [VirtualminTask] Error deleting account {account_id}: {e}")
        return {"success": False, "error": str(e), "retriability": Retriability.UNKNOWN.value}


def health_check_virtualmin_servers() -> dict[str, Any]:
    """
    Periodic task to health check all Virtualmin servers.

    Returns:
        Dictionary with health check results
    """
    logger.info("🔄 [VirtualminTask] Starting server health checks")

    try:
        # Prevent concurrent health checks
        lock_key = "virtualmin_health_check_lock"
        if cache.get(lock_key):
            logger.info("⏭️ [VirtualminTask] Health check already running, skipping")
            return {"success": True, "message": "Already running"}

        # Lock must not outlive the 10-minute sweep cadence, or a crashed
        # worker would silently skip sweeps until the stale lock expires.
        cache.set(lock_key, True, 540)

        try:
            # Auto-failed servers stay in the sweep so they can recover;
            # operator-failed servers are left alone.
            servers = VirtualminServer.objects.filter(
                models.Q(status="active") | models.Q(status="failed", failed_by_health_check=True)
            )
            results: dict[str, Any] = {
                "total_servers": servers.count(),
                "healthy_servers": 0,
                "unhealthy_servers": 0,
                "servers": [],
            }

            management_service = VirtualminServerManagementService()

            for server in servers:
                logger.info(f"🏥 [VirtualminTask] Health checking {server.hostname}")

                health_result = management_service.health_check_server(server)

                server_result = {
                    "hostname": server.hostname,
                    "healthy": health_result.is_ok(),
                    "last_check": timezone.now().isoformat(),
                }

                if health_result.is_ok():
                    results["healthy_servers"] += 1
                    server_result["data"] = health_result.unwrap()
                else:
                    results["unhealthy_servers"] += 1
                    server_result["error"] = health_result.unwrap_err()

                results["servers"].append(server_result)

            logger.info(
                f"✅ [VirtualminTask] Health check completed: "
                f"{results['healthy_servers']}/{results['total_servers']} healthy"
            )

            results["reclaimed"] = reclaim_stalled_virtualmin_operations()

            return {"success": True, "results": results}

        finally:
            # Always release lock
            cache.delete(lock_key)

    except Exception as e:
        logger.exception(f"💥 [VirtualminTask] Error in health check: {e}")
        return {"success": False, "error": str(e)}


def update_virtualmin_server_statistics() -> dict[str, Any]:
    """
    Periodic task to update server statistics from Virtualmin.

    Returns:
        Dictionary with statistics update results
    """
    logger.info("🔄 [VirtualminTask] Updating server statistics")

    try:
        # Prevent concurrent statistics updates
        lock_key = "virtualmin_stats_update_lock"
        if cache.get(lock_key):
            logger.info("⏭️ [VirtualminTask] Statistics update already running, skipping")
            return {"success": True, "message": "Already running"}

        # Set lock for 1 hour
        cache.set(lock_key, True, 3600)

        try:
            # Auto-failed servers stay in the sweep so they can recover;
            # operator-failed servers are left alone.
            servers = VirtualminServer.objects.filter(
                models.Q(status="active") | models.Q(status="failed", failed_by_health_check=True)
            )
            results: dict[str, Any] = {
                "total_servers": servers.count(),
                "updated_servers": 0,
                "failed_servers": 0,
                "servers": [],
            }

            management_service = VirtualminServerManagementService()

            for server in servers:
                logger.info(f"📊 [VirtualminTask] Updating statistics for {server.hostname}")

                stats_result = management_service.update_server_statistics(server)

                server_result = {
                    "hostname": server.hostname,
                    "updated": stats_result.is_ok(),
                    "last_update": timezone.now().isoformat(),
                }

                if stats_result.is_ok():
                    results["updated_servers"] += 1
                    server_result["statistics"] = stats_result.unwrap()
                else:
                    results["failed_servers"] += 1
                    server_result["error"] = stats_result.unwrap_err()

                results["servers"].append(server_result)

            logger.info(
                f"✅ [VirtualminTask] Statistics update completed: "
                f"{results['updated_servers']}/{results['total_servers']} updated"
            )

            return {"success": True, "results": results}

        finally:
            # Always release lock
            cache.delete(lock_key)

    except Exception as e:
        logger.exception(f"💥 [VirtualminTask] Error updating statistics: {e}")
        return {"success": False, "error": str(e)}


# Operations retry_virtualmin_job knows how to recover; anything else found
# failed is terminal for the sweep (backup/restore jobs opt out separately).
_RETRYABLE_OPERATIONS = ("create_domain", "suspend_domain", "unsuspend_domain", "delete_domain", "migrate_domain")

# A claimed (pending) job whose retry task has not reconciled it within this
# window is presumed lost to a process death and returned to the failed pool.
_CLAIM_LEASE_MINUTES = 30


def retry_virtualmin_job(job_id: str, claim_nonce: str = "") -> dict[str, Any]:
    """One-off task: re-run a claimed failed job on its existing rows."""
    from apps.provisioning.virtualmin_service import (  # noqa: PLC0415  # Deferred: avoids circular import
        VirtualminProvisioningService,  # Circular: cross-app
    )

    try:
        job = VirtualminProvisioningJob.objects.select_related("server", "account", "account__service").get(pk=job_id)
    except VirtualminProvisioningJob.DoesNotExist:
        return {"success": False, "error": f"Job {job_id} not found"}

    # Fence: only the owner of THIS claim may execute. A re-delivered task, or
    # one whose claim was recovered and re-issued, finds the row not pending
    # (or carrying a different claim nonce) and discards itself.
    if not VirtualminProvisioningJob.start_claimed(job_id, timezone.now(), claim_nonce or None):
        logger.info(f"⏭️ [VirtualminTask] Discarding stale retry delivery for job {job_id}")
        return {"success": False, "action": "stale_claim_discarded"}
    job.refresh_from_db()

    service = VirtualminProvisioningService(job.server)
    result = service.retry_job(job)
    if result.is_ok():
        outcome = result.unwrap()
        if isinstance(outcome, dict):
            return {"success": True, "job_id": job_id, **outcome}
        return {"success": True, "job_id": job_id}
    return {"success": False, "job_id": job_id, "error": str(result.unwrap_err())}


def _recover_expired_claims(now: Any) -> int:
    """Claimed jobs (pending or running) whose lease expired return to the failed pool."""
    lease_cutoff = now - timedelta(minutes=_CLAIM_LEASE_MINUTES)
    return VirtualminProvisioningJob.recover_expired_claims(lease_cutoff, now + timedelta(minutes=5))


def process_failed_virtualmin_jobs() -> dict[str, Any]:
    """
    Retry sweep with a leased-claim protocol: each due failed job is claimed by
    a conditional update (attempt consumed at claim time, so a broken dispatch
    can never rearm the same attempt forever), then handed its own
    retry_virtualmin_job task which recovers on the EXISTING account+job rows.
    """
    logger.info("🔄 [VirtualminTask] Processing failed jobs")

    try:
        now = timezone.now()
        recovered_claims = _recover_expired_claims(now)

        # Exhausted jobs opt out of future sweeps entirely (existing
        # next_retry_at=None convention) instead of sitting armed forever.
        exhausted = VirtualminProvisioningJob.objects.filter(
            status="failed", retry_count__gte=models.F("max_retries"), next_retry_at__isnull=False
        ).update(next_retry_at=None)

        retryable_jobs = (
            VirtualminProvisioningJob.objects.filter(
                status="failed", retry_count__lt=models.F("max_retries"), next_retry_at__lte=now
            )
            .select_related("server", "account")
            .order_by("next_retry_at", "pk")  # deterministic fairness under the 50-job cap
        )

        results: dict[str, Any] = {
            "total_jobs": retryable_jobs.count(),
            "retried_jobs": 0,
            "skipped_jobs": 0,
            "recovered_claims": recovered_claims,
            "exhausted_jobs": exhausted,
            "jobs": [],
        }

        for job in retryable_jobs[:50]:  # Limit to 50 jobs per run
            try:
                # Validate BEFORE claiming: unsupported/orphaned jobs are
                # terminal, never counted as retried.
                if job.operation not in _RETRYABLE_OPERATIONS or job.account is None:
                    VirtualminProvisioningJob.terminalize(job.pk)
                    results["skipped_jobs"] += 1
                    results["jobs"].append({"job_id": str(job.id), "operation": job.operation, "status": "terminal"})
                    continue

                # Leased claim: concurrent sweeps lose cleanly; the attempt is
                # consumed here so retries are bounded even if dispatch breaks.
                if not VirtualminProvisioningJob.claim_for_retry(job.pk, now):
                    continue

                try:
                    dispatch_timeout = TASK_TIME_LIMIT
                    if job.operation == "migrate_domain":
                        from .virtualmin_migration_service import migration_task_timeout  # noqa: PLC0415

                        dispatch_timeout = migration_task_timeout()
                    task_id = async_task(
                        "apps.provisioning.virtualmin_tasks.retry_virtualmin_job",
                        str(job.id),
                        now.isoformat(),  # claim nonce: only this claim's task may run the job
                        timeout=dispatch_timeout,
                    )
                    VirtualminProvisioningJob.record_dispatch(job.pk, task_id)
                except Exception as enqueue_error:
                    # Enqueue failed: return the job to the failed pool with a
                    # future retry window instead of stranding it pending.
                    VirtualminProvisioningJob.restore_after_enqueue_failure(job.pk, now + timedelta(minutes=5))
                    results["skipped_jobs"] += 1
                    results["jobs"].append(
                        {
                            "job_id": str(job.id),
                            "operation": job.operation,
                            "status": "enqueue_failed",
                            "error": str(enqueue_error),
                        }
                    )
                    logger.warning(f"⚠️ [VirtualminTask] Failed to enqueue retry for job {job.id}: {enqueue_error}")
                    continue

                results["retried_jobs"] += 1
                results["jobs"].append(
                    {"job_id": str(job.id), "operation": job.operation, "status": "retried", "task_id": task_id}
                )
                logger.info(f"🔄 [VirtualminTask] Claimed and dispatched retry for job {job.id} ({job.operation})")

            except Exception as e:
                results["skipped_jobs"] += 1
                results["jobs"].append(
                    {"job_id": str(job.id), "operation": job.operation, "status": "skipped", "error": str(e)}
                )
                logger.warning(f"⚠️ [VirtualminTask] Failed to retry job {job.id}: {e}")

        logger.info(
            f"✅ [VirtualminTask] Job processing completed: "
            f"{results['retried_jobs']} retried, {results['skipped_jobs']} skipped, "
            f"{recovered_claims} expired claims recovered"
        )

        return {"success": True, "results": results}

    except Exception as e:
        logger.exception(f"💥 [VirtualminTask] Error processing failed jobs: {e}")
        return {"success": False, "error": str(e)}


# ===============================================================================
# TASK QUEUE WRAPPER FUNCTIONS
# ===============================================================================


def provision_virtualmin_account_async(params: VirtualminProvisioningParams | SecureTaskParameters) -> str:
    """Queue Virtualmin account provisioning task with secure parameter handling."""
    try:
        # Log task scheduling with sanitized parameters
        if isinstance(params, SecureTaskParameters):
            logger.info(
                f"🚀 [VirtualminTask] Scheduling secure provisioning task (hash: {params.parameter_hash[:16]}...)"
            )
        else:
            safe_params = sanitize_log_parameters(dict(params))
            logger.info(f"🚀 [VirtualminTask] Scheduling provisioning task: {safe_params}")

        # NOTE: no `retry=` — django-q2 1.9.0 has no such option; it would leak
        # into the task kwargs and TypeError on every dequeue. Retries are
        # DB-driven via VirtualminProvisioningJob + process_failed_virtualmin_jobs.
        return async_task(
            "apps.provisioning.virtualmin_tasks.provision_virtualmin_account",
            params,
            timeout=TASK_TIME_LIMIT,
        )

    except Exception as e:
        logger.error(f"🔥 [VirtualminTask] Failed to schedule provisioning task: {e}")

        # Log security event for task scheduling failures
        if isinstance(params, SecureTaskParameters):
            log_security_event_safe(
                "virtualmin_task_scheduling_failed",
                {"error": str(e), "parameter_hash": params.parameter_hash[:16] + "..."},
                None,
            )
        else:
            log_security_event_safe(
                "virtualmin_task_scheduling_failed",
                {"error": str(e), "params": sanitize_log_parameters(dict(params))},
                params.get("service_id") if isinstance(params, dict) else None,
            )

        raise


def suspend_virtualmin_account_async(account_id: str, reason: str = "") -> str:
    """Queue Virtualmin account suspension task."""
    return async_task(
        "apps.provisioning.virtualmin_tasks.suspend_virtualmin_account",
        account_id,
        reason,
        timeout=TASK_SOFT_TIME_LIMIT,
    )


def unsuspend_virtualmin_account_async(account_id: str) -> str:
    """Queue Virtualmin account unsuspension task."""
    return async_task(
        "apps.provisioning.virtualmin_tasks.unsuspend_virtualmin_account", account_id, timeout=TASK_SOFT_TIME_LIMIT
    )


def delete_virtualmin_account_async(account_id: str) -> str:
    """Queue Virtualmin account deletion task."""
    return async_task(
        "apps.provisioning.virtualmin_tasks.delete_virtualmin_account", account_id, timeout=TASK_TIME_LIMIT
    )


# ===============================================================================
# SCHEDULED TASKS SETUP
# ===============================================================================


def setup_virtualmin_scheduled_tasks() -> dict[str, str]:
    """Set up all Virtualmin scheduled tasks."""
    tasks_created = {}

    # Check for existing tasks first
    existing_tasks = list(
        ScheduleModel.objects.filter(
            name__in=["virtualmin-health-check", "virtualmin-statistics", "virtualmin-retry-failed-jobs"]
        ).values_list("name", flat=True)
    )

    # Health check every 10 minutes. UPSERT by name: skip-if-exists left
    # deployed installations on the old hourly cadence forever, starving
    # placement (is_healthy freshness << cadence).
    _, created = ScheduleModel.objects.update_or_create(
        name="virtualmin-health-check",
        defaults={
            "func": "apps.provisioning.virtualmin_tasks.health_check_virtualmin_servers",
            "schedule_type": "I",
            "minutes": 10,
            "cluster": "praho-cluster",
        },
    )
    tasks_created["health_check"] = "created" if created else "updated"

    # Divergence backstop every 15 minutes (durable recovery for lost
    # reconcile enqueues)
    _, created = ScheduleModel.objects.update_or_create(
        name="virtualmin-reconcile-divergence",
        defaults={
            "func": "apps.provisioning.virtualmin_tasks.reconcile_divergent_services_task",
            "schedule_type": "I",
            "minutes": 15,
            "cluster": "praho-cluster",
        },
    )
    tasks_created["reconcile_divergence"] = "created" if created else "updated"

    # Statistics update every 6 hours
    if "virtualmin-statistics" not in existing_tasks:
        schedule(
            "apps.provisioning.virtualmin_tasks.update_virtualmin_server_statistics",
            schedule_type="C",
            cron="0 */6 * * *",
            name="virtualmin-statistics",
            cluster="praho-cluster",
        )
        tasks_created["statistics"] = "created"
    else:
        tasks_created["statistics"] = "already_exists"

    # Process failed jobs every 15 minutes
    if "virtualmin-retry-failed-jobs" not in existing_tasks:
        schedule(
            "apps.provisioning.virtualmin_tasks.process_failed_virtualmin_jobs",
            schedule_type="I",
            minutes=15,
            name="virtualmin-retry-failed-jobs",
            cluster="praho-cluster",
        )
        tasks_created["retry_jobs"] = "created"
    else:
        tasks_created["retry_jobs"] = "already_exists"

    logger.info(f"✅ [VirtualminTask] Scheduled tasks setup: {tasks_created}")
    return tasks_created
