"""
Virtualmin Django-Q2 Tasks - PRAHO Platform
Asynchronous provisioning tasks for Virtualmin operations.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import timedelta
from typing import Any, TypedDict

from django.conf import settings
from django.core.cache import cache
from django.db import models, transaction
from django.utils import timezone
from django_q.models import Schedule as ScheduleModel
from django_q.tasks import async_task, schedule

from apps.audit.services import AuditContext, AuditEventData, AuditService
from apps.provisioning.models import Service

from .security_utils import (
    IdempotencyManager,
    ProvisioningErrorClassifier,
    ProvisioningParametersValidator,
    SecureTaskParameters,
    log_security_event_safe,
    sanitize_log_parameters,
)
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

    except Exception as db_error:
        logger.error(f"🔥 [VirtualminTask] Database operation failed: {db_error}")
        IdempotencyManager.clear(context.idempotency_key)

        # Classify error for proper handling
        error_type = ProvisioningErrorClassifier.classify_error(str(db_error))

        if ProvisioningErrorClassifier.is_retryable(error_type):
            logger.warning(f"🔄 [VirtualminTask] Retryable error, will retry: {db_error}")
            raise db_error  # Trigger retry
        else:
            return {"success": False, "error": f"Database error: {db_error}"}


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

        if ProvisioningErrorClassifier.is_retryable(error_type):
            raise exec_error  # Trigger retry
        else:
            return {"success": False, "error": f"Execution failed: {exec_error}"}


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
    """Handle successful provisioning with enhanced security and audit logging."""
    # Converge once more after creation: a termination that landed while the
    # gateway was working must not leave a live account for a dead Service.
    service_id = str(service.id)
    transaction.on_commit(lambda: reconcile_virtualmin_service_state_async(service_id))
    try:
        # Enhanced audit logging with security metadata
        AuditService.log_event(
            AuditEventData(
                event_type="virtualmin_account_provisioned",
                content_object=account,
                new_values={
                    "account_id": str(account.id),
                    "domain": account.domain,
                    "server": account.server.hostname,
                    "service_id": str(service.id),
                    "customer_id": str(service.customer.id),
                    "provisioning_type": "automatic_secure",
                    "status": account.status,
                },
                description=f"VirtualMin account provisioned securely for domain '{account.domain}'",
            ),
            context=AuditContext(
                actor_type="system",
                metadata={
                    "source_app": "provisioning",
                    "provisioning_event": True,
                    "automatic_provisioning": True,
                    "security_enhanced": True,
                    "correlation_id": correlation_id,
                    "domain": account.domain,
                    "server_hostname": account.server.hostname,
                    "customer_id": str(service.customer.id),
                },
            ),
        )

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


def _handle_failed_provisioning_secure(
    error_msg: str, service: Service, domain: str, correlation_id: str, safe_log_ctx: dict[str, Any]
) -> dict[str, Any]:
    """Handle failed provisioning with enhanced security and error classification."""

    # Classify error type for proper handling
    error_type = ProvisioningErrorClassifier.classify_error(error_msg)

    error_ctx = safe_log_ctx.copy()
    error_ctx.update(
        {
            "error": error_msg,
            "error_type": error_type.value,
        }
    )

    logger.error(f"❌ [VirtualminTask] Secure provisioning failed: {sanitize_log_parameters(error_ctx)}")

    try:
        # Enhanced audit logging with error classification
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
                    "retryable": ProvisioningErrorClassifier.is_retryable(error_type),
                },
            ),
        )

        # Log security event for provisioning failures
        log_security_event_safe(
            "virtualmin_provisioning_failed",
            {
                "error": error_msg,
                "error_type": error_type.value,
                "retryable": ProvisioningErrorClassifier.is_retryable(error_type),
                "context": error_ctx,
            },
            str(service.id),
            domain,
        )

    except Exception as audit_error:
        logger.warning(f"⚠️ [VirtualminTask] Audit logging failed for error case: {audit_error}")

    # Check if this is a retryable error using enhanced classification
    if ProvisioningErrorClassifier.is_retryable(error_type):
        logger.warning(f"🔄 [VirtualminTask] Retryable error for {domain}, will retry: {error_type.value}")
        raise Exception(error_msg)  # Trigger retry in django-q2

    return {
        "success": False,
        "error": error_msg,
        "error_type": error_type.value,
        "correlation_id": correlation_id,
        "security_enhanced": True,
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
    """Handle critical provisioning errors with enhanced security and classification."""
    error_msg = str(error)
    error_type = ProvisioningErrorClassifier.classify_error(error_msg)

    critical_ctx = safe_log_ctx.copy()
    critical_ctx.update(
        {
            "error": error_msg,
            "error_type": error_type.value,
            "is_critical": True,
        }
    )

    logger.exception(f"💥 [VirtualminTask] Critical secure provisioning error: {sanitize_log_parameters(critical_ctx)}")

    # Log critical error with enhanced security context
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
                    "retryable": ProvisioningErrorClassifier.is_retryable(error_type),
                },
            ),
        )

        # Log security event for critical errors
        log_security_event_safe(
            "virtualmin_provisioning_critical_error",
            {
                "error": error_msg,
                "error_type": error_type.value,
                "requires_investigation": True,
                "context": critical_ctx,
            },
            service_id,
            domain,
        )

    except Exception as audit_error:
        logger.error(f"🔥 [VirtualminTask] Failed to log critical error audit event: {audit_error}")

    # Determine if error should trigger retry based on classification
    if ProvisioningErrorClassifier.is_retryable(error_type):
        logger.warning(f"🔄 [VirtualminTask] Critical error is retryable: {error_type.value}")
        raise error  # Re-raise to trigger retry
    else:
        logger.error(f"❌ [VirtualminTask] Critical error is permanent: {error_type.value}")
        return {
            "success": False,
            "error": error_msg,
            "error_type": error_type.value,
            "correlation_id": correlation_id,
            "is_critical": True,
            "security_enhanced": True,
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
            return {"success": True, "action": "unsuspended"}
        return {"success": True, "action": "noop"}

    if service.status in ("suspended", "terminated", "expired"):
        if account is not None and account.status == "active":
            reason = service.suspension_reason or f"service_{service.status}"
            result = VirtualminProvisioningService(account.server).suspend_account(account, reason)
            if result.is_err():
                return {"success": False, "action": "suspend", "error": str(result.unwrap_err())}
            return {"success": True, "action": "suspended"}
        return {"success": True, "action": "noop"}

    return {"success": True, "action": "noop"}


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

        # Execute suspension
        result = provisioning_service.suspend_account(account, reason)

        if result.is_ok():
            logger.info(f"✅ [VirtualminTask] Suspended {account.domain} successfully")
            return {"success": True, "account_id": str(account.id), "domain": account.domain, "reason": reason}
        else:
            error_msg = result.unwrap_err()
            logger.error(f"❌ [VirtualminTask] Suspension failed for {account.domain}: {error_msg}")

            if _is_retryable_error(error_msg):
                raise Exception(error_msg)  # Trigger retry

            return {"success": False, "error": error_msg}

    except Exception as e:
        logger.exception(f"💥 [VirtualminTask] Error suspending account {account_id}: {e}")
        raise


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

        # Execute unsuspension
        result = provisioning_service.unsuspend_account(account)

        if result.is_ok():
            logger.info(f"✅ [VirtualminTask] Unsuspended {account.domain} successfully")
            return {"success": True, "account_id": str(account.id), "domain": account.domain}
        else:
            error_msg = result.unwrap_err()
            logger.error(f"❌ [VirtualminTask] Unsuspension failed for {account.domain}: {error_msg}")

            if _is_retryable_error(error_msg):
                raise Exception(error_msg)  # Trigger retry

            return {"success": False, "error": error_msg}

    except Exception as e:
        logger.exception(f"💥 [VirtualminTask] Error unsuspending account {account_id}: {e}")
        raise


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

            if _is_retryable_error(error_msg):
                raise Exception(error_msg)  # Trigger retry

            return {"success": False, "error": error_msg}

    except Exception as e:
        logger.exception(f"💥 [VirtualminTask] Error deleting account {account_id}: {e}")
        raise


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
_RETRYABLE_OPERATIONS = ("create_domain", "suspend_domain", "unsuspend_domain", "delete_domain")

# A claimed (pending) job whose retry task has not reconciled it within this
# window is presumed lost to a process death and returned to the failed pool.
_CLAIM_LEASE_MINUTES = 15


def retry_virtualmin_job(job_id: str) -> dict[str, Any]:
    """One-off task: re-run a claimed failed job on its existing rows."""
    from apps.provisioning.virtualmin_service import (  # noqa: PLC0415  # Deferred: avoids circular import
        VirtualminProvisioningService,  # Circular: cross-app
    )

    try:
        job = VirtualminProvisioningJob.objects.select_related("server", "account", "account__service").get(pk=job_id)
    except VirtualminProvisioningJob.DoesNotExist:
        return {"success": False, "error": f"Job {job_id} not found"}

    service = VirtualminProvisioningService(job.server)
    result = service.retry_job(job)
    if result.is_ok():
        return {"success": True, "job_id": job_id}
    return {"success": False, "job_id": job_id, "error": str(result.unwrap_err())}


def _recover_expired_claims(now: Any) -> int:
    """Pending jobs whose claim lease expired go back to the failed pool."""
    lease_cutoff = now - timedelta(minutes=_CLAIM_LEASE_MINUTES)
    return VirtualminProvisioningJob.objects.filter(
        status="pending", claimed_at__isnull=False, claimed_at__lt=lease_cutoff
    ).update(status="failed", next_retry_at=now + timedelta(minutes=5))


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

        retryable_jobs = VirtualminProvisioningJob.objects.filter(
            status="failed", retry_count__lt=models.F("max_retries"), next_retry_at__lte=now
        ).select_related("server", "account")

        results: dict[str, Any] = {
            "total_jobs": retryable_jobs.count(),
            "retried_jobs": 0,
            "skipped_jobs": 0,
            "recovered_claims": recovered_claims,
            "jobs": [],
        }

        for job in retryable_jobs[:50]:  # Limit to 50 jobs per run
            try:
                # Validate BEFORE claiming: unsupported/orphaned jobs are
                # terminal, never counted as retried.
                if job.operation not in _RETRYABLE_OPERATIONS or job.account is None:
                    VirtualminProvisioningJob.objects.filter(pk=job.pk, status="failed").update(next_retry_at=None)
                    results["skipped_jobs"] += 1
                    results["jobs"].append({"job_id": str(job.id), "operation": job.operation, "status": "terminal"})
                    continue

                # Leased claim: concurrent sweeps lose cleanly; the attempt is
                # consumed here so retries are bounded even if dispatch breaks.
                claimed = VirtualminProvisioningJob.objects.filter(
                    pk=job.pk,
                    status="failed",
                    retry_count__lt=models.F("max_retries"),
                    next_retry_at__lte=now,
                ).update(status="pending", retry_count=models.F("retry_count") + 1, claimed_at=now)
                if not claimed:
                    continue

                try:
                    task_id = async_task(
                        "apps.provisioning.virtualmin_tasks.retry_virtualmin_job",
                        str(job.id),
                        timeout=TASK_TIME_LIMIT,
                    )
                except Exception as enqueue_error:
                    # Enqueue failed: return the job to the failed pool with a
                    # future retry window instead of stranding it pending.
                    VirtualminProvisioningJob.objects.filter(pk=job.pk, status="pending").update(
                        status="failed",
                        claimed_at=None,
                        next_retry_at=now + timedelta(minutes=5),
                    )
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


def _is_retryable_error(error_message: str) -> bool:
    """
    Determine if an error is retryable.

    Args:
        error_message: Error message to analyze

    Returns:
        True if error should be retried
    """
    retryable_patterns = [
        "connection timeout",
        "connection error",
        "server error",
        "timeout",
        "temporarily unavailable",
        "service unavailable",
        "rate limit",
        "network error",
        "dns error",
    ]

    error_lower = error_message.lower()
    return any(pattern in error_lower for pattern in retryable_patterns)


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
