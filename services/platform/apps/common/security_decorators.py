"""
Security Decorators for Service Layer - PRAHO Platform
Comprehensive security wrappers addressing critical vulnerabilities.
"""

import functools
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from apps.common.constants import (
    CUSTOMER_DATA_ARG_POSITION,
    INVITATION_CUSTOMER_ARG_POSITION,
    INVITATION_ROLE_ARG_POSITION,
    INVITEE_EMAIL_ARG_POSITION,
    INVITER_ARG_POSITION,
    USER_DATA_ARG_POSITION,
)
from apps.common.types import Err, Ok, Result

from .validators import (
    _DEFAULT_RATE_LIMIT_REGISTRATION_PER_IP,
    BusinessLogicValidator,
    SecureErrorHandler,
    SecureInputValidator,
    log_security_event,
)

logger = logging.getLogger(__name__)


# ===============================================================================
# SECURITY DECORATOR PARAMETER OBJECTS
# ===============================================================================


@dataclass
class SecurityConfig:
    """Parameter object for security decorator configuration"""

    validation_type: str = "general"
    rate_limit_key: str | None = None
    rate_limit: int | None = None
    requires_permission: str | None = None
    log_attempts: bool = True
    prevent_timing_attacks: bool = True


# ===============================================================================
# COMPREHENSIVE SERVICE SECURITY DECORATOR
# ===============================================================================


def secure_service_method(
    config: SecurityConfig | None = None, **kwargs: Any
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """
    Master security decorator for service methods

    Args:
        validation_type: Type of validation ('user_registration', 'customer_data', 'invitation')
        rate_limit_key: Cache key prefix for rate limiting
        rate_limit: Number of attempts allowed per hour
        requires_permission: Required permission level
        log_attempts: Whether to log security events
        prevent_timing_attacks: Whether to normalize response times
    """
    # Use default config if none provided and merge with kwargs
    if config is None:
        config = SecurityConfig()

    # Override config with any direct kwargs for backward compatibility
    for key, value in kwargs.items():
        if hasattr(config, key):
            setattr(config, key, value)

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Result[Any, str]:
            start_time = time.time()
            request_ip = kwargs.get("request_ip", "unknown")
            user = kwargs.get("user")

            try:
                # Execute security checks
                _execute_security_checks(config, args, kwargs, request_ip, user)

                # Execute original function with atomic transaction
                result = _execute_protected_function(func, args, kwargs)

                # Log successful execution
                _log_success_event(config, func.__name__, user, request_ip)

                return Ok(result)

            except ValidationError as e:
                return _handle_validation_error(e, config, func.__name__, user, request_ip)

            except Exception as e:
                return _handle_unexpected_error(e, config, func.__name__, user, request_ip)

            finally:
                # Timing Attack Prevention
                if config.prevent_timing_attacks:
                    _normalize_response_time(start_time)

        return wrapper

    return decorator


# Legacy wrapper for backward compatibility
def secure_service_method_legacy(  # noqa: PLR0913
    validation_type: str = "general",
    rate_limit_key: str | None = None,
    rate_limit: int | None = None,
    requires_permission: str | None = None,
    log_attempts: bool = True,
    prevent_timing_attacks: bool = True,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Legacy wrapper for backward compatibility"""
    config = SecurityConfig(
        validation_type=validation_type,
        rate_limit_key=rate_limit_key,
        rate_limit=rate_limit,
        requires_permission=requires_permission,
        log_attempts=log_attempts,
        prevent_timing_attacks=prevent_timing_attacks,
    )
    return secure_service_method(config)


# ===============================================================================
# SPECIALIZED SECURITY DECORATORS
# ===============================================================================


def secure_user_registration(
    rate_limit: int = _DEFAULT_RATE_LIMIT_REGISTRATION_PER_IP,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Security decorator specifically for user registration methods"""
    return secure_service_method(
        validation_type="user_registration",
        rate_limit_key="registration",
        rate_limit=rate_limit,
        log_attempts=True,
        prevent_timing_attacks=True,
    )


def secure_customer_operation(requires_owner: bool = False) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Security decorator for customer-related operations"""
    permission = "owner" if requires_owner else "viewer"
    return secure_service_method(
        validation_type="customer_data", requires_permission=permission, log_attempts=True, prevent_timing_attacks=True
    )


def secure_invitation_system() -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Security decorator for invitation system"""
    return secure_service_method(
        validation_type="invitation",
        rate_limit_key="invitation",
        rate_limit=10,  # 10 invitations per hour
        requires_permission="owner",
        log_attempts=True,
        prevent_timing_attacks=True,
    )


# ===============================================================================
# ATOMIC BUSINESS LOGIC DECORATORS
# ===============================================================================


def atomic_with_retry(max_retries: int = 3, delay: float = 0.1) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """
    Atomic transaction with retry logic for race condition handling
    """

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            last_exception = None

            for attempt in range(max_retries):
                try:
                    with transaction.atomic():
                        return func(*args, **kwargs)

                except Exception as e:
                    last_exception = e
                    if attempt < max_retries - 1:
                        time.sleep(delay * (attempt + 1))  # Exponential backoff
                        logger.warning(f"🔄 [Security] Retry {attempt + 1} for {func.__name__}: {e}")
                    else:
                        logger.error(f"🔥 [Security] All retries failed for {func.__name__}: {e}")

            # Ensure we always have an exception to raise
            if last_exception is not None:
                raise last_exception
            else:
                raise RuntimeError("All retry attempts failed but no exception was captured")

        return wrapper

    return decorator


def prevent_race_conditions(
    lock_key_generator: Callable[..., Any],
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """
    Prevent race conditions using distributed locking
    """

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            # Generate unique lock key
            lock_key = f"race_lock:{lock_key_generator(*args, **kwargs)}"

            # Try to acquire lock
            if cache.add(lock_key, "locked", timeout=30):  # 30 second lock
                try:
                    return func(*args, **kwargs)
                finally:
                    cache.delete(lock_key)
            else:
                # Lock already held - potential race condition
                logger.warning(f"🚨 [Security] Race condition prevented for {func.__name__}")
                raise ValidationError(_("Operation in progress, please try again"))

        return wrapper

    return decorator


# ===============================================================================
# SECURITY DECORATOR HELPER FUNCTIONS
# ===============================================================================


def _execute_security_checks(
    config: SecurityConfig, args: tuple[Any, ...], kwargs: dict[str, Any], request_ip: str, user: Any
) -> None:
    """Execute all security checks for the decorator"""
    # 1. Rate Limiting Check
    if config.rate_limit_key and config.rate_limit:
        _check_rate_limit(config.rate_limit_key, config.rate_limit, request_ip, user)

    # 2. Input Validation
    if config.validation_type == "user_registration":
        _validate_user_registration_input(args, kwargs)
    elif config.validation_type == "customer_data":
        _validate_customer_data_input(args, kwargs)
    elif config.validation_type == "invitation":
        _validate_invitation_input(args, kwargs)

    # 3. Permission Validation
    if config.requires_permission:
        # Extract user and customer from request objects if available
        extracted_user, extracted_customer = _extract_user_and_customer(args, kwargs, user)
        _validate_permissions(extracted_user, extracted_customer, config.requires_permission)


def _execute_protected_function(func: Callable[..., Any], args: tuple[Any, ...], kwargs: dict[str, Any]) -> Any:
    """Execute the original function within an atomic transaction"""
    with transaction.atomic():
        return func(*args, **kwargs)


def _log_success_event(config: SecurityConfig, method_name: str, user: Any, request_ip: str) -> None:
    """Log successful method execution"""
    if config.log_attempts:
        log_security_event(
            "method_success",
            {"method": method_name, "validation_type": config.validation_type, "user_id": user.id if user else None},
            request_ip,
        )


def _handle_validation_error(
    e: ValidationError, config: SecurityConfig, method_name: str, user: Any, request_ip: str
) -> Result[Any, str]:
    """Handle validation errors with proper logging"""
    if config.log_attempts:
        log_security_event(
            "validation_failed",
            {
                "method": method_name,
                "error": str(e),
                "validation_type": config.validation_type,
                "user_id": user.id if user else None,
            },
            request_ip,
        )

    return Err(SecureErrorHandler.safe_error_response(e, config.validation_type))


def _handle_unexpected_error(
    e: Exception, config: SecurityConfig, method_name: str, user: Any, request_ip: str
) -> Result[Any, str]:
    """Handle unexpected errors with proper logging"""
    if config.log_attempts:
        log_security_event(
            "method_error", {"method": method_name, "error": str(e), "user_id": user.id if user else None}, request_ip
        )

    return Err(SecureErrorHandler.safe_error_response(e, "general"))


# ===============================================================================
# HELPER FUNCTIONS
# ===============================================================================


def _check_rate_limit(key_prefix: str, limit: int, request_ip: str, user: Any = None) -> None:
    """Check rate limiting with user and IP tracking"""
    identifiers = [request_ip]
    if user:
        identifiers.append(str(user.id))

    for identifier in identifiers:
        cache_key = f"rate_limit:{key_prefix}:{identifier}"
        try:
            # Try to get current count
            current_count = cache.get(cache_key, 0)

            if current_count >= limit:
                try:
                    log_security_event(
                        "rate_limit_exceeded",
                        {"key": key_prefix, "identifier": identifier, "limit": limit, "current": current_count},
                        request_ip,
                    )
                except Exception as e:
                    # Log the logging error but don't fail rate limiting
                    logger.warning(f"⚠️ [Security] Failed to log rate limit event: {e}")  # nosec B110 - Intentional exception handling with logging
                raise ValidationError(_("Rate limit exceeded"))

            # Increment counter with add/set pattern for race condition safety
            new_count = current_count + 1
            try:
                cache.set(cache_key, new_count, timeout=3600)
            except Exception as cache_err:
                # Fallback if cache.set fails
                logger.warning(f"🚨 [Security] Cache set failed for rate limiting key: {cache_key}: {cache_err}")
        except ValidationError:
            # Re-raise ValidationError (rate limit exceeded)
            raise
        except Exception as e:
            # If cache is not available, allow the request but log the issue
            logger.warning(f"🚨 [Security] Rate limiting failed due to cache issue: {e}")


def _validate_user_registration_input(args: tuple[Any, ...], kwargs: dict[str, Any]) -> None:
    """Validate user registration input data"""
    # Extract user_data from arguments
    user_data = None
    if len(args) >= USER_DATA_ARG_POSITION and isinstance(args[1], dict):
        user_data = args[1]
    elif "user_data" in kwargs:
        user_data = kwargs["user_data"]

    if user_data:
        SecureInputValidator.validate_user_data_dict(user_data)
        # Validation is complete - the service method will use the original args
        # Don't modify kwargs to avoid positional/keyword argument conflicts


def _validate_customer_data_input(args: tuple[Any, ...], kwargs: dict[str, Any]) -> None:
    """Validate customer data input"""
    customer_data = None
    if len(args) >= CUSTOMER_DATA_ARG_POSITION and isinstance(args[2], dict):
        customer_data = args[2]
    elif "customer_data" in kwargs:
        customer_data = kwargs["customer_data"]

    if customer_data:
        validated_customer_data = SecureInputValidator.validate_customer_data_dict(customer_data)
        # Validation is complete - the service method will use the original args
        # Don't modify kwargs to avoid positional/keyword argument conflicts

        # Also check business logic constraints
        BusinessLogicValidator.check_company_uniqueness(validated_customer_data, kwargs.get("request_ip"))


def _validate_invitation_input(args: tuple[Any, ...], kwargs: dict[str, Any]) -> None:
    """Validate invitation input data"""
    inviter = kwargs.get("inviter") or (args[1] if len(args) > INVITER_ARG_POSITION else None)
    invitee_email = kwargs.get("invitee_email") or (args[2] if len(args) > INVITEE_EMAIL_ARG_POSITION else None)
    customer = kwargs.get("customer") or (args[3] if len(args) > INVITATION_CUSTOMER_ARG_POSITION else None)
    role = kwargs.get("role", "viewer") or (args[4] if len(args) > INVITATION_ROLE_ARG_POSITION else "viewer")

    if (
        all([inviter, invitee_email, customer, role])
        and isinstance(invitee_email, str)
        and inviter is not None
        and hasattr(inviter, "id")
    ):
        BusinessLogicValidator.validate_invitation_request(
            inviter=inviter,
            invitee_email=invitee_email,
            customer=customer,
            role=role,
            user_id=inviter.id,
            request_ip=kwargs.get("request_ip"),
        )


def _extract_user_and_customer(args: tuple[Any, ...], kwargs: dict[str, Any], fallback_user: Any) -> tuple[Any, Any]:
    """Extract user and customer from request objects or kwargs"""
    user = fallback_user
    customer = kwargs.get("customer")

    # Check if second argument (after cls) is a request object with user and customer attributes
    if len(args) > 1:
        request_obj = args[1]
        if hasattr(request_obj, "customer"):
            customer = request_obj.customer or customer

            # Priority order for user extraction: created_by > inviter > user
            # This ensures we validate the permissions of the user performing the action
            if hasattr(request_obj, "created_by") and request_obj.created_by:
                user = request_obj.created_by
            elif hasattr(request_obj, "inviter") and request_obj.inviter:
                user = request_obj.inviter
            elif hasattr(request_obj, "user") and request_obj.user:
                user = request_obj.user

    return user, customer


def _validate_permissions(user: Any, customer: Any, required_role: str) -> None:
    """Validate user permissions for customer operations"""
    if user and customer:
        BusinessLogicValidator.validate_user_permissions(user, customer, required_role)


def _normalize_response_time(start_time: float, min_time: float = 0.1) -> None:
    """Ensure consistent response time to prevent timing attacks"""
    elapsed = time.time() - start_time
    if elapsed < min_time:
        time.sleep(min_time - elapsed)


# ===============================================================================
# AUDIT & MONITORING DECORATORS
# ===============================================================================


def audit_service_call(
    event_type: str, extract_details: Callable[..., Any] | None = None
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """
    Comprehensive audit logging for service method calls
    """

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            start_time = timezone.now()
            user = kwargs.get("user") or (args[0] if len(args) > 0 and hasattr(args[0], "id") else None)
            request_ip = kwargs.get("request_ip")

            # Extract additional details if provided
            details = {}
            if extract_details:
                try:
                    details = extract_details(*args, **kwargs)
                except Exception as e:
                    logger.warning(f"Failed to extract audit details: {e}")

            try:
                result = func(*args, **kwargs)

                # Log successful operation
                log_security_event(
                    f"{event_type}_success",
                    {
                        "method": func.__name__,
                        "duration_ms": (timezone.now() - start_time).total_seconds() * 1000,
                        "user_id": user.id if user else None,
                        **details,
                    },
                    request_ip,
                )

                return result

            except Exception as e:
                # Log failed operation
                log_security_event(
                    f"{event_type}_failed",
                    {
                        "method": func.__name__,
                        "duration_ms": (timezone.now() - start_time).total_seconds() * 1000,
                        "error": str(e)[:200],  # Truncate long errors
                        "user_id": user.id if user else None,
                        **details,
                    },
                    request_ip,
                )

                raise

        return wrapper

    return decorator


# ===============================================================================
# PERFORMANCE MONITORING DECORATORS
# ===============================================================================


def monitor_performance(
    max_duration_seconds: float = 5.0, alert_threshold: float = 2.0
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """
    Monitor method performance and alert on slow operations
    """

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            start_time = time.time()

            try:
                result = func(*args, **kwargs)
                duration = time.time() - start_time

                # Alert on slow operations
                if duration > alert_threshold:
                    logger.warning(f"⚠️ [Performance] Slow operation {func.__name__}: {duration:.2f}s")

                # Error on extremely slow operations
                if duration > max_duration_seconds:
                    logger.error(f"🐢 [Performance] Extremely slow operation {func.__name__}: {duration:.2f}s")

                return result

            except Exception as e:
                duration = time.time() - start_time
                logger.error(f"🔥 [Performance] Failed operation {func.__name__} after {duration:.2f}s: {e}")
                raise

        return wrapper

    return decorator
