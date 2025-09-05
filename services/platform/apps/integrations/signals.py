"""
Streamlined integrations signals for PRAHO Platform
Focus ONLY on webhook delivery success/failure tracking for reliability monitoring.
"""

import logging
from typing import Any

from django.db.models.signals import post_save, pre_save
from django.dispatch import receiver

from apps.audit.services import IntegrationsAuditService

from .models import WebhookDelivery, WebhookEvent

logger = logging.getLogger(__name__)

# Business constants for webhook reliability monitoring
WEBHOOK_RELIABILITY_THRESHOLDS: dict[str, Any] = {
    "response_time_excellent_ms": 1000,  # < 1s is excellent
    "response_time_good_ms": 3000,  # < 3s is good
    "response_time_poor_ms": 10000,  # > 10s is poor
    "max_retry_attempts": 5,  # Max retries before giving up
    "suspicious_failure_threshold": 10,  # Multiple failures from same IP
    "security_alert_retry_count": 3,  # Alert on repeated failures
    "sla_breach_retry_threshold": 3,  # SLA breach threshold for critical services
}

# Romanian business integration priorities
ROMANIAN_SERVICE_PRIORITIES: dict[str, str] = {
    "efactura": "critical",  # e-Factura integration is mandatory
    "bank_bt": "high",  # Banca Transilvania payments
    "bank_bcr": "high",  # BCR payments
    "stripe": "high",  # International payments
    "paypal": "medium",  # Alternative payments
    "virtualmin": "high",  # Server management
    "cpanel": "medium",  # Alternative hosting
    "registrar_namecheap": "medium",  # Domain management
    "registrar_godaddy": "low",  # Secondary registrar
    "other": "low",  # Generic integrations
}


@receiver(pre_save, sender=WebhookEvent)
def capture_webhook_status_change(sender: type[WebhookEvent], instance: WebhookEvent, **kwargs: Any) -> None:
    """
    Capture webhook status changes to track processing transitions.

    This pre_save signal captures the old status and timing so we can analyze
    performance and reliability in post_save.
    """
    try:
        if instance.pk:
            # Get the old instance from database to compare status and timing
            old_instance = WebhookEvent.objects.get(pk=instance.pk)
            instance._old_status = old_instance.status  # type: ignore[attr-defined]
            instance._old_processed_at = old_instance.processed_at  # type: ignore[attr-defined]
            instance._old_retry_count = old_instance.retry_count  # type: ignore[attr-defined]

            # Calculate response time if transitioning to processed
            if old_instance.status == "pending" and instance.status == "processed" and instance.processed_at:
                processing_duration = instance.processed_at - instance.received_at
                instance._response_time_ms = int(processing_duration.total_seconds() * 1000)  # type: ignore[attr-defined]
            else:
                instance._response_time_ms = None  # type: ignore[attr-defined]
        else:
            # New webhook - no old status
            instance._old_status = None  # type: ignore[attr-defined]
            instance._old_processed_at = None  # type: ignore[attr-defined]
            instance._old_retry_count = 0  # type: ignore[attr-defined]
            instance._response_time_ms = None  # type: ignore[attr-defined]

    except WebhookEvent.DoesNotExist:
        # Edge case: instance has PK but doesn't exist in DB
        instance._old_status = None  # type: ignore[attr-defined]
        instance._old_processed_at = None  # type: ignore[attr-defined]
        instance._old_retry_count = 0  # type: ignore[attr-defined]
        instance._response_time_ms = None  # type: ignore[attr-defined]
    except Exception as e:
        logger.error(f"🔥 [Integrations Signal] Failed to capture old webhook state for {instance.pk}: {e}")
        instance._old_status = None  # type: ignore[attr-defined]
        instance._old_processed_at = None  # type: ignore[attr-defined]
        instance._old_retry_count = 0  # type: ignore[attr-defined]
        instance._response_time_ms = None  # type: ignore[attr-defined]


@receiver(post_save, sender=WebhookEvent)
def log_webhook_reliability_events(
    sender: type[WebhookEvent], instance: WebhookEvent, created: bool, **kwargs: Any
) -> None:
    """
    Log webhook reliability events focusing on service health monitoring.

    Events tracked:
    - Successful webhook processing (with performance metrics)
    - Webhook processing failures (with error analysis)
    - Retry exhaustion (when max attempts reached)
    - Security indicators (suspicious patterns)
    """
    try:
        # Skip logging for newly created pending webhooks
        if created and instance.status == "pending":
            return

        # Handle status transitions for existing webhooks
        old_status = getattr(instance, "_old_status", None)
        old_retry_count = getattr(instance, "_old_retry_count", 0)
        response_time_ms = getattr(instance, "_response_time_ms", None)

        # Log successful processing
        if old_status == "pending" and instance.status == "processed":
            _log_webhook_success(instance, response_time_ms or 0)

        # Log failures
        elif old_status in ["pending", "failed"] and instance.status == "failed":
            # Distinguish between first failure and retry failure
            if old_retry_count < instance.retry_count:
                _log_webhook_failure(instance, is_retry=True)

                # Check if retries are exhausted
                if instance.retry_count >= WEBHOOK_RELIABILITY_THRESHOLDS["max_retry_attempts"]:
                    _log_webhook_retry_exhausted(instance)
            else:
                _log_webhook_failure(instance, is_retry=False)

        # Log skipped webhooks (duplicates detected)
        elif instance.status == "skipped":
            logger.info(
                f"📋 [Integrations] Webhook skipped: {instance.source}.{instance.event_type} - {instance.error_message}"
            )

    except Exception as e:
        # Never let audit logging break webhook processing
        logger.error(f"🔥 [Integrations Signal] Failed to log webhook event for {instance.event_id}: {e}")


@receiver(post_save, sender=WebhookDelivery)
def log_outbound_webhook_events(
    sender: type[WebhookDelivery], instance: WebhookDelivery, created: bool, **kwargs: Any
) -> None:
    """
    Log outbound webhook delivery events for customer webhook reliability.

    This tracks webhooks we send TO customers about their services.
    """
    try:
        # Only log when delivery status changes to final states
        if not created and instance.status in ["delivered", "failed"]:
            _log_outbound_webhook_result(instance)

    except Exception as e:
        logger.error(f"🔥 [Integrations Signal] Failed to log outbound webhook for {instance.id}: {e}")


def _log_webhook_success(webhook_event: WebhookEvent, response_time_ms: int) -> None:
    """Log successful webhook processing with performance analysis"""
    try:
        # Analyze performance metrics
        performance_grade = "excellent"
        if response_time_ms > WEBHOOK_RELIABILITY_THRESHOLDS["response_time_poor_ms"]:
            performance_grade = "poor"
        elif response_time_ms > WEBHOOK_RELIABILITY_THRESHOLDS["response_time_good_ms"]:
            performance_grade = "good"
        elif response_time_ms > WEBHOOK_RELIABILITY_THRESHOLDS["response_time_excellent_ms"]:
            performance_grade = "fair"

        # Build reliability context
        service_priority = ROMANIAN_SERVICE_PRIORITIES.get(webhook_event.source, "low")
        reliability_context = {
            "service_priority": service_priority,
            "performance_grade": performance_grade,
            "romanian_compliance_critical": service_priority in ["critical", "high"],
            "sla_impact": "none" if performance_grade in ["excellent", "good"] else "minor",
            "customer_experience": "positive",
        }

        IntegrationsAuditService.log_webhook_success(
            webhook_event=webhook_event,
            response_time_ms=response_time_ms,
            response_status=200,  # Success assumed
            reliability_context=reliability_context,
        )

        logger.info(
            f"✅ [Integrations] Webhook processed: {webhook_event.source}.{webhook_event.event_type} ({response_time_ms}ms, {performance_grade})"
        )

    except Exception as e:
        logger.error(f"🔥 [Integrations] Failed to log webhook success: {e}")


def _log_webhook_failure(webhook_event: WebhookEvent, is_retry: bool = False) -> None:
    """Log webhook processing failure with error analysis"""
    try:
        # Analyze error patterns
        error_type = _classify_error_type(webhook_event.error_message)
        security_flags = _analyze_security_indicators(webhook_event)

        # Build error details
        error_details = {
            "error_type": error_type,
            "category": "retry_attempt" if is_retry else "initial_failure",
            "service_impact": _assess_service_impact(webhook_event, error_type),
            "pattern": "repeated" if webhook_event.retry_count > 1 else "isolated",
            "endpoint_status": "degraded" if is_retry else "unknown",
        }

        # Build reliability context
        service_priority = ROMANIAN_SERVICE_PRIORITIES.get(webhook_event.source, "low")
        reliability_context = {
            "service_priority": service_priority,
            "critical_service_affected": service_priority in ["critical", "high"],
            "romanian_compliance_impact": service_priority == "critical",
            "customer_impact_level": "high" if service_priority == "critical" else "medium",
            "sla_breach": webhook_event.retry_count >= WEBHOOK_RELIABILITY_THRESHOLDS["sla_breach_retry_threshold"]
            and service_priority == "critical",
        }

        IntegrationsAuditService.log_webhook_failure(
            webhook_event=webhook_event,
            error_details=error_details,
            security_flags=security_flags,
            reliability_context=reliability_context,
        )

        # Log appropriate level based on severity
        log_level = logger.warning if is_retry else logger.error
        retry_info = f" (retry {webhook_event.retry_count})" if is_retry else ""
        log_level(
            f"❌ [Integrations] Webhook failed: {webhook_event.source}.{webhook_event.event_type} - {error_type}{retry_info}"
        )

    except Exception as e:
        logger.error(f"🔥 [Integrations] Failed to log webhook failure: {e}")


def _log_webhook_retry_exhausted(webhook_event: WebhookEvent) -> None:
    """Log webhook retry exhaustion for alerting and investigation"""
    try:
        service_priority = ROMANIAN_SERVICE_PRIORITIES.get(webhook_event.source, "low")

        # Build reliability impact assessment
        reliability_impact = {
            "service_priority": service_priority,
            "sla_breach": service_priority in ["critical", "high"],
            "customer_impact_level": "high" if service_priority == "critical" else "medium",
            "customer_visible": service_priority in ["critical", "high"],
            "requires_escalation": service_priority == "critical",
            "compliance_risk": service_priority == "critical",  # e-Factura failures are compliance risks
        }

        IntegrationsAuditService.log_webhook_retry_exhausted(
            webhook_event=webhook_event,
            total_attempts=webhook_event.retry_count,
            final_error=webhook_event.error_message,
            reliability_impact=reliability_impact,
        )

        # Alert based on service priority
        if service_priority == "critical":
            logger.critical(
                f"🚨 [Integrations] CRITICAL webhook failure: {webhook_event.source}.{webhook_event.event_type} - REQUIRES IMMEDIATE ATTENTION"
            )
        else:
            logger.error(
                f"🔥 [Integrations] Webhook retry exhausted: {webhook_event.source}.{webhook_event.event_type} after {webhook_event.retry_count} attempts"
            )

    except Exception as e:
        logger.error(f"🔥 [Integrations] Failed to log retry exhaustion: {e}")


def _log_outbound_webhook_result(webhook_delivery: WebhookDelivery) -> None:
    """Log outbound webhook delivery results for customer service reliability"""
    try:
        if webhook_delivery.status == "delivered":
            # Calculate response time if available
            response_time_ms = 0
            if webhook_delivery.delivered_at and webhook_delivery.scheduled_at:
                response_duration = webhook_delivery.delivered_at - webhook_delivery.scheduled_at
                response_time_ms = int(response_duration.total_seconds() * 1000)

            logger.info(
                f"📤 [Integrations] Outbound webhook delivered: {webhook_delivery.customer} - {webhook_delivery.event_type} ({response_time_ms}ms)"
            )

        elif webhook_delivery.status == "failed":
            logger.warning(
                f"📤 [Integrations] Outbound webhook failed: {webhook_delivery.customer} - {webhook_delivery.event_type} (retry {webhook_delivery.retry_count})"
            )

    except Exception as e:
        logger.error(f"🔥 [Integrations] Failed to log outbound webhook: {e}")


def _classify_error_type(error_message: str) -> str:
    """Classify webhook error type for analysis"""
    if not error_message:
        return "unknown"

    error_lower = error_message.lower()

    # Error type mappings to reduce complexity
    error_checkers = [
        (_is_timeout_error, "timeout"),
        (_is_service_unavailable_error, "service_unavailable"),
        (_is_authentication_error, "authentication_error"),
        (_is_validation_error, "validation_error"),
        (_is_server_error, "server_error"),
        (_is_parsing_error, "parsing_error"),
    ]

    # Check each error type in order
    for checker_func, error_type in error_checkers:
        if checker_func(error_lower):
            return error_type

    return "processing_error"


def _is_timeout_error(error_lower: str) -> bool:
    """Check if error is related to timeouts or connectivity"""
    return any(term in error_lower for term in ["timeout", "connection", "network", "unreachable"])


def _is_service_unavailable_error(error_lower: str) -> bool:
    """Check if error indicates service unavailability"""
    return any(term in error_lower for term in ["502", "503", "504", "bad gateway", "service unavailable"])


def _is_authentication_error(error_lower: str) -> bool:
    """Check if error is related to authentication"""
    return any(term in error_lower for term in ["401", "403", "unauthorized", "forbidden", "authentication"])


def _is_validation_error(error_lower: str) -> bool:
    """Check if error is related to request validation"""
    return any(term in error_lower for term in ["400", "bad request", "invalid", "malformed"])


def _is_server_error(error_lower: str) -> bool:
    """Check if error is a server-side error"""
    return any(term in error_lower for term in ["500", "internal server error"])


def _is_parsing_error(error_lower: str) -> bool:
    """Check if error is related to data parsing"""
    return any(term in error_lower for term in ["json", "parse", "decode", "format"])


def _analyze_security_indicators(webhook_event: WebhookEvent) -> dict[str, bool]:
    """Analyze webhook for security indicators"""
    security_flags = {
        "suspicious_ip": False,
        "malformed_payload": False,
        "invalid_signature": False,
        "rate_limit_exceeded": False,
        "repeated_failures": webhook_event.retry_count > WEBHOOK_RELIABILITY_THRESHOLDS["security_alert_retry_count"],
    }

    try:
        # Check for invalid signature
        if webhook_event.signature and "invalid" in webhook_event.error_message.lower():  # type: ignore[attr-defined]
            security_flags["invalid_signature"] = True

        # Check for malformed payload
        if any(term in webhook_event.error_message.lower() for term in ["malformed", "invalid json", "parse error"]):
            security_flags["malformed_payload"] = True

        # Check for rate limiting
        if any(term in webhook_event.error_message.lower() for term in ["rate limit", "too many requests", "429"]):
            security_flags["rate_limit_exceeded"] = True

        # Simple heuristic for suspicious IPs (private ranges in production)
        if webhook_event.ip_address and webhook_event.ip_address.startswith(("10.", "172.", "192.168.")):
            # This would need more sophisticated logic in production
            security_flags["suspicious_ip"] = False  # Disabled for now

    except Exception as e:
        logger.warning(f"⚠️ [Integrations] Failed to analyze security indicators: {e}")

    return security_flags


def _assess_service_impact(webhook_event: WebhookEvent, error_type: str) -> str:
    """Assess the impact of webhook failure on service reliability"""
    service_priority = ROMANIAN_SERVICE_PRIORITIES.get(webhook_event.source, "low")

    # Critical services have higher impact
    if service_priority == "critical":
        return "high"
    elif service_priority == "high":
        return "medium"

    # Certain error types have inherently higher impact
    if error_type in ["authentication_error", "service_unavailable"]:
        return "medium"
    elif error_type in ["timeout", "processing_error"]:
        return "low"

    return "low"
