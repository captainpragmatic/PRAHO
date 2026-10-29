"""
The one place an audit action is classified (ADR-0016).

``classify(action)`` answers category, severity, sensitivity and whether the event needs
review, from the action alone. Two stages:

1. Patterns over the action name (a prefix says what family it belongs to).
2. ``ACTION_OVERRIDES``: facts a pattern cannot express, kept per action. Every entry here
   used to be passed in event metadata by the code that writes the action, where it silently
   overrode the classification; they live in one reviewed table now.

A fact that depends on the event, not the action (a coupon update that cancels, a sensitive
setting), is passed by its writer as an explicit ``severity`` / ``is_sensitive`` argument,
validated here. Metadata never classifies an event: it is evidence, not an instruction.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)

SEVERITIES = ("low", "medium", "high", "critical")

# Facts the patterns cannot express. Only the fields listed change; the rest comes from the patterns.
ACTION_OVERRIDES: dict[str, dict[str, Any]] = {
    # Account and authorization changes recorded by model receivers.
    "name_changed": {"severity": "medium", "is_sensitive": True},
    "staff_role_changed": {"is_sensitive": True},
    "marketing_consent_withdrawn": {"requires_review": True},
    "customer_membership_updated": {"severity": "medium"},
    "customer_membership_deleted": {"severity": "high", "requires_review": True},
    "customer_role_changed": {"severity": "high", "requires_review": True},
    # Operational alerts: a person has to look.
    "coupon_reversal_failed_on_cancellation": {"severity": "high", "requires_review": True},
    "coupon_reversal_failed_on_refund": {"severity": "high", "requires_review": True},
    "gift_card_reversal_failed_on_cancellation": {"severity": "high", "requires_review": True},
    "gift_card_reversal_failed_on_refund": {"severity": "high", "requires_review": True},
    "promotion_release_blocked_anomalous_payments": {"severity": "high", "requires_review": True},
    "domain_operation_review_required": {"requires_review": True},
    "account_name_certificate_alert": {"severity": "high", "requires_review": True},
    "email_provider_blocked": {"severity": "high", "requires_review": True},
    "virtualmin_chain_backup_alert": {"severity": "high", "requires_review": True},
    "virtualmin_chain_schedule_deferred": {"severity": "high", "requires_review": True},
    "virtualmin_pair_release_abandoned": {"severity": "high", "requires_review": True},
    "virtualmin_server_autofail_deferred": {"severity": "high", "requires_review": True},
    "virtualmin_server_health_alert": {"severity": "high", "requires_review": True},
    "virtualmin_migration_needs_review": {"requires_review": True},
    "node_drain_paused": {"severity": "high", "requires_review": True},
    # Severity or category set by the writer, and kept.
    "refund_reconciliation_gap": {"severity": "critical"},
    "efactura_submission_failed": {"severity": "high"},
    "security_bnr_outbound_blocked": {"severity": "high"},
    "data_anonymization_completed": {"category": "privacy"},
    # Customer view (ADR-0065): staff access, not the customer's own authorization changes.
    "customer_view_issued": {"category": "system_admin", "severity": "high"},
    "customer_view_issue_denied": {"category": "system_admin"},
    "customer_view_started": {"category": "system_admin", "severity": "high"},
    "customer_view_accessed": {"category": "system_admin"},
    "customer_view_denied": {"category": "system_admin"},
    "customer_view_ended": {"category": "system_admin"},
    "setting_override_cleared": {"is_sensitive": True},
}


@dataclass(frozen=True, slots=True)
class Classification:
    category: str
    severity: str
    is_sensitive: bool
    requires_review: bool


def _pattern_category(action: str) -> str:
    """Determine audit event category from action type"""
    # Use a mapping approach to reduce branching complexity
    category_mappings = {
        # api_token_ must precede the integration api_ prefix — token lifecycle is authentication
        "authentication": ["login_", "logout_", "session_", "account_", "password_", "2fa_", "api_token_"],
        "account_management": ["profile_updated", "email_changed", "phone_updated", "name_changed"],
        "privacy": ["privacy_", "gdpr_", "marketing_consent_", "cookie_consent_"],
        "authorization": [
            "role_assigned",
            "role_removed",
            "permission_granted",
            "permission_revoked",
            "staff_role_changed",
            "customer_",
            "privilege_escalation_attempt",
        ],
        "security_event": ["security_", "suspicious_", "brute_force_", "malicious_", "data_breach_"],
        "data_protection": ["data_export_", "data_deletion_"],
        "integration": ["api_", "webhook_"],
        "system_admin": [
            "system_",
            "backup_",
            "configuration_",
            "customer_view_",
            # Infrastructure operations (node_drain_ is provisioning, not infrastructure)
            "cloud_provider_",
            "drift_",
            "infrastructure_",
            "node_deployment_",
            "node_destroy_",
            "node_maintenance_",
            "node_reboot_",
            "node_region_",
            "node_size_",
            "node_start_",
            "node_stop_",
            "node_upgrade_",
        ],
        "compliance": ["vat_", "efactura_", "data_retention", "tax_rule", "legal_document_", "early_performance_"],
        "business_operation": [
            "proforma_",
            "invoice_",
            "payment_",
            "credit_",
            "billing_",
            "currency_conversion",
            "order_",
            "provisioning_",
            "service_",
            "domain_",
            "support_ticket_",
        ],
    }

    # Check each category's patterns
    for category, patterns in category_mappings.items():
        for pattern in patterns:
            if pattern.endswith("_"):  # Prefix pattern
                if action.startswith(pattern):
                    return category
            elif action == pattern:
                return category

    # Default to business operation
    return "business_operation"


def _pattern_severity(action: str) -> str:
    """Determine severity level from action type"""
    # Critical severity events
    critical_actions = [
        "data_breach_detected",
        "security_incident_detected",
        "account_compromised",
        "malicious_request",
        "brute_force_attempt",
    ]

    # High severity events
    high_actions = [
        "password_compromised",
        "2fa_disabled",
        "2fa_admin_reset",
        "role_assigned",
        "role_removed",
        "permission_granted",
        "permission_revoked",
        "staff_role_changed",
        "data_export_requested",
        "data_deletion_requested",
        "gdpr_consent_withdrawn",
        "customer_view_issued",
        "customer_view_started",
        "system_maintenance_started",
        "configuration_changed",
        "payment_failed",
        "payment_fraud_detected",
        "payment_chargeback_received",
        "invoice_voided",
        "invoice_refunded",
        "credit_limit_changed",
        "credit_hold_applied",
        "order_cancelled_admin",
        "provisioning_failed",
        "efactura_rejected",
        "privilege_escalation_attempt",
    ]

    # Medium severity events
    medium_actions = [
        "login_success",
        "login_failed",
        "logout_manual",
        "account_locked",
        "session_rotation",
        "password_changed",
        "2fa_enabled",
        "profile_updated",
        "email_changed",
        "phone_updated",
        "customer_membership_created",
        "api_key_generated",
        "api_token_created",
        "api_token_deleted",
        "invoice_paid",
        "payment_succeeded",
        "order_created",
        "order_completed",
        "proforma_created",
        "provisioning_completed",
        "efactura_submitted",
    ]

    if action in critical_actions or action.startswith(("security_", "suspicious_", "data_breach")):
        return "critical"
    elif action in high_actions or action.startswith(
        (
            "data_",
            "gdpr_",
            "privacy_",
            "marketing_consent",
            "cookie_consent",
            "role_",
            "permission_",
            "payment_fraud",
            "payment_chargeback",
        )
    ):
        return "high"
    elif action in medium_actions or action.startswith(
        ("login_", "password_", "2fa_", "profile_", "payment_", "order_")
    ):
        return "medium"
    else:
        return "low"


def _pattern_sensitive(action: str) -> bool:
    """Determine if action involves sensitive data"""
    # Specific sensitive actions
    sensitive_actions = [
        "account_locked",
        "account_unlocked",
        "session_rotation",
        "session_terminated",
        "suspicious_activity",
        "brute_force_attempt",
        "malicious_request",
        "privilege_escalation_attempt",
    ]

    # Sensitive patterns (excluding some common business operations)
    sensitive_patterns = [
        "login_",
        "logout_",
        "password_",
        "2fa_",
        "email_",
        "phone_",
        "profile_",
        "privacy_",
        "gdpr_",
        "marketing_consent",
        "cookie_consent",
        "data_",
        "security_",
        "role_",
        "permission_",
        "payment_",
        "billing_",
        "tax_",
        "credit_",
        "proforma_",
        "vat_",
        "efactura_",
        "customer_",
    ]

    # Non-sensitive invoice actions (basic business operations)
    non_sensitive_invoice_actions = ["invoice_created", "invoice_sent"]
    if action in non_sensitive_invoice_actions:
        return False

    return action in sensitive_actions or any(action.startswith(pattern) for pattern in sensitive_patterns)


def _pattern_requires_review(action: str) -> bool:
    """Determine if action requires manual review"""
    review_actions = [
        "account_locked",
        "login_failed_2fa",
        "password_compromised",
        "2fa_disabled",
        "2fa_admin_reset",
        "role_assigned",
        "role_removed",
        "permission_granted",
        "permission_revoked",
        "staff_role_changed",
        "privilege_escalation_attempt",
        "data_export_requested",
        "data_deletion_requested",
        "gdpr_consent_withdrawn",
        "security_incident_detected",
        "suspicious_activity",
        "brute_force_attempt",
        "customer_view_issued",
        "customer_view_started",
        "configuration_changed",
        "system_maintenance_started",
    ]

    return action in review_actions or action.startswith(("security_", "data_breach", "malicious_"))


def classify(action: str, *, severity: str | None = None, is_sensitive: bool | None = None) -> Classification:
    """Classify an action. ``severity`` / ``is_sensitive`` are the writer's event-specific facts."""
    overrides = ACTION_OVERRIDES.get(action, {})
    result = Classification(
        category=overrides.get("category", _pattern_category(action)),
        severity=overrides.get("severity", _pattern_severity(action)),
        is_sensitive=overrides.get("is_sensitive", _pattern_sensitive(action)),
        requires_review=overrides.get("requires_review", _pattern_requires_review(action)),
    )
    if severity is not None:
        if severity in SEVERITIES:
            result = Classification(result.category, severity, result.is_sensitive, result.requires_review)
        else:
            logger.error("🔥 [Audit] Ignoring unknown severity %r for action %s", severity, action)
    if is_sensitive is not None:
        result = Classification(result.category, result.severity, bool(is_sensitive), result.requires_review)
    return result
