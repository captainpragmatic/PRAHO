"""
Notification Services for PRAHO Platform
Handles email notifications, template management, and delivery tracking.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from apps.billing.models import Invoice

logger = logging.getLogger(__name__)


# ===============================================================================
# EMAIL SERVICE
# ===============================================================================


class EmailService:
    """
    Email notification service.
    Placeholder implementation for signal compatibility.
    """

    @staticmethod
    def send_invoice_created(invoice: Invoice) -> None:
        """Send invoice created notification"""
        logger.info(f"📧 [Email] Would send invoice created email for {invoice.number} to {invoice.bill_to_email}")
        # TODO: Implement actual email sending

    @staticmethod
    def send_invoice_paid(invoice: Invoice) -> None:
        """Send invoice paid notification"""
        logger.info(f"📧 [Email] Would send invoice paid email for {invoice.number} to {invoice.bill_to_email}")
        # TODO: Implement actual email sending

    @staticmethod
    def send_payment_reminder(invoice: Invoice) -> None:
        """Send payment reminder"""
        logger.info(f"📧 [Email] Would send payment reminder for {invoice.number} to {invoice.bill_to_email}")
        # TODO: Implement actual email sending

    @staticmethod
    def send_template_email(template_key: str, recipient: str, context: dict[str, Any], **kwargs: Any) -> None:
        """Send templated email"""
        logger.info(
            f"📧 [Email] Would send {template_key} email to {recipient} with context keys: {list(context.keys())}"
        )
        # TODO: Implement template-based email sending
