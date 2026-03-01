"""
Proforma Services for PRAHO Platform
Business logic for proforma invoice management and PDF generation.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from django.utils.translation import gettext as _t

from apps.common.types import Err, Ok, Result

if TYPE_CHECKING:
    from apps.users.models import User

    from .proforma_models import ProformaInvoice

logger = logging.getLogger(__name__)


# ===============================================================================
# PROFORMA PDF GENERATION & EMAIL SERVICES
# ===============================================================================


def generate_proforma_pdf(proforma: Any) -> bytes:  # ProformaInvoice type would create circular import
    """Generate PDF for a proforma invoice using the ReportLab generator."""
    logger.info(f"📄 [PDF] Generating PDF for proforma {proforma.number}")
    from apps.billing.pdf_generators import generate_proforma_pdf as _generate_pdf  # noqa: PLC0415

    return _generate_pdf(proforma)


def send_proforma_email(
    proforma: Any, recipient_email: str | None = None
) -> bool:  # ProformaInvoice type would create circular import
    """Send proforma invoice via email with PDF attachment."""
    from apps.notifications.services import EmailService  # noqa: PLC0415

    email = recipient_email or proforma.customer.primary_email
    logger.info(f"📧 [Email] Sending proforma {proforma.number} to {email}")
    try:
        pdf_bytes = generate_proforma_pdf(proforma)
        email_result = EmailService.send_email(
            to=email,
            subject=_t("Proforma Invoice %(number)s") % {"number": proforma.number},
            body_text=_t("Please find attached proforma invoice %(number)s.") % {"number": proforma.number},
            attachments=[(f"proforma_{proforma.number}.pdf", pdf_bytes, "application/pdf")],
        )
        if not email_result.success:
            logger.error(f"🔥 [Email] Proforma {proforma.number} send failed: {email_result.error}")
            return False
        logger.info(f"✅ [Email] Proforma {proforma.number} sent to {email}")
        return True
    except Exception as exc:
        logger.error(f"🔥 [Email] Failed to send proforma {proforma.number}: {exc}")
        return False


# ===============================================================================
# PROFORMA SERVICE CLASS
# ===============================================================================


class ProformaService:
    """Service class for proforma invoice business logic"""

    @staticmethod
    def update_proforma(proforma: ProformaInvoice, update_data: dict[str, Any], user: User) -> Result[bool, str]:
        """Update proforma invoice with new data"""
        try:
            # Update basic fields
            if "bill_to_name" in update_data:
                proforma.bill_to_name = update_data["bill_to_name"]
            if "bill_to_email" in update_data:
                proforma.bill_to_email = update_data["bill_to_email"]
            if "notes" in update_data:
                proforma.notes = update_data["notes"]

            # Save changes
            proforma.save()

            logger.info(f"📝 [Proforma] Updated proforma {proforma.number} by user {user.email}")
            return Ok(True)

        except Exception as e:
            logger.error(f"Failed to update proforma {proforma.number}: {e}")
            return Err(f"Failed to update proforma: {e}")

    @staticmethod
    def change_status(proforma: ProformaInvoice, new_status: str, user: User) -> Result[bool, str]:
        """Change proforma status"""
        try:
            old_status = proforma.status
            proforma.status = new_status
            proforma.save()

            logger.info(
                f"📝 [Proforma] Changed status of {proforma.number} from {old_status} to {new_status} by user {user.email}"
            )
            return Ok(True)

        except Exception as e:
            logger.error(f"Failed to change proforma status: {e}")
            return Err(f"Failed to change status: {e}")
