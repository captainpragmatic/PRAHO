"""Audit-transaction regressions for e-Factura submission claims (#351)."""

from unittest.mock import Mock, patch

from django.test import TestCase, override_settings

from apps.audit.models import ComplianceLog
from apps.audit.services import AuditService
from apps.billing.efactura.client import EFacturaClient
from apps.billing.efactura.models import EFacturaDocument, EFacturaStatus
from tests.billing.efactura.test_submission_claims import _SubmissionClaimFixture


@override_settings(EFACTURA_ENABLED=True, EFACTURA_ENVIRONMENT="test")
class SubmissionClaimAuditTests(_SubmissionClaimFixture, TestCase):
    def _expired_document(self, number: str):
        invoice = self.create_invoice(number)
        document = EFacturaDocument.objects.create(invoice=invoice, xml_content="<Invoice/>")
        self.mark_uploading(document, expired=True)
        return invoice, document

    def test_expired_claim_records_reconciliation_status_without_rolling_back(self):
        invoice, document = self._expired_document("INV-CLAIM-AUDIT")

        result = self.service(Mock(spec=EFacturaClient)).submit_invoice(invoice)

        self.assertFalse(result.success)
        persisted_status = EFacturaDocument.objects.values_list("status", flat=True).get(pk=document.pk)
        self.assertEqual(persisted_status, EFacturaStatus.OUTCOME_UNKNOWN.value)
        audit_log = ComplianceLog.objects.get(
            compliance_type="efactura_submission",
            reference_id=invoice.number,
        )
        self.assertEqual(audit_log.status, "needs_reconciliation")

    def test_audit_database_failure_cannot_rollback_claim_quarantine(self):
        invoice, document = self._expired_document("INV-CLAIM-AUDIT-FAILURE")

        def fail_with_database_constraint(_request):
            ComplianceLog.objects.create(
                compliance_type=None,
                reference_id=invoice.number,
                description="invalid audit row",
                status="failed",
            )

        with patch.object(
            AuditService,
            "log_compliance_event",
            side_effect=fail_with_database_constraint,
        ):
            result = self.service(Mock(spec=EFacturaClient)).submit_invoice(invoice)

        self.assertFalse(result.success)
        persisted_status = EFacturaDocument.objects.values_list("status", flat=True).get(pk=document.pk)
        self.assertEqual(persisted_status, EFacturaStatus.OUTCOME_UNKNOWN.value)
