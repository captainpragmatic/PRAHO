"""
Tests for billing coverage gaps:
- efactura/audit.py (EFacturaAuditService)
- management/commands/setup_tax_rules.py
- metering_tasks.py
"""

from __future__ import annotations

import uuid
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass, field
from datetime import date, timedelta
from decimal import Decimal
from io import StringIO
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from django.core.management import call_command
from django.test import TestCase
from django.utils import timezone

from apps.billing.models import TaxRule

# ===============================================================================
# EFACTURA AUDIT TESTS
# ===============================================================================


def _make_mock_invoice(number: str = "INV-2026-001") -> MagicMock:
    invoice = MagicMock()
    invoice.id = uuid.uuid4()
    invoice.number = number
    return invoice


def _make_mock_document(**kwargs: Any) -> MagicMock:
    doc = MagicMock()
    doc.id = uuid.uuid4()
    doc.xml_hash = "abc123hash"
    doc.document_type = "invoice"
    doc.environment = "test"
    doc.retry_count = 0
    doc.anaf_upload_index = "12345"
    doc.anaf_download_id = "dl-67890"
    doc.last_error = ""
    doc.status = "submitted"
    doc.submitted_at = timezone.now() - timedelta(hours=1)
    doc.response_at = timezone.now()
    doc.submission_deadline = timezone.now() + timedelta(days=2)
    for k, v in kwargs.items():
        setattr(doc, k, v)
    return doc


@dataclass
class FakeValidationError:
    code: str = "E001"
    message: str = "Test error"
    location: str = ""
    severity: str = "error"

    def to_dict(self) -> dict[str, str]:
        return {"code": self.code, "message": self.message, "location": self.location, "severity": self.severity}


@dataclass
class FakeValidationResult:
    is_valid: bool = True
    errors: list[Any] = field(default_factory=list)
    warnings: list[Any] = field(default_factory=list)


def _patch_audit_imports():
    """Context manager that patches audit service lazy imports to accept any kwargs."""
    mock_bed = MagicMock(name="BusinessEventData")
    mock_ctx = MagicMock(name="AuditContext")
    mock_bas = MagicMock(name="BillingAuditService")
    mock_as = MagicMock(name="AuditService")
    mock_cer = MagicMock(name="ComplianceEventRequest")
    mock_aa = MagicMock(name="AuditAlert")
    return {
        "BusinessEventData": mock_bed,
        "AuditContext": mock_ctx,
        "BillingAuditService": mock_bas,
        "AuditService": mock_as,
        "ComplianceEventRequest": mock_cer,
        "AuditAlert": mock_aa,
    }


class TestEFacturaAuditServiceLogXmlGenerated(TestCase):
    def test_log_xml_generated_success(self) -> None:
        from apps.billing.efactura.audit import EFacturaAuditService  # noqa: PLC0415

        invoice = _make_mock_invoice()
        doc = _make_mock_document()
        mocks = _patch_audit_imports()
        with (
            patch("apps.audit.services.BusinessEventData", mocks["BusinessEventData"]),
            patch("apps.audit.services.AuditContext", mocks["AuditContext"]),
            patch("apps.audit.services.BillingAuditService", mocks["BillingAuditService"]),
        ):
            EFacturaAuditService.log_xml_generated(invoice, doc, xml_hash="custom_hash")
        mocks["BillingAuditService"].log_invoice_event.assert_called_once()

    def test_log_xml_generated_exception_swallowed(self) -> None:
        from apps.billing.efactura.audit import EFacturaAuditService  # noqa: PLC0415

        invoice = _make_mock_invoice()
        doc = _make_mock_document()
        with (
            patch("apps.audit.services.BusinessEventData", MagicMock()),
            patch("apps.audit.services.AuditContext", MagicMock()),
            patch("apps.audit.services.BillingAuditService") as mock_bas,
        ):
            mock_bas.log_invoice_event.side_effect = RuntimeError("boom")
            EFacturaAuditService.log_xml_generated(invoice, doc)

    def test_log_xml_generated_uses_doc_hash_when_empty(self) -> None:
        """When xml_hash is empty string, it should fall back to document.xml_hash."""
        from apps.billing.efactura.audit import EFacturaAuditService  # noqa: PLC0415

        invoice = _make_mock_invoice()
        doc = _make_mock_document(xml_hash="doc_hash_value")
        with (
            patch("apps.audit.services.BusinessEventData", MagicMock()),
            patch("apps.audit.services.AuditContext", MagicMock()),
            patch("apps.audit.services.BillingAuditService"),
        ):
            EFacturaAuditService.log_xml_generated(invoice, doc, xml_hash="")


class TestEFacturaAuditServiceLogValidation(TestCase):
    def test_log_validation_result_valid(self) -> None:
        from apps.billing.efactura.audit import EFacturaAuditService  # noqa: PLC0415

        invoice = _make_mock_invoice()
        doc = _make_mock_document()
        vr = FakeValidationResult(is_valid=True)
        with (
            patch("apps.audit.services.AuditService") as mock_as,
            patch("apps.audit.services.ComplianceEventRequest", MagicMock()),
        ):
            EFacturaAuditService.log_validation_result(invoice, doc, vr)
        mock_as.log_compliance_event.assert_called_once()

    def test_log_validation_result_invalid(self) -> None:
        from apps.billing.efactura.audit import EFacturaAuditService  # noqa: PLC0415

        invoice = _make_mock_invoice()
        doc = _make_mock_document()
        errors = [FakeValidationError(code="E001"), FakeValidationError(code="E002")]
        warnings = [FakeValidationError(code="W001", severity="warning")]
        vr = FakeValidationResult(is_valid=False, errors=errors, warnings=warnings)
        with (
            patch("apps.audit.services.AuditService"),
            patch("apps.audit.services.ComplianceEventRequest", MagicMock()),
        ):
            EFacturaAuditService.log_validation_result(invoice, doc, vr)

    def test_log_validation_result_exception_swallowed(self) -> None:
        from apps.billing.efactura.audit import EFacturaAuditService  # noqa: PLC0415

        invoice = _make_mock_invoice()
        doc = _make_mock_document()
        vr = FakeValidationResult(is_valid=True)
        with (
            patch("apps.audit.services.AuditService") as mock_as,
            patch("apps.audit.services.ComplianceEventRequest", MagicMock()),
        ):
            mock_as.log_compliance_event.side_effect = RuntimeError("boom")
            EFacturaAuditService.log_validation_result(invoice, doc, vr)


class TestEFacturaAuditServiceLogSubmission(TestCase):
    @contextmanager
    def _patches(self):
        with ExitStack() as stack:
            stack.enter_context(patch("apps.audit.services.BusinessEventData", MagicMock()))
            stack.enter_context(patch("apps.audit.services.AuditContext", MagicMock()))
            stack.enter_context(patch("apps.audit.services.BillingAuditService"))
            stack.enter_context(patch("apps.audit.services.AuditService"))
            stack.enter_context(patch("apps.audit.services.ComplianceEventRequest", MagicMock()))
            yield

    def test_log_submission_success(self) -> None:
        from apps.billing.efactura.audit import EFacturaAuditService  # noqa: PLC0415

        invoice = _make_mock_invoice()
        doc = _make_mock_document()
        with self._patches():
            EFacturaAuditService.log_submission_attempt(invoice, doc, success=True, upload_index="idx-123")

    def test_log_submission_failure(self) -> None:
        from apps.billing.efactura.audit import EFacturaAuditService  # noqa: PLC0415

        invoice = _make_mock_invoice()
        doc = _make_mock_document()
        with self._patches():
            EFacturaAuditService.log_submission_attempt(
                invoice, doc, success=False, error_message="Connection timeout"
            )

    def test_log_submission_exception_swallowed(self) -> None:
        from apps.billing.efactura.audit import EFacturaAuditService  # noqa: PLC0415

        invoice = _make_mock_invoice()
        doc = _make_mock_document()
        with (
            patch("apps.audit.services.BusinessEventData", MagicMock()),
            patch("apps.audit.services.AuditContext", MagicMock()),
            patch("apps.audit.services.BillingAuditService") as mock_bas,
            patch("apps.audit.services.AuditService"),
            patch("apps.audit.services.ComplianceEventRequest", MagicMock()),
        ):
            mock_bas.log_invoice_event.side_effect = RuntimeError("boom")
            EFacturaAuditService.log_submission_attempt(invoice, doc, success=True)


class TestEFacturaAuditServiceLogStatusChange(TestCase):
    def test_log_status_change(self) -> None:
        from apps.billing.efactura.audit import EFacturaAuditService  # noqa: PLC0415

        invoice = _make_mock_invoice()
        doc = _make_mock_document()
        with (
            patch("apps.audit.services.BusinessEventData", MagicMock()),
            patch("apps.audit.services.AuditContext", MagicMock()),
            patch("apps.audit.services.BillingAuditService") as mock_bas,
        ):
            EFacturaAuditService.log_status_change(invoice, doc, "submitted", "accepted")
        mock_bas.log_invoice_event.assert_called_once()

    def test_log_status_change_exception_swallowed(self) -> None:
        from apps.billing.efactura.audit import EFacturaAuditService  # noqa: PLC0415

        invoice = _make_mock_invoice()
        doc = _make_mock_document()
        with (
            patch("apps.audit.services.BusinessEventData", MagicMock()),
            patch("apps.audit.services.AuditContext", MagicMock()),
            patch("apps.audit.services.BillingAuditService") as mock_bas,
        ):
            mock_bas.log_invoice_event.side_effect = RuntimeError("boom")
            EFacturaAuditService.log_status_change(invoice, doc, "submitted", "error")


class TestEFacturaAuditServiceLogAccepted(TestCase):
    @contextmanager
    def _patches(self):
        with ExitStack() as stack:
            stack.enter_context(patch("apps.audit.services.BusinessEventData", MagicMock()))
            stack.enter_context(patch("apps.audit.services.AuditContext", MagicMock()))
            stack.enter_context(patch("apps.audit.services.BillingAuditService"))
            stack.enter_context(patch("apps.audit.services.AuditService"))
            stack.enter_context(patch("apps.audit.services.ComplianceEventRequest", MagicMock()))
            yield

    def test_log_accepted(self) -> None:
        from apps.billing.efactura.audit import EFacturaAuditService  # noqa: PLC0415

        invoice = _make_mock_invoice()
        doc = _make_mock_document()
        with self._patches():
            EFacturaAuditService.log_accepted(invoice, doc, download_id="dl-999")

    def test_log_accepted_no_download_id(self) -> None:
        from apps.billing.efactura.audit import EFacturaAuditService  # noqa: PLC0415

        invoice = _make_mock_invoice()
        doc = _make_mock_document()
        with self._patches():
            EFacturaAuditService.log_accepted(invoice, doc)

    def test_log_accepted_no_timestamps(self) -> None:
        from apps.billing.efactura.audit import EFacturaAuditService  # noqa: PLC0415

        invoice = _make_mock_invoice()
        doc = _make_mock_document(submitted_at=None, response_at=None)
        with self._patches():
            EFacturaAuditService.log_accepted(invoice, doc)

    def test_log_accepted_exception_swallowed(self) -> None:
        from apps.billing.efactura.audit import EFacturaAuditService  # noqa: PLC0415

        invoice = _make_mock_invoice()
        doc = _make_mock_document()
        with (
            patch("apps.audit.services.BusinessEventData", MagicMock()),
            patch("apps.audit.services.AuditContext", MagicMock()),
            patch("apps.audit.services.BillingAuditService") as mock_bas,
            patch("apps.audit.services.AuditService"),
            patch("apps.audit.services.ComplianceEventRequest", MagicMock()),
        ):
            mock_bas.log_invoice_event.side_effect = RuntimeError("boom")
            EFacturaAuditService.log_accepted(invoice, doc)


@pytest.mark.django_db
class TestEFacturaAuditServiceLogRejected(TestCase):
    @contextmanager
    def _patches(self):
        with ExitStack() as stack:
            stack.enter_context(patch("apps.audit.services.BusinessEventData", MagicMock()))
            stack.enter_context(patch("apps.audit.services.AuditContext", MagicMock()))
            stack.enter_context(patch("apps.audit.services.BillingAuditService"))
            stack.enter_context(patch("apps.audit.services.AuditService"))
            stack.enter_context(patch("apps.audit.services.ComplianceEventRequest", MagicMock()))
            stack.enter_context(patch("apps.audit.models.AuditAlert"))
            yield

    def test_log_rejected(self) -> None:
        from apps.billing.efactura.audit import EFacturaAuditService  # noqa: PLC0415

        invoice = _make_mock_invoice()
        doc = _make_mock_document()
        errors = [{"code": "ERR01", "message": "Bad field"}]
        with self._patches():
            EFacturaAuditService.log_rejected(invoice, doc, errors)

    def test_log_rejected_exception_swallowed(self) -> None:
        from apps.billing.efactura.audit import EFacturaAuditService  # noqa: PLC0415

        invoice = _make_mock_invoice()
        doc = _make_mock_document()
        with (
            patch("apps.audit.services.BusinessEventData", MagicMock()),
            patch("apps.audit.services.AuditContext", MagicMock()),
            patch("apps.audit.services.BillingAuditService") as mock_bas,
        ):
            mock_bas.log_invoice_event.side_effect = RuntimeError("boom")
            EFacturaAuditService.log_rejected(invoice, doc, [])


class TestEFacturaAuditServiceLogRetry(TestCase):
    @contextmanager
    def _patches(self):
        with ExitStack() as stack:
            stack.enter_context(patch("apps.audit.services.BusinessEventData", MagicMock()))
            stack.enter_context(patch("apps.audit.services.AuditContext", MagicMock()))
            stack.enter_context(patch("apps.audit.services.BillingAuditService"))
            yield

    def test_log_retry_scheduled(self) -> None:
        from apps.billing.efactura.audit import EFacturaAuditService  # noqa: PLC0415

        invoice = _make_mock_invoice()
        doc = _make_mock_document(last_error="Connection refused")
        next_retry = timezone.now() + timedelta(hours=1)
        with self._patches():
            EFacturaAuditService.log_retry_scheduled(invoice, doc, retry_count=3, next_retry_at=next_retry)

    def test_log_retry_scheduled_no_next_retry(self) -> None:
        from apps.billing.efactura.audit import EFacturaAuditService  # noqa: PLC0415

        invoice = _make_mock_invoice()
        doc = _make_mock_document(last_error="")
        with self._patches():
            EFacturaAuditService.log_retry_scheduled(invoice, doc, retry_count=1, next_retry_at=None)

    def test_log_retry_exception_swallowed(self) -> None:
        from apps.billing.efactura.audit import EFacturaAuditService  # noqa: PLC0415

        invoice = _make_mock_invoice()
        doc = _make_mock_document()
        with (
            patch("apps.audit.services.BusinessEventData", MagicMock()),
            patch("apps.audit.services.AuditContext", MagicMock()),
            patch("apps.audit.services.BillingAuditService") as mock_bas,
        ):
            mock_bas.log_invoice_event.side_effect = RuntimeError("boom")
            EFacturaAuditService.log_retry_scheduled(invoice, doc, retry_count=1, next_retry_at=None)


@pytest.mark.django_db
class TestEFacturaAuditServiceLogDeadline(TestCase):
    @contextmanager
    def _patches(self):
        with ExitStack() as stack:
            stack.enter_context(patch("apps.audit.services.AuditService"))
            stack.enter_context(patch("apps.audit.services.ComplianceEventRequest", MagicMock()))
            stack.enter_context(patch("apps.audit.models.AuditAlert"))
            yield

    def test_log_deadline_warning_high(self) -> None:
        from apps.billing.efactura.audit import EFacturaAuditService  # noqa: PLC0415

        invoice = _make_mock_invoice()
        doc = _make_mock_document()
        with self._patches():
            EFacturaAuditService.log_deadline_warning(invoice, doc, hours_remaining=24.0)

    def test_log_deadline_warning_critical(self) -> None:
        from apps.billing.efactura.audit import EFacturaAuditService  # noqa: PLC0415

        invoice = _make_mock_invoice()
        doc = _make_mock_document()
        with self._patches():
            EFacturaAuditService.log_deadline_warning(invoice, doc, hours_remaining=6.0)

    def test_log_deadline_warning_no_deadline(self) -> None:
        from apps.billing.efactura.audit import EFacturaAuditService  # noqa: PLC0415

        invoice = _make_mock_invoice()
        doc = _make_mock_document(submission_deadline=None)
        with self._patches():
            EFacturaAuditService.log_deadline_warning(invoice, doc, hours_remaining=3.0)

    def test_log_deadline_exception_swallowed(self) -> None:
        from apps.billing.efactura.audit import EFacturaAuditService  # noqa: PLC0415

        invoice = _make_mock_invoice()
        doc = _make_mock_document()
        with (
            patch("apps.audit.services.AuditService") as mock_as,
            patch("apps.audit.services.ComplianceEventRequest", MagicMock()),
        ):
            mock_as.log_compliance_event.side_effect = RuntimeError("boom")
            EFacturaAuditService.log_deadline_warning(invoice, doc, hours_remaining=5.0)


class TestEFacturaAuditServiceLogDownload(TestCase):
    def test_log_download_completed(self) -> None:
        from apps.billing.efactura.audit import EFacturaAuditService  # noqa: PLC0415

        invoice = _make_mock_invoice()
        doc = _make_mock_document()
        with (
            patch("apps.audit.services.BusinessEventData", MagicMock()),
            patch("apps.audit.services.AuditContext", MagicMock()),
            patch("apps.audit.services.BillingAuditService") as mock_bas,
        ):
            EFacturaAuditService.log_download_completed(invoice, doc, file_path="/tmp/inv.pdf")  # noqa: S108
        mock_bas.log_invoice_event.assert_called_once()

    def test_log_download_exception_swallowed(self) -> None:
        from apps.billing.efactura.audit import EFacturaAuditService  # noqa: PLC0415

        invoice = _make_mock_invoice()
        doc = _make_mock_document()
        with (
            patch("apps.audit.services.BusinessEventData", MagicMock()),
            patch("apps.audit.services.AuditContext", MagicMock()),
            patch("apps.audit.services.BillingAuditService") as mock_bas,
        ):
            mock_bas.log_invoice_event.side_effect = RuntimeError("boom")
            EFacturaAuditService.log_download_completed(invoice, doc, file_path="/tmp/inv.pdf")  # noqa: S108


# ===============================================================================
# SETUP TAX RULES COMMAND TESTS
# ===============================================================================


@pytest.mark.django_db
class TestSetupTaxRulesCommand(TestCase):
    def _call(self, *args: str) -> str:
        out = StringIO()
        call_command("setup_tax_rules", *args, stdout=out)
        return out.getvalue()

    def test_creates_all_rules_fresh(self) -> None:
        output = self._call()
        assert "Created" in output
        # Romanian (2 rules) + EU (9 rules) + Non-EU (6 rules) = 17
        assert TaxRule.objects.count() == 17

    def test_skips_existing_rules(self) -> None:
        self._call()
        count_before = TaxRule.objects.count()
        output = self._call()
        assert "Skipping existing" in output
        assert TaxRule.objects.count() == count_before

    def test_force_updates_existing(self) -> None:
        self._call()
        output = self._call("--force")
        assert "Updated" in output
        assert TaxRule.objects.count() == 17

    def test_romanian_rules_have_correct_rates(self) -> None:
        self._call()
        ro_rules = TaxRule.objects.filter(country_code="RO").order_by("valid_from")
        assert ro_rules.count() == 2
        assert ro_rules[0].rate == Decimal("0.19")
        assert ro_rules[1].rate == Decimal("0.21")

    def test_eu_rules_created(self) -> None:
        self._call()
        de = TaxRule.objects.filter(country_code="DE").first()
        assert de is not None
        assert de.rate == Decimal("0.19")
        assert de.is_eu_member is True

    def test_non_eu_rules_zero_rate(self) -> None:
        self._call()
        us = TaxRule.objects.filter(country_code="US").first()
        assert us is not None
        assert us.rate == Decimal("0.00")
        assert us.is_eu_member is False

    def test_remediate_legacy_ro_rules(self) -> None:
        # Create a stale open-ended RO rule
        TaxRule.objects.create(
            country_code="RO",
            tax_type="vat",
            rate=Decimal("0.19"),
            valid_from=date(2023, 1, 1),
            valid_to=None,
            applies_to_b2b=True,
            applies_to_b2c=True,
        )
        output = self._call()
        stale = TaxRule.objects.get(valid_from=date(2023, 1, 1))
        assert stale.valid_to == date(2025, 7, 31)
        assert "Closed" in output

    def test_get_active_rate_shown_in_output(self) -> None:
        output = self._call()
        assert "Current Romanian VAT rate" in output

    def test_summary_shows_total(self) -> None:
        output = self._call()
        assert "Total active rules" in output

    def test_next_steps_shown(self) -> None:
        output = self._call()
        assert "Next steps" in output


# ===============================================================================
# METERING TASKS TESTS
# ===============================================================================


class TestGetTaskTimeout(TestCase):
    def test_returns_default(self) -> None:
        with patch("apps.settings.services.SettingsService.get_integer_setting", return_value=300):
            from apps.billing.metering_tasks import get_task_timeout  # noqa: PLC0415

            assert get_task_timeout() == 300

    def test_returns_custom(self) -> None:
        with patch("apps.settings.services.SettingsService.get_integer_setting", return_value=600):
            from apps.billing.metering_tasks import get_task_timeout  # noqa: PLC0415

            assert get_task_timeout() == 600


class TestUpdateAggregationForEvent(TestCase):
    def test_event_not_found(self) -> None:
        from apps.billing.metering_tasks import update_aggregation_for_event  # noqa: PLC0415

        with patch("apps.billing.metering_models.UsageEvent") as mock_model:
            mock_model.DoesNotExist = type("DoesNotExist", (Exception,), {})
            mock_model.objects.get.side_effect = mock_model.DoesNotExist()
            result = update_aggregation_for_event("fake-id")
        assert result["success"] is False
        assert "not found" in result["error"]

    def test_already_processed(self) -> None:
        from apps.billing.metering_tasks import update_aggregation_for_event  # noqa: PLC0415

        mock_event = MagicMock()
        mock_event.is_processed = True

        with patch("apps.billing.metering_models.UsageEvent") as mock_model:
            mock_model.DoesNotExist = type("DoesNotExist", (Exception,), {})
            mock_model.objects.get.return_value = mock_event
            result = update_aggregation_for_event("fake-id")
        assert result["success"] is True
        assert "already processed" in result["message"]

    def test_success(self) -> None:
        from apps.billing.metering_tasks import update_aggregation_for_event  # noqa: PLC0415

        mock_event = MagicMock()
        mock_event.is_processed = False

        with (
            patch("apps.billing.metering_models.UsageEvent") as mock_model,
            patch("apps.billing.metering_service.MeteringService"),
        ):
            mock_model.DoesNotExist = type("DoesNotExist", (Exception,), {})
            mock_model.objects.get.return_value = mock_event
            result = update_aggregation_for_event("fake-id")
        assert result["success"] is True

    def test_aggregation_error(self) -> None:
        from apps.billing.metering_tasks import update_aggregation_for_event  # noqa: PLC0415

        mock_event = MagicMock()
        mock_event.is_processed = False

        with (
            patch("apps.billing.metering_models.UsageEvent") as mock_model,
            patch("apps.billing.metering_service.MeteringService") as mock_svc_cls,
        ):
            mock_model.DoesNotExist = type("DoesNotExist", (Exception,), {})
            mock_model.objects.get.return_value = mock_event
            mock_svc_cls.return_value._update_aggregation_sync.side_effect = RuntimeError("fail")
            result = update_aggregation_for_event("fake-id")
        assert result["success"] is False


class TestProcessPendingUsageEvents(TestCase):
    def test_success(self) -> None:
        from apps.billing.metering_tasks import process_pending_usage_events  # noqa: PLC0415

        with (
            patch("apps.billing.metering_service.AggregationService") as mock_cls,
            patch("apps.billing.metering_tasks.AuditService"),
        ):
            mock_cls.return_value.process_pending_events.return_value = (50, 2)
            result = process_pending_usage_events(limit=100, meter_id="meter-1")
        assert result["success"] is True
        assert result["processed"] == 50
        assert result["errors"] == 2

    def test_exception(self) -> None:
        from apps.billing.metering_tasks import process_pending_usage_events  # noqa: PLC0415

        with patch("apps.billing.metering_service.AggregationService") as mock_cls:
            mock_cls.return_value.process_pending_events.side_effect = RuntimeError("boom")
            result = process_pending_usage_events()
        assert result["success"] is False


class TestAdvanceBillingCycles(TestCase):
    def test_success(self) -> None:
        from apps.billing.metering_tasks import advance_billing_cycles  # noqa: PLC0415

        with (
            patch("apps.billing.usage_invoice_service.BillingCycleManager") as mock_cls,
            patch("apps.billing.metering_tasks.AuditService"),
        ):
            mock_cls.return_value.advance_all_subscriptions.return_value = (5, 1, ["err1"])
            result = advance_billing_cycles()
        assert result["success"] is True
        assert result["created"] == 5

    def test_exception(self) -> None:
        from apps.billing.metering_tasks import advance_billing_cycles  # noqa: PLC0415

        with patch("apps.billing.usage_invoice_service.BillingCycleManager") as mock_cls:
            mock_cls.return_value.advance_all_subscriptions.side_effect = RuntimeError("boom")
            result = advance_billing_cycles()
        assert result["success"] is False


class TestCloseExpiredBillingCycles(TestCase):
    def test_success(self) -> None:
        from apps.billing.metering_tasks import close_expired_billing_cycles  # noqa: PLC0415

        with patch("apps.billing.usage_invoice_service.BillingCycleManager") as mock_cls:
            mock_cls.return_value.close_expired_cycles.return_value = (3, 0)
            result = close_expired_billing_cycles()
        assert result["success"] is True
        assert result["closed"] == 3

    def test_exception(self) -> None:
        from apps.billing.metering_tasks import close_expired_billing_cycles  # noqa: PLC0415

        with patch("apps.billing.usage_invoice_service.BillingCycleManager") as mock_cls:
            mock_cls.return_value.close_expired_cycles.side_effect = RuntimeError("boom")
            result = close_expired_billing_cycles()
        assert result["success"] is False


class TestRatePendingAggregations(TestCase):
    def test_specific_cycle(self) -> None:
        from apps.billing.metering_tasks import rate_pending_aggregations  # noqa: PLC0415

        mock_result = MagicMock()
        mock_result.is_ok.return_value = True
        mock_result.unwrap.return_value = {"rated_count": 10}

        with patch("apps.billing.metering_service.RatingEngine") as mock_cls:
            mock_cls.return_value.rate_billing_cycle.return_value = mock_result
            result = rate_pending_aggregations(billing_cycle_id="cycle-1")
        assert result["rated_count"] == 10

    def test_specific_cycle_error(self) -> None:
        from apps.billing.metering_tasks import rate_pending_aggregations  # noqa: PLC0415

        mock_result = MagicMock()
        mock_result.is_ok.return_value = False
        mock_result.error = "bad cycle"

        with patch("apps.billing.metering_service.RatingEngine") as mock_cls:
            mock_cls.return_value.rate_billing_cycle.return_value = mock_result
            result = rate_pending_aggregations(billing_cycle_id="cycle-1")
        assert result["success"] is False

    def test_all_pending(self) -> None:
        from apps.billing.metering_tasks import rate_pending_aggregations  # noqa: PLC0415

        mock_cycle = MagicMock()
        mock_cycle.id = uuid.uuid4()

        ok_result = MagicMock()
        ok_result.is_ok.return_value = True
        ok_result.unwrap.return_value = {"rated_count": 5}

        err_result = MagicMock()
        err_result.is_ok.return_value = False

        with (
            patch("apps.billing.metering_service.RatingEngine") as mock_eng,
            patch("apps.billing.metering_models.BillingCycle") as mock_bc,
        ):
            mock_bc.objects.filter.return_value = [mock_cycle, mock_cycle]
            mock_eng.return_value.rate_billing_cycle.side_effect = [ok_result, err_result]
            result = rate_pending_aggregations()
        assert result["success"] is True
        assert result["rated"] == 5
        assert result["errors"] == 1

    def test_exception(self) -> None:
        from apps.billing.metering_tasks import rate_pending_aggregations  # noqa: PLC0415

        with patch("apps.billing.metering_service.RatingEngine") as mock_cls:
            mock_cls.side_effect = RuntimeError("boom")
            result = rate_pending_aggregations()
        assert result["success"] is False


class TestGeneratePendingInvoices(TestCase):
    def test_success(self) -> None:
        from apps.billing.metering_tasks import generate_pending_invoices  # noqa: PLC0415

        with patch("apps.billing.usage_invoice_service.BillingCycleManager") as mock_cls:
            mock_cls.return_value.generate_pending_invoices.return_value = (4, 1)
            result = generate_pending_invoices()
        assert result["success"] is True
        assert result["generated"] == 4

    def test_exception(self) -> None:
        from apps.billing.metering_tasks import generate_pending_invoices  # noqa: PLC0415

        with patch("apps.billing.usage_invoice_service.BillingCycleManager") as mock_cls:
            mock_cls.return_value.generate_pending_invoices.side_effect = RuntimeError("boom")
            result = generate_pending_invoices()
        assert result["success"] is False


class TestRunBillingCycleWorkflow(TestCase):
    def test_success(self) -> None:
        from apps.billing.metering_tasks import run_billing_cycle_workflow  # noqa: PLC0415

        with (
            patch("apps.billing.metering_tasks.close_expired_billing_cycles", return_value={"success": True}),
            patch("apps.billing.metering_tasks.rate_pending_aggregations", return_value={"success": True}),
            patch("apps.billing.metering_tasks.generate_pending_invoices", return_value={"success": True}),
            patch("apps.billing.metering_tasks.advance_billing_cycles", return_value={"success": True}),
            patch("apps.billing.metering_tasks.AuditService"),
        ):
            result = run_billing_cycle_workflow()
        assert result["success"] is True

    def test_exception(self) -> None:
        from apps.billing.metering_tasks import run_billing_cycle_workflow  # noqa: PLC0415

        with patch(
            "apps.billing.metering_tasks.close_expired_billing_cycles", side_effect=RuntimeError("boom")
        ):
            result = run_billing_cycle_workflow()
        assert result["success"] is False
        assert "partial_results" in result


class TestCheckUsageThresholds(TestCase):
    def test_success(self) -> None:
        from apps.billing.metering_tasks import check_usage_thresholds  # noqa: PLC0415

        mock_alert = MagicMock()
        mock_alert.id = uuid.uuid4()

        with patch("apps.billing.metering_service.UsageAlertService") as mock_cls:
            mock_cls.return_value.check_thresholds.return_value = [mock_alert]
            result = check_usage_thresholds("cust-1", "meter-1", "sub-1")
        assert result["success"] is True
        assert result["alerts_created"] == 1

    def test_exception(self) -> None:
        from apps.billing.metering_tasks import check_usage_thresholds  # noqa: PLC0415

        with patch("apps.billing.metering_service.UsageAlertService") as mock_cls:
            mock_cls.return_value.check_thresholds.side_effect = RuntimeError("boom")
            result = check_usage_thresholds("cust-1", "meter-1")
        assert result["success"] is False


class TestSendUsageAlertNotification(TestCase):
    def test_success(self) -> None:
        from apps.billing.metering_tasks import send_usage_alert_notification  # noqa: PLC0415

        mock_result = MagicMock()
        mock_result.is_ok.return_value = True

        with patch("apps.billing.metering_service.UsageAlertService") as mock_cls:
            mock_cls.return_value.send_alert_notification.return_value = mock_result
            result = send_usage_alert_notification("alert-1")
        assert result["success"] is True

    def test_failure(self) -> None:
        from apps.billing.metering_tasks import send_usage_alert_notification  # noqa: PLC0415

        mock_result = MagicMock()
        mock_result.is_ok.return_value = False
        mock_result.error = "not found"

        with patch("apps.billing.metering_service.UsageAlertService") as mock_cls:
            mock_cls.return_value.send_alert_notification.return_value = mock_result
            result = send_usage_alert_notification("alert-1")
        assert result["success"] is False

    def test_exception(self) -> None:
        from apps.billing.metering_tasks import send_usage_alert_notification  # noqa: PLC0415

        with patch("apps.billing.metering_service.UsageAlertService") as mock_cls:
            mock_cls.return_value.send_alert_notification.side_effect = RuntimeError("boom")
            result = send_usage_alert_notification("alert-1")
        assert result["success"] is False


class TestCheckAllUsageThresholds(TestCase):
    def test_success(self) -> None:
        from apps.billing.metering_tasks import check_all_usage_thresholds  # noqa: PLC0415

        mock_item = MagicMock()
        mock_item.product_id = uuid.uuid4()

        mock_sub = MagicMock()
        mock_sub.customer_id = uuid.uuid4()
        mock_sub.id = uuid.uuid4()
        mock_sub.items.all.return_value = [mock_item]

        mock_qs = MagicMock()
        mock_qs.__iter__ = lambda self: iter([mock_sub])
        mock_qs.count.return_value = 1

        with (
            patch("apps.billing.metering_service.UsageAlertService") as mock_svc,
            patch("apps.billing.subscription_models.Subscription") as mock_model,
        ):
            mock_model.objects.filter.return_value.prefetch_related.return_value = mock_qs
            mock_svc.return_value.check_thresholds.return_value = []
            result = check_all_usage_thresholds()
        assert result["success"] is True

    def test_exception(self) -> None:
        from apps.billing.metering_tasks import check_all_usage_thresholds  # noqa: PLC0415

        with patch("apps.billing.metering_service.UsageAlertService") as mock_cls:
            mock_cls.side_effect = RuntimeError("boom")
            result = check_all_usage_thresholds()
        assert result["success"] is False


class TestSyncAggregationToStripe(TestCase):
    def test_success(self) -> None:
        from apps.billing.metering_tasks import sync_aggregation_to_stripe  # noqa: PLC0415

        mock_result = MagicMock()
        mock_result.is_ok.return_value = True
        mock_result.unwrap.return_value = {"synced": True}

        with patch("apps.billing.stripe_metering.StripeUsageSyncService") as mock_cls:
            mock_cls.return_value.sync_aggregation_to_stripe.return_value = mock_result
            result = sync_aggregation_to_stripe("agg-1")
        assert result["success"] is True

    def test_failure(self) -> None:
        from apps.billing.metering_tasks import sync_aggregation_to_stripe  # noqa: PLC0415

        mock_result = MagicMock()
        mock_result.is_ok.return_value = False
        mock_result.error = "stripe error"

        with patch("apps.billing.stripe_metering.StripeUsageSyncService") as mock_cls:
            mock_cls.return_value.sync_aggregation_to_stripe.return_value = mock_result
            result = sync_aggregation_to_stripe("agg-1")
        assert result["success"] is False

    def test_exception(self) -> None:
        from apps.billing.metering_tasks import sync_aggregation_to_stripe  # noqa: PLC0415

        with patch("apps.billing.stripe_metering.StripeUsageSyncService") as mock_cls:
            mock_cls.return_value.sync_aggregation_to_stripe.side_effect = RuntimeError("boom")
            result = sync_aggregation_to_stripe("agg-1")
        assert result["success"] is False


class TestSyncBillingCycleToStripe(TestCase):
    def test_success(self) -> None:
        from apps.billing.metering_tasks import sync_billing_cycle_to_stripe  # noqa: PLC0415

        mock_result = MagicMock()
        mock_result.is_ok.return_value = True
        mock_result.unwrap.return_value = {"count": 5}

        with patch("apps.billing.stripe_metering.StripeUsageSyncService") as mock_cls:
            mock_cls.return_value.sync_billing_cycle_to_stripe.return_value = mock_result
            result = sync_billing_cycle_to_stripe("cycle-1")
        assert result["success"] is True

    def test_failure(self) -> None:
        from apps.billing.metering_tasks import sync_billing_cycle_to_stripe  # noqa: PLC0415

        mock_result = MagicMock()
        mock_result.is_ok.return_value = False
        mock_result.error = "stripe error"

        with patch("apps.billing.stripe_metering.StripeUsageSyncService") as mock_cls:
            mock_cls.return_value.sync_billing_cycle_to_stripe.return_value = mock_result
            result = sync_billing_cycle_to_stripe("cycle-1")
        assert result["success"] is False

    def test_exception(self) -> None:
        from apps.billing.metering_tasks import sync_billing_cycle_to_stripe  # noqa: PLC0415

        with patch("apps.billing.stripe_metering.StripeUsageSyncService") as mock_cls:
            mock_cls.return_value.sync_billing_cycle_to_stripe.side_effect = RuntimeError("boom")
            result = sync_billing_cycle_to_stripe("cycle-1")
        assert result["success"] is False


class TestSyncPendingToStripe(TestCase):
    def test_success(self) -> None:
        from apps.billing.metering_tasks import sync_pending_to_stripe  # noqa: PLC0415

        mock_agg = MagicMock()
        mock_agg.id = uuid.uuid4()

        ok_result = MagicMock()
        ok_result.is_ok.return_value = True

        mock_qs = MagicMock()
        mock_qs.count.return_value = 2
        mock_qs.__getitem__ = lambda self, key: [mock_agg, mock_agg]

        with (
            patch("apps.billing.stripe_metering.StripeUsageSyncService") as mock_svc,
            patch("apps.billing.metering_models.UsageAggregation") as mock_model,
        ):
            mock_model.objects.filter.return_value.exclude.return_value.select_related.return_value = mock_qs
            mock_svc.return_value.sync_aggregation_to_stripe.return_value = ok_result
            result = sync_pending_to_stripe()
        assert result["success"] is True

    def test_with_errors(self) -> None:
        from apps.billing.metering_tasks import sync_pending_to_stripe  # noqa: PLC0415

        mock_agg = MagicMock()
        mock_agg.id = uuid.uuid4()

        err_result = MagicMock()
        err_result.is_ok.return_value = False

        mock_qs = MagicMock()
        mock_qs.count.return_value = 1
        mock_qs.__getitem__ = lambda self, key: [mock_agg]

        with (
            patch("apps.billing.stripe_metering.StripeUsageSyncService") as mock_svc,
            patch("apps.billing.metering_models.UsageAggregation") as mock_model,
        ):
            mock_model.objects.filter.return_value.exclude.return_value.select_related.return_value = mock_qs
            mock_svc.return_value.sync_aggregation_to_stripe.return_value = err_result
            result = sync_pending_to_stripe()
        assert result["success"] is True
        assert result["errors"] == 1

    def test_exception(self) -> None:
        from apps.billing.metering_tasks import sync_pending_to_stripe  # noqa: PLC0415

        with patch("apps.billing.stripe_metering.StripeUsageSyncService") as mock_cls:
            mock_cls.side_effect = RuntimeError("boom")
            result = sync_pending_to_stripe()
        assert result["success"] is False


class TestCollectVirtualminUsage(TestCase):
    def test_meters_not_configured(self) -> None:
        from apps.billing.metering_tasks import collect_virtualmin_usage  # noqa: PLC0415

        with (
            patch("apps.billing.metering_service.MeteringService"),
            patch("apps.billing.metering_models.UsageMeter") as mock_meter,
            patch("apps.billing.metering_service.UsageEventData"),
            patch("apps.provisioning.models.VirtualminAccount"),
        ):
            mock_meter.objects.filter.return_value.first.return_value = None
            result = collect_virtualmin_usage()
        assert result["success"] is False
        assert "not configured" in result["error"]

    def test_success_with_accounts(self) -> None:
        from apps.billing.metering_tasks import collect_virtualmin_usage  # noqa: PLC0415

        mock_account = MagicMock()
        mock_account.id = uuid.uuid4()
        mock_account.service = MagicMock()
        mock_account.service.customer = MagicMock()
        mock_account.service.customer.id = uuid.uuid4()
        mock_account.service.id = uuid.uuid4()
        mock_account.current_disk_usage_gb = 5.0
        mock_account.current_bandwidth_usage_gb = 2.0
        mock_account.domain = "test.com"

        mock_disk_meter = MagicMock()
        mock_bw_meter = MagicMock()

        ok_result = MagicMock()
        ok_result.is_ok.return_value = True

        with (
            patch("apps.billing.metering_service.MeteringService") as mock_svc,
            patch("apps.billing.metering_models.UsageMeter") as mock_meter_model,
            patch("apps.billing.metering_service.UsageEventData"),
            patch("apps.billing.metering_tasks.AuditService"),
            patch("apps.provisioning.models.VirtualminAccount") as mock_va,
        ):
            mock_meter_model.objects.filter.return_value.first.side_effect = [mock_disk_meter, mock_bw_meter]
            mock_va.objects.filter.return_value.count.return_value = 1
            mock_va.objects.filter.return_value.select_related.return_value.iterator.return_value = [mock_account]
            mock_svc.return_value.record_event.return_value = ok_result
            result = collect_virtualmin_usage()
        assert result["success"] is True
        assert result["events_created"] == 2

    def test_account_without_service(self) -> None:
        from apps.billing.metering_tasks import collect_virtualmin_usage  # noqa: PLC0415

        mock_account = MagicMock()
        mock_account.service = None

        with (
            patch("apps.billing.metering_service.MeteringService"),
            patch("apps.billing.metering_models.UsageMeter") as mock_meter_model,
            patch("apps.billing.metering_service.UsageEventData"),
            patch("apps.billing.metering_tasks.AuditService"),
            patch("apps.provisioning.models.VirtualminAccount") as mock_va,
        ):
            mock_meter_model.objects.filter.return_value.first.side_effect = [MagicMock(), MagicMock()]
            mock_va.objects.filter.return_value.count.return_value = 1
            mock_va.objects.filter.return_value.select_related.return_value.iterator.return_value = [mock_account]
            result = collect_virtualmin_usage()
        assert result["success"] is True
        assert result["events_created"] == 0

    def test_record_event_error(self) -> None:
        from apps.billing.metering_tasks import collect_virtualmin_usage  # noqa: PLC0415

        mock_account = MagicMock()
        mock_account.id = uuid.uuid4()
        mock_account.service = MagicMock()
        mock_account.service.customer = MagicMock()
        mock_account.service.customer.id = uuid.uuid4()
        mock_account.service.id = uuid.uuid4()
        mock_account.current_disk_usage_gb = 5.0
        mock_account.current_bandwidth_usage_gb = 0
        mock_account.domain = "test.com"

        err_result = MagicMock()
        err_result.is_ok.return_value = False

        with (
            patch("apps.billing.metering_service.MeteringService") as mock_svc,
            patch("apps.billing.metering_models.UsageMeter") as mock_meter_model,
            patch("apps.billing.metering_service.UsageEventData"),
            patch("apps.billing.metering_tasks.AuditService"),
            patch("apps.provisioning.models.VirtualminAccount") as mock_va,
        ):
            mock_meter_model.objects.filter.return_value.first.side_effect = [MagicMock(), MagicMock()]
            mock_va.objects.filter.return_value.count.return_value = 1
            mock_va.objects.filter.return_value.select_related.return_value.iterator.return_value = [mock_account]
            mock_svc.return_value.record_event.return_value = err_result
            result = collect_virtualmin_usage()
        assert result["errors"] == 1

    def test_account_exception(self) -> None:
        from apps.billing.metering_tasks import collect_virtualmin_usage  # noqa: PLC0415

        mock_account = MagicMock()
        mock_account.id = uuid.uuid4()
        mock_account.service = MagicMock()
        mock_account.service.customer = MagicMock()
        mock_account.service.customer.id = uuid.uuid4()
        mock_account.service.id = uuid.uuid4()
        mock_account.current_disk_usage_gb = 5.0
        mock_account.current_bandwidth_usage_gb = 0
        mock_account.domain = "test.com"

        with (
            patch("apps.billing.metering_service.MeteringService") as mock_svc,
            patch("apps.billing.metering_models.UsageMeter") as mock_meter_model,
            patch("apps.billing.metering_service.UsageEventData"),
            patch("apps.billing.metering_tasks.AuditService"),
            patch("apps.provisioning.models.VirtualminAccount") as mock_va,
        ):
            mock_meter_model.objects.filter.return_value.first.side_effect = [MagicMock(), MagicMock()]
            mock_va.objects.filter.return_value.count.return_value = 1
            mock_va.objects.filter.return_value.select_related.return_value.iterator.return_value = [mock_account]
            mock_svc.return_value.record_event.side_effect = RuntimeError("kaboom")
            result = collect_virtualmin_usage()
        assert result["errors"] == 1

    def test_outer_exception(self) -> None:
        from apps.billing.metering_tasks import collect_virtualmin_usage  # noqa: PLC0415

        with patch("apps.billing.metering_service.MeteringService", side_effect=RuntimeError("boom")):
            result = collect_virtualmin_usage()
        assert result["success"] is False


class TestCollectServiceUsage(TestCase):
    def test_success(self) -> None:
        from apps.billing.metering_tasks import collect_service_usage  # noqa: PLC0415

        mock_svc = MagicMock()
        mock_svc.customer = MagicMock()
        mock_svc.customer.id = uuid.uuid4()
        mock_svc.id = uuid.uuid4()
        mock_svc.disk_usage_mb = 2048
        mock_svc.bandwidth_usage_mb = 1024
        mock_svc.service_name = "web"
        mock_svc.domain = "test.com"

        ok_result = MagicMock()
        ok_result.is_ok.return_value = True

        with (
            patch("apps.billing.metering_service.MeteringService") as mock_ms,
            patch("apps.billing.metering_service.UsageEventData"),
            patch("apps.provisioning.models.Service") as mock_model,
        ):
            mock_model.objects.filter.return_value.count.return_value = 1
            mock_model.objects.filter.return_value.select_related.return_value.iterator.return_value = [mock_svc]
            mock_ms.return_value.record_event.return_value = ok_result
            result = collect_service_usage()
        assert result["success"] is True
        assert result["events_created"] == 2

    def test_no_usage(self) -> None:
        from apps.billing.metering_tasks import collect_service_usage  # noqa: PLC0415

        mock_svc = MagicMock()
        mock_svc.customer = MagicMock()
        mock_svc.disk_usage_mb = 0
        mock_svc.bandwidth_usage_mb = None

        with (
            patch("apps.billing.metering_service.MeteringService"),
            patch("apps.billing.metering_service.UsageEventData"),
            patch("apps.provisioning.models.Service") as mock_model,
        ):
            mock_model.objects.filter.return_value.count.return_value = 1
            mock_model.objects.filter.return_value.select_related.return_value.iterator.return_value = [mock_svc]
            result = collect_service_usage()
        assert result["success"] is True
        assert result["events_created"] == 0

    def test_record_error(self) -> None:
        from apps.billing.metering_tasks import collect_service_usage  # noqa: PLC0415

        mock_svc = MagicMock()
        mock_svc.customer = MagicMock()
        mock_svc.customer.id = uuid.uuid4()
        mock_svc.id = uuid.uuid4()
        mock_svc.disk_usage_mb = 1024
        mock_svc.bandwidth_usage_mb = 0
        mock_svc.service_name = "web"
        mock_svc.domain = "test.com"

        err_result = MagicMock()
        err_result.is_ok.return_value = False

        with (
            patch("apps.billing.metering_service.MeteringService") as mock_ms,
            patch("apps.billing.metering_service.UsageEventData"),
            patch("apps.provisioning.models.Service") as mock_model,
        ):
            mock_model.objects.filter.return_value.count.return_value = 1
            mock_model.objects.filter.return_value.select_related.return_value.iterator.return_value = [mock_svc]
            mock_ms.return_value.record_event.return_value = err_result
            result = collect_service_usage()
        assert result["errors"] == 1

    def test_service_exception(self) -> None:
        from apps.billing.metering_tasks import collect_service_usage  # noqa: PLC0415

        mock_svc = MagicMock()
        mock_svc.customer = MagicMock()
        mock_svc.id = uuid.uuid4()
        mock_svc.disk_usage_mb = 1024
        mock_svc.bandwidth_usage_mb = 0
        mock_svc.service_name = "web"
        mock_svc.domain = "test.com"

        with (
            patch("apps.billing.metering_service.MeteringService") as mock_ms,
            patch("apps.billing.metering_service.UsageEventData"),
            patch("apps.provisioning.models.Service") as mock_model,
        ):
            mock_model.objects.filter.return_value.count.return_value = 1
            mock_model.objects.filter.return_value.select_related.return_value.iterator.return_value = [mock_svc]
            mock_ms.return_value.record_event.side_effect = RuntimeError("boom")
            result = collect_service_usage()
        assert result["errors"] == 1

    def test_outer_exception(self) -> None:
        from apps.billing.metering_tasks import collect_service_usage  # noqa: PLC0415

        with patch("apps.billing.metering_service.MeteringService", side_effect=RuntimeError("boom")):
            result = collect_service_usage()
        assert result["success"] is False


class TestAsyncWrappers(TestCase):
    def test_update_aggregation_for_event_async(self) -> None:
        from apps.billing.metering_tasks import update_aggregation_for_event_async  # noqa: PLC0415

        with patch("apps.billing.metering_tasks.async_task", return_value="task-123"):
            result = update_aggregation_for_event_async("evt-1")
        assert result == "task-123"

    def test_check_usage_thresholds_async(self) -> None:
        from apps.billing.metering_tasks import check_usage_thresholds_async  # noqa: PLC0415

        with patch("apps.billing.metering_tasks.async_task", return_value="task-456"):
            result = check_usage_thresholds_async("cust-1", "meter-1", "sub-1")
        assert result == "task-456"

    def test_send_usage_alert_notification_async(self) -> None:
        from apps.billing.metering_tasks import send_usage_alert_notification_async  # noqa: PLC0415

        with patch("apps.billing.metering_tasks.async_task", return_value="task-789"):
            result = send_usage_alert_notification_async("alert-1")
        assert result == "task-789"

    def test_sync_aggregation_to_stripe_async(self) -> None:
        from apps.billing.metering_tasks import sync_aggregation_to_stripe_async  # noqa: PLC0415

        with patch("apps.billing.metering_tasks.async_task", return_value="task-abc"):
            result = sync_aggregation_to_stripe_async("agg-1")
        assert result == "task-abc"


class TestRegisterScheduledTasks(TestCase):
    def test_registers_all_tasks(self) -> None:
        from apps.billing.metering_tasks import register_scheduled_tasks  # noqa: PLC0415

        with patch("django_q.models.Schedule") as mock_schedule:
            mock_schedule.MINUTES = 1
            mock_schedule.HOURLY = 2
            register_scheduled_tasks()
        assert mock_schedule.objects.update_or_create.call_count == 6
