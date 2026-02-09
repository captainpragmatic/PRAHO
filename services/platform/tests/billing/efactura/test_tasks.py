"""
Tests for e-Factura async tasks.
"""

from unittest.mock import MagicMock, Mock, patch
from uuid import uuid4

from django.test import TestCase, override_settings
from django.utils import timezone

from apps.billing.efactura.models import EFacturaDocument, EFacturaStatus
from apps.billing.efactura.service import SubmissionResult, StatusCheckResult
from apps.billing.efactura.tasks import (
    check_efactura_deadlines_task,
    download_efactura_response_task,
    poll_all_pending_status_task,
    poll_efactura_status_task,
    process_efactura_retries_task,
    process_pending_submissions_task,
    queue_efactura_submission,
    queue_status_poll,
    schedule_efactura_tasks,
    submit_efactura_task,
    TASK_TIMEOUT,
)


class SubmitEfacturaTaskTestCase(TestCase):
    """Test submit_efactura_task."""

    @patch("apps.billing.efactura.tasks.Invoice")
    @patch("apps.billing.efactura.tasks.EFacturaService")
    def test_submit_success(self, mock_service_class, mock_invoice_model):
        """Test successful submission task."""
        invoice_id = str(uuid4())
        mock_invoice = Mock()
        mock_invoice.number = "INV-001"
        mock_invoice_model.objects.get.return_value = mock_invoice

        mock_service = Mock()
        mock_service_class.return_value = mock_service

        mock_doc = Mock()
        mock_doc.anaf_upload_index = "12345"
        mock_service.submit_invoice.return_value = SubmissionResult(
            success=True,
            document=mock_doc,
        )

        result = submit_efactura_task(invoice_id)

        self.assertTrue(result["success"])
        self.assertEqual(result["invoice_id"], invoice_id)
        self.assertEqual(result["upload_index"], "12345")

    @patch("apps.billing.efactura.tasks.Invoice")
    def test_submit_invoice_not_found(self, mock_invoice_model):
        """Test submission when invoice not found."""
        from apps.billing.invoice_models import Invoice as InvoiceModel

        invoice_id = str(uuid4())
        mock_invoice_model.objects.get.side_effect = InvoiceModel.DoesNotExist()

        result = submit_efactura_task(invoice_id)

        self.assertFalse(result["success"])
        self.assertIn("not found", result["error"].lower())

    @patch("apps.billing.efactura.tasks.Invoice")
    @patch("apps.billing.efactura.tasks.EFacturaService")
    def test_submit_failure(self, mock_service_class, mock_invoice_model):
        """Test failed submission task."""
        invoice_id = str(uuid4())
        mock_invoice = Mock()
        mock_invoice.number = "INV-001"
        mock_invoice_model.objects.get.return_value = mock_invoice

        mock_service = Mock()
        mock_service_class.return_value = mock_service
        mock_service.submit_invoice.return_value = SubmissionResult(
            success=False,
            error_message="Validation failed",
            errors=[{"code": "BR-01"}],
        )

        result = submit_efactura_task(invoice_id)

        self.assertFalse(result["success"])
        self.assertEqual(result["error"], "Validation failed")
        self.assertEqual(len(result["errors"]), 1)


class PollEfacturaStatusTaskTestCase(TestCase):
    """Test poll_efactura_status_task."""

    @patch("apps.billing.efactura.tasks.EFacturaDocument")
    @patch("apps.billing.efactura.tasks.EFacturaService")
    def test_poll_success(self, mock_service_class, mock_doc_model):
        """Test successful status poll."""
        doc_id = str(uuid4())
        mock_doc = Mock()
        mock_doc.invoice = Mock(number="INV-001")
        mock_doc_model.objects.select_related.return_value.get.return_value = mock_doc

        mock_service = Mock()
        mock_service_class.return_value = mock_service
        mock_service.check_status.return_value = StatusCheckResult(
            status="accepted",
            is_terminal=True,
            download_id="67890",
        )

        result = poll_efactura_status_task(doc_id)

        self.assertTrue(result["success"])
        self.assertEqual(result["status"], "accepted")
        self.assertTrue(result["is_terminal"])
        self.assertEqual(result["download_id"], "67890")

    @patch("apps.billing.efactura.tasks.EFacturaDocument")
    def test_poll_document_not_found(self, mock_doc_model):
        """Test poll when document not found."""
        doc_id = str(uuid4())
        mock_doc_model.objects.select_related.return_value.get.side_effect = (
            EFacturaDocument.DoesNotExist()
        )

        result = poll_efactura_status_task(doc_id)

        self.assertFalse(result["success"])
        self.assertIn("not found", result["error"].lower())


class PollAllPendingStatusTaskTestCase(TestCase):
    """Test poll_all_pending_status_task."""

    @patch("apps.billing.efactura.tasks.EFacturaService")
    def test_poll_all_pending(self, mock_service_class):
        """Test polling all pending documents."""
        mock_service = Mock()
        mock_service_class.return_value = mock_service
        mock_service.poll_awaiting_documents.return_value = {
            "accepted": 3,
            "rejected": 1,
            "processing": 2,
            "error": 0,
        }

        result = poll_all_pending_status_task()

        self.assertTrue(result["success"])
        self.assertEqual(result["accepted"], 3)
        self.assertEqual(result["rejected"], 1)
        mock_service.poll_awaiting_documents.assert_called_once_with(limit=100)


class ProcessEfacturaRetriesTaskTestCase(TestCase):
    """Test process_efactura_retries_task."""

    @patch("apps.billing.efactura.tasks.EFacturaService")
    def test_process_retries(self, mock_service_class):
        """Test processing retries."""
        mock_service = Mock()
        mock_service_class.return_value = mock_service
        mock_service.process_retries.return_value = {
            "retried": 2,
            "failed": 1,
        }

        result = process_efactura_retries_task()

        self.assertTrue(result["success"])
        self.assertEqual(result["retried"], 2)
        self.assertEqual(result["failed"], 1)


class ProcessPendingSubmissionsTaskTestCase(TestCase):
    """Test process_pending_submissions_task."""

    @patch("apps.billing.efactura.tasks.EFacturaService")
    def test_process_pending(self, mock_service_class):
        """Test processing pending submissions."""
        mock_service = Mock()
        mock_service_class.return_value = mock_service
        mock_service.process_pending_submissions.return_value = {
            "submitted": 5,
            "failed": 2,
            "skipped": 0,
        }

        result = process_pending_submissions_task()

        self.assertTrue(result["success"])
        self.assertEqual(result["submitted"], 5)
        mock_service.process_pending_submissions.assert_called_once_with(limit=50)


class CheckEfacturaDeadlinesTaskTestCase(TestCase):
    """Test check_efactura_deadlines_task."""

    @patch("apps.billing.efactura.tasks._create_deadline_alerts")
    @patch("apps.billing.efactura.tasks.EFacturaService")
    def test_check_deadlines_none_approaching(self, mock_service_class, mock_create_alerts):
        """Test checking deadlines with none approaching."""
        mock_service = Mock()
        mock_service_class.return_value = mock_service
        mock_service.check_approaching_deadlines.return_value = []

        result = check_efactura_deadlines_task()

        self.assertTrue(result["success"])
        self.assertEqual(result["approaching_deadline_count"], 0)
        mock_create_alerts.assert_not_called()

    @patch("apps.billing.efactura.tasks._create_deadline_alerts")
    @patch("apps.billing.efactura.tasks.EFacturaService")
    def test_check_deadlines_some_approaching(self, mock_service_class, mock_create_alerts):
        """Test checking deadlines with some approaching."""
        mock_service = Mock()
        mock_service_class.return_value = mock_service

        mock_doc = Mock()
        mock_doc.invoice = Mock(number="INV-001")
        mock_service.check_approaching_deadlines.return_value = [mock_doc]

        result = check_efactura_deadlines_task()

        self.assertTrue(result["success"])
        self.assertEqual(result["approaching_deadline_count"], 1)
        self.assertEqual(result["invoice_numbers"], ["INV-001"])
        mock_create_alerts.assert_called_once_with([mock_doc])


class DownloadEfacturaResponseTaskTestCase(TestCase):
    """Test download_efactura_response_task."""

    @patch("apps.billing.efactura.tasks.EFacturaDocument")
    def test_download_document_not_found(self, mock_doc_model):
        """Test download when document not found."""
        doc_id = str(uuid4())
        mock_doc_model.objects.get.side_effect = EFacturaDocument.DoesNotExist()

        result = download_efactura_response_task(doc_id)

        self.assertFalse(result["success"])
        self.assertIn("not found", result["error"].lower())

    @patch("apps.billing.efactura.tasks.EFacturaDocument")
    def test_download_not_accepted(self, mock_doc_model):
        """Test download when document not accepted."""
        doc_id = str(uuid4())
        mock_doc = Mock()
        mock_doc.status = EFacturaStatus.SUBMITTED.value
        mock_doc_model.objects.get.return_value = mock_doc

        result = download_efactura_response_task(doc_id)

        self.assertFalse(result["success"])
        self.assertIn("not accepted", result["error"].lower())

    @patch("apps.billing.efactura.tasks.EFacturaService")
    @patch("apps.billing.efactura.tasks.EFacturaDocument")
    def test_download_success(self, mock_doc_model, mock_service_class):
        """Test successful download."""
        doc_id = str(uuid4())
        mock_doc = Mock()
        mock_doc.status = EFacturaStatus.ACCEPTED.value
        mock_doc.signed_pdf = Mock()
        mock_doc.signed_pdf.path = "/path/to/pdf"
        mock_doc_model.objects.get.return_value = mock_doc

        mock_service = Mock()
        mock_service_class.return_value = mock_service
        mock_service.download_response.return_value = b"%PDF content"

        result = download_efactura_response_task(doc_id)

        self.assertTrue(result["success"])
        self.assertEqual(result["file_path"], "/path/to/pdf")

    @patch("apps.billing.efactura.tasks.EFacturaService")
    @patch("apps.billing.efactura.tasks.EFacturaDocument")
    def test_download_failure(self, mock_doc_model, mock_service_class):
        """Test download failure."""
        doc_id = str(uuid4())
        mock_doc = Mock()
        mock_doc.status = EFacturaStatus.ACCEPTED.value
        mock_doc_model.objects.get.return_value = mock_doc

        mock_service = Mock()
        mock_service_class.return_value = mock_service
        mock_service.download_response.return_value = None

        result = download_efactura_response_task(doc_id)

        self.assertFalse(result["success"])
        self.assertIn("failed", result["error"].lower())


class ScheduleEfacturaTasksTestCase(TestCase):
    """Test schedule_efactura_tasks."""

    @patch("apps.billing.efactura.tasks.Schedule")
    def test_schedule_tasks(self, mock_schedule):
        """Test scheduling recurring tasks."""
        mock_schedule.objects.update_or_create.return_value = (Mock(), True)
        mock_schedule.MINUTES = 5
        mock_schedule.HOURLY = 1
        mock_schedule.DAILY = 24

        schedule_efactura_tasks()

        # Should create 4 schedules
        self.assertEqual(mock_schedule.objects.update_or_create.call_count, 4)

    def test_schedule_tasks_no_django_q(self):
        """Test scheduling when Django-Q not installed."""
        with patch(
            "apps.billing.efactura.tasks.Schedule",
            side_effect=ImportError("No module"),
        ):
            # Should not raise, just log warning
            schedule_efactura_tasks()


class QueueEfacturaSubmissionTestCase(TestCase):
    """Test queue_efactura_submission."""

    @patch("apps.billing.efactura.tasks.async_task")
    def test_queue_submission_success(self, mock_async_task):
        """Test queuing submission."""
        invoice_id = str(uuid4())
        mock_async_task.return_value = "task-123"

        result = queue_efactura_submission(invoice_id)

        self.assertEqual(result, "task-123")
        mock_async_task.assert_called_once_with(
            "apps.billing.efactura.tasks.submit_efactura_task",
            invoice_id,
            timeout=TASK_TIMEOUT,
        )

    @patch("apps.billing.efactura.tasks.submit_efactura_task")
    def test_queue_submission_no_django_q(self, mock_submit_task):
        """Test queuing when Django-Q not installed (runs synchronously)."""
        with patch(
            "apps.billing.efactura.tasks.async_task",
            side_effect=ImportError("No module"),
        ):
            invoice_id = str(uuid4())
            mock_submit_task.return_value = {"success": True}

            result = queue_efactura_submission(invoice_id)

            self.assertEqual(result, "sync")
            mock_submit_task.assert_called_once()

    @patch("apps.billing.efactura.tasks.submit_efactura_task")
    def test_queue_submission_sync_failure(self, mock_submit_task):
        """Test queuing with sync fallback failure."""
        with patch(
            "apps.billing.efactura.tasks.async_task",
            side_effect=ImportError("No module"),
        ):
            invoice_id = str(uuid4())
            mock_submit_task.return_value = {"success": False}

            result = queue_efactura_submission(invoice_id)

            self.assertIsNone(result)

    @patch("apps.billing.efactura.tasks.async_task")
    def test_queue_submission_exception(self, mock_async_task):
        """Test queuing with exception."""
        mock_async_task.side_effect = Exception("Queue error")
        invoice_id = str(uuid4())

        result = queue_efactura_submission(invoice_id)

        self.assertIsNone(result)


class QueueStatusPollTestCase(TestCase):
    """Test queue_status_poll."""

    @patch("apps.billing.efactura.tasks.async_task")
    def test_queue_poll_success(self, mock_async_task):
        """Test queuing status poll."""
        doc_id = str(uuid4())
        mock_async_task.return_value = "task-456"

        result = queue_status_poll(doc_id)

        self.assertEqual(result, "task-456")
        mock_async_task.assert_called_once_with(
            "apps.billing.efactura.tasks.poll_efactura_status_task",
            doc_id,
            timeout=TASK_TIMEOUT,
        )

    @patch("apps.billing.efactura.tasks.poll_efactura_status_task")
    def test_queue_poll_no_django_q(self, mock_poll_task):
        """Test queuing poll when Django-Q not installed."""
        with patch(
            "apps.billing.efactura.tasks.async_task",
            side_effect=ImportError("No module"),
        ):
            doc_id = str(uuid4())
            mock_poll_task.return_value = {"success": True}

            result = queue_status_poll(doc_id)

            self.assertEqual(result, "sync")

    @patch("apps.billing.efactura.tasks.async_task")
    def test_queue_poll_exception(self, mock_async_task):
        """Test queuing poll with exception."""
        mock_async_task.side_effect = Exception("Queue error")
        doc_id = str(uuid4())

        result = queue_status_poll(doc_id)

        self.assertIsNone(result)


class TaskTimeoutTestCase(TestCase):
    """Test task timeout configuration."""

    def test_task_timeout_value(self):
        """Test task timeout is set appropriately."""
        # 5 minutes should be enough for API calls with retries
        self.assertEqual(TASK_TIMEOUT, 300)
        self.assertGreater(TASK_TIMEOUT, 60)  # At least 1 minute
        self.assertLess(TASK_TIMEOUT, 600)  # At most 10 minutes
