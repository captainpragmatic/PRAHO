"""
Tests for EFacturaWebhookProcessor and WebhookEvent integration.
"""

from unittest.mock import patch
from uuid import uuid4

from django.test import TestCase


class EFacturaWebhookProcessorTestCase(TestCase):
    """Test EFacturaWebhookProcessor."""

    def setUp(self):
        from apps.integrations.webhooks.efactura import EFacturaWebhookProcessor

        self.processor = EFacturaWebhookProcessor()

    def test_source_name(self):
        """Processor source should be 'efactura'."""
        self.assertEqual(self.processor.source_name, "efactura")

    def test_extract_event_id_from_upload_index(self):
        """Should extract event ID from anaf_upload_index + status."""
        payload = {"anaf_upload_index": "12345", "status": "accepted"}
        event_id = self.processor.extract_event_id(payload)
        self.assertEqual(event_id, "12345_accepted")

    def test_extract_event_id_from_index_incarcare(self):
        """Should also support index_incarcare field name."""
        payload = {"index_incarcare": "67890", "status": "rejected"}
        event_id = self.processor.extract_event_id(payload)
        self.assertEqual(event_id, "67890_rejected")

    def test_extract_event_id_missing_upload_index(self):
        """Should return None when upload index is missing."""
        payload = {"status": "accepted"}
        event_id = self.processor.extract_event_id(payload)
        self.assertIsNone(event_id)

    def test_extract_event_type(self):
        """Should extract event type from status."""
        payload = {"status": "accepted"}
        event_type = self.processor.extract_event_type(payload)
        self.assertEqual(event_type, "efactura.status.accepted")

    def test_extract_event_type_missing_status(self):
        """Should return None when status is missing."""
        payload = {"anaf_upload_index": "12345"}
        event_type = self.processor.extract_event_type(payload)
        self.assertIsNone(event_type)

    @patch("apps.billing.efactura.models.EFacturaDocument.objects")
    def test_verify_signature_with_valid_upload_index(self, mock_objects):
        """Should verify by checking upload_index exists in DB."""
        mock_objects.filter.return_value.exists.return_value = True

        result = self.processor.verify_signature(
            {"anaf_upload_index": "12345"}, "", {}
        )
        self.assertTrue(result)
        mock_objects.filter.assert_called_once_with(anaf_upload_index="12345")

    @patch("apps.billing.efactura.models.EFacturaDocument.objects")
    def test_verify_signature_with_unknown_upload_index(self, mock_objects):
        """Should reject when upload_index not found in DB."""
        mock_objects.filter.return_value.exists.return_value = False

        result = self.processor.verify_signature(
            {"anaf_upload_index": "unknown"}, "", {}
        )
        self.assertFalse(result)

    def test_verify_signature_with_empty_payload(self):
        """Should reject empty payload."""
        result = self.processor.verify_signature({}, "", {})
        self.assertFalse(result)


class RecordAnafResponseTestCase(TestCase):
    """Test the record_anaf_response helper function."""

    def test_creates_webhook_event(self):
        """Should create a WebhookEvent record."""
        from apps.integrations.webhooks.efactura import record_anaf_response

        event = record_anaf_response(
            document_id=str(uuid4()),
            anaf_upload_index="12345",
            status="accepted",
            response_data={"download_id": "DL-001"},
        )

        self.assertIsNotNone(event)
        self.assertEqual(event.source, "efactura")
        self.assertEqual(event.event_id, "12345_accepted")
        self.assertEqual(event.event_type, "efactura.status.accepted")
        self.assertEqual(event.status, "processed")

    def test_deduplicates_events(self):
        """Should skip duplicate events."""
        from apps.integrations.webhooks.efactura import record_anaf_response

        doc_id = str(uuid4())

        # First call creates
        event1 = record_anaf_response(
            document_id=doc_id,
            anaf_upload_index="12345",
            status="accepted",
        )
        self.assertIsNotNone(event1)

        # Second call returns None (duplicate)
        event2 = record_anaf_response(
            document_id=doc_id,
            anaf_upload_index="12345",
            status="accepted",
        )
        self.assertIsNone(event2)

    def test_different_statuses_not_duplicates(self):
        """Events with different statuses should not be duplicates."""
        from apps.integrations.webhooks.efactura import record_anaf_response

        doc_id = str(uuid4())

        event1 = record_anaf_response(
            document_id=doc_id,
            anaf_upload_index="12345",
            status="processing",
        )
        event2 = record_anaf_response(
            document_id=doc_id,
            anaf_upload_index="12345",
            status="accepted",
        )

        self.assertIsNotNone(event1)
        self.assertIsNotNone(event2)
        self.assertNotEqual(event1.event_id, event2.event_id)


class GetWebhookProcessorTestCase(TestCase):
    """Test that efactura processor is registered in the factory."""

    def test_efactura_processor_registered(self):
        """get_webhook_processor('efactura') should return EFacturaWebhookProcessor."""
        from apps.integrations.webhooks.base import get_webhook_processor
        from apps.integrations.webhooks.efactura import EFacturaWebhookProcessor

        processor = get_webhook_processor("efactura")
        self.assertIsNotNone(processor)
        self.assertIsInstance(processor, EFacturaWebhookProcessor)
