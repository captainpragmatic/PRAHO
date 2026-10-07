"""Effect tests for persisted e-Factura document retry policy."""

from datetime import timedelta
from uuid import uuid4

from django.test import TestCase
from django.utils import timezone

from apps.billing.efactura.models import EFacturaDocument, EFacturaStatus
from apps.settings.services import SettingsService
from tests.factories import InvoiceFactory


class EFacturaRetrySettingsEffectsTests(TestCase):
    """Exercise real transitions and retry selection without replacing consumers."""

    def _write(self, key: str, value: int) -> None:
        result = SettingsService.update_setting(key, value)
        self.assertTrue(result.is_ok(), str(result))
        self.addCleanup(SettingsService._clear_setting_cache, key)

    def _document(self, retry_count: int = 0) -> EFacturaDocument:
        invoice = InvoiceFactory(
            number=f"RETRY-{uuid4().hex}",
            status="issued",
            bill_to_country="RO",
        )
        return EFacturaDocument.objects.create(invoice=invoice, retry_count=retry_count)

    def _assert_scheduled_delay(self, attempt: int, seconds: int) -> None:
        document = self._document(retry_count=attempt - 1)
        document.mark_queued()
        document.save()
        before = timezone.now()
        document.mark_error("Transient submission failure")
        document.save()
        after = timezone.now()
        persisted = EFacturaDocument.objects.get(pk=document.pk)

        self.assertEqual(persisted.status, EFacturaStatus.ERROR.value)
        self.assertEqual(persisted.retry_count, attempt)
        self.assertEqual(persisted.last_error, "Transient submission failure")
        self.assertIsNotNone(persisted.next_retry_at)
        if persisted.next_retry_at is None:
            self.fail("A retry must have a persisted deadline")
        self.assertLessEqual(persisted.next_retry_at, after + timedelta(seconds=seconds))
        self.assertGreaterEqual(persisted.next_retry_at, before + timedelta(seconds=seconds))
        self.assertNotIn(document.pk, EFacturaDocument.get_ready_for_retry().values_list("pk", flat=True))

    def test_delay_1_changes_persisted_retry_deadline(self) -> None:
        self._write("efactura.retry.delay_1_seconds", 17)
        self._assert_scheduled_delay(attempt=1, seconds=17)

    def test_delay_2_changes_persisted_retry_deadline(self) -> None:
        self._write("efactura.retry.delay_2_seconds", 29)
        self._assert_scheduled_delay(attempt=2, seconds=29)

    def test_delay_3_changes_persisted_retry_deadline(self) -> None:
        self._write("efactura.retry.delay_3_seconds", 43)
        self._assert_scheduled_delay(attempt=3, seconds=43)

    def test_delay_4_changes_persisted_retry_deadline(self) -> None:
        self._write("efactura.retry.delay_4_seconds", 59)
        self._assert_scheduled_delay(attempt=4, seconds=59)

    def test_delay_5_changes_persisted_retry_deadline(self) -> None:
        self._write("efactura.retry.delay_5_seconds", 71)
        self._assert_scheduled_delay(attempt=5, seconds=71)
        self._write("efactura.retry.max_retries", 7)
        self._assert_scheduled_delay(attempt=7, seconds=71)

    def test_max_retries_changes_scheduling_and_both_retry_gates(self) -> None:
        self._write("efactura.retry.max_retries", 0)
        document = self._document()
        document.mark_local_error("Invalid invoice data")
        document.save()
        persisted = EFacturaDocument.objects.get(pk=document.pk)
        self.assertFalse(persisted.can_requeue_after_fix)

        persisted.mark_queued()
        persisted.mark_error("Retries disabled")
        persisted.save()
        persisted = EFacturaDocument.objects.get(pk=persisted.pk)
        self.assertIsNone(persisted.next_retry_at)
        self.assertFalse(persisted.can_retry)

        for budget in (2, 7):
            with self.subTest(budget=budget):
                self._assert_retry_budget(budget)

    def _assert_retry_budget(self, budget: int) -> None:
        self._write("efactura.retry.max_retries", budget)
        automatic = self._document(retry_count=budget - 2)
        automatic.mark_queued()
        automatic.save()
        automatic.mark_error("Transient submission failure")
        automatic.save()
        persisted = EFacturaDocument.objects.get(pk=automatic.pk)
        self.assertEqual(persisted.retry_count, budget - 1)
        self.assertIsNotNone(persisted.next_retry_at)
        self.assertTrue(persisted.can_retry)

        self._write("efactura.retry.max_retries", budget - 1)
        self.assertFalse(persisted.can_retry)
        self._write("efactura.retry.max_retries", budget)
        self.assertTrue(persisted.can_retry)
        persisted.mark_queued()
        persisted.mark_error("Transient submission failure")
        persisted.save()
        persisted = EFacturaDocument.objects.get(pk=persisted.pk)
        self.assertEqual(persisted.retry_count, budget)
        self.assertIsNotNone(persisted.next_retry_at)
        self.assertFalse(persisted.can_retry)

        persisted.mark_queued()
        persisted.mark_error("Retry budget exceeded")
        persisted.save()
        persisted = EFacturaDocument.objects.get(pk=persisted.pk)
        self.assertEqual(persisted.retry_count, budget + 1)
        self.assertIsNone(persisted.next_retry_at)
        self.assertFalse(persisted.can_retry)
        self.assertFalse(persisted.can_requeue_after_fix)
        self.assertNotIn(persisted.pk, EFacturaDocument.get_ready_for_retry().values_list("pk", flat=True))

        local = self._document(retry_count=budget - 1)
        local.mark_local_error("Invalid invoice data")
        local.save()
        persisted = EFacturaDocument.objects.get(pk=local.pk)
        self.assertFalse(persisted.can_retry)
        self.assertTrue(persisted.can_requeue_after_fix)
        self._write("efactura.retry.max_retries", budget - 1)
        self.assertFalse(persisted.can_requeue_after_fix)
        self._write("efactura.retry.max_retries", budget)
        persisted.mark_queued()
        persisted.mark_error("Transient submission failure")
        persisted.save()
        persisted = EFacturaDocument.objects.get(pk=persisted.pk)
        self.assertEqual(persisted.retry_count, budget)
        self.assertFalse(persisted.can_retry)
