"""Behaviour regressions for retry policy, quota reservation and supplier fallback."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import timedelta
from threading import Barrier
from typing import ClassVar, cast
from unittest.mock import patch
from uuid import uuid4

import requests
from django.core.cache import cache
from django.db import DatabaseError, connection, connections, transaction
from django.test import SimpleTestCase, TestCase, override_settings
from django.test.utils import CaptureQueriesContext
from django.utils import timezone
from freezegun import freeze_time

from apps.billing.efactura.client import EFacturaClient, EFacturaConfig
from apps.billing.efactura.models import EFacturaDocument, EFacturaStatus
from apps.billing.efactura.quota import ANAFQuotaTracker, QuotaEndpoint, QuotaExceededError
from apps.billing.efactura.service import EFacturaService
from apps.common import counters
from apps.settings.services import SettingsService
from config.settings.test import LOCMEM_TEST_CACHE
from tests.billing.efactura.test_efactura_connection_settings_effects import VALID_XML
from tests.billing.efactura.test_submission_claims import _SubmissionClaimFixture
from tests.helpers.counter_concurrency import counter_database


@freeze_time("2026-10-07 09:00:00+00:00")
@override_settings(
    EFACTURA_ENABLED=True,
    EFACTURA_ENVIRONMENT="test",
    EFACTURA_ACCESS_TOKEN="review-token",
    EFACTURA_SUBMISSION_AUTO_SUBMIT_ENABLED=True,
    EFACTURA_RETRY_MAX_RETRIES=2,
    EFACTURA_RETRY_DELAY_1_SECONDS=17,
    EFACTURA_RETRY_DELAY_2_SECONDS=29,
    EFACTURA_RATE_LIMIT_GLOBAL_PER_MINUTE=0,
    CACHES=LOCMEM_TEST_CACHE,
)
class SubmissionQuotaReviewTests(_SubmissionClaimFixture, TestCase):
    def setUp(self) -> None:
        super().setUp()
        cache.clear()
        self.addCleanup(cache.clear)
        self.invoice = self.create_invoice(f"EF2-{uuid4().hex}")
        self.document = EFacturaDocument.objects.create(invoice=self.invoice, xml_content=VALID_XML, retry_count=1)
        self.service_under_test = EFacturaService(
            client=EFacturaClient(EFacturaConfig("review-client", "review-secret", "12345678"))
        )
        self.payloads: list[bytes] = []

    def _transport(self, method: str, url: str, **kwargs: object) -> requests.Response:
        self.assertEqual(method, "POST")
        self.assertTrue(url.endswith("/upload"))
        self.payloads.append(cast(bytes, kwargs["data"]))
        response = requests.Response()
        response.status_code = 200
        response._content = b'<header ExecutionStatus="0" index_incarcare="EF2-ACCEPTED"/>'
        return response

    @contextmanager
    def _unavailable_counter_store(self) -> Iterator[None]:
        # Real database rejection at the counter boundary; business rows remain writable.
        with connection.cursor() as cursor:
            if connection.vendor == "postgresql":
                cursor.execute(
                    "CREATE FUNCTION pg_temp.ef2_counter_failure() RETURNS trigger LANGUAGE plpgsql AS $ef2$ "
                    "BEGIN RAISE EXCEPTION 'Counter store unavailable' USING ERRCODE = '58000'; END; $ef2$"
                )
                cursor.execute(
                    "CREATE TRIGGER ef2_counter_failure BEFORE INSERT ON common_counters "
                    "FOR EACH ROW EXECUTE FUNCTION pg_temp.ef2_counter_failure()"
                )
            else:
                cursor.execute(
                    "CREATE TEMP TRIGGER ef2_counter_failure BEFORE INSERT ON common_counters "
                    "BEGIN SELECT RAISE(ABORT, 'Counter store unavailable'); END"
                )
        try:
            yield
        finally:
            with connection.cursor() as cursor:
                if connection.vendor == "postgresql":
                    cursor.execute("DROP TRIGGER ef2_counter_failure ON common_counters")
                    cursor.execute("DROP FUNCTION pg_temp.ef2_counter_failure()")
                else:
                    cursor.execute("DROP TRIGGER ef2_counter_failure")

    def test_unavailable_counter_store_schedules_a_safe_retry_without_dispatch(self) -> None:
        self.document.retry_count = 0
        self.document.save()
        with (
            self._unavailable_counter_store(),
            patch("apps.billing.efactura.client.safe_request", side_effect=self._transport),
        ):
            try:
                with transaction.atomic():
                    result = self.service_under_test.submit_invoice(self.invoice)
            except DatabaseError as error:
                self.fail(f"Pre-dispatch store failure escaped without scheduling a retry: {error}")

        self.assertFalse(result.success)
        persisted = EFacturaDocument.objects.get(pk=self.document.pk)
        self.assertEqual(persisted.status, EFacturaStatus.ERROR.value)
        self.assertEqual(self.payloads, [])
        self.assertEqual(persisted.retry_count, 1)
        self.assertEqual(persisted.next_retry_at, timezone.now() + timedelta(seconds=17))
        self.assertTrue(persisted.can_retry)
        self.assertIsNone(persisted.submission_claim_token)

    def test_quota_deferral_preserves_last_retry_and_submits_after_reset(self) -> None:
        with override_settings(EFACTURA_RATE_LIMIT_GLOBAL_PER_MINUTE=1):
            tracker = ANAFQuotaTracker()
            tracker.check_and_increment(QuotaEndpoint.UPLOAD, "other-company")
            with patch("apps.billing.efactura.client.safe_request", side_effect=self._transport):
                result = self.service_under_test.submit_invoice(self.invoice)
            self.assertFalse(result.success)
            persisted = EFacturaDocument.objects.get(pk=self.document.pk)
            self.assertEqual(persisted.retry_count, 1)
            self.assertEqual(persisted.status, EFacturaStatus.QUEUED.value)
            self.assertEqual(persisted.next_retry_at, timezone.now() + timedelta(minutes=1))
            self.assertIsNone(persisted.submission_claim_token)
            self.assertEqual(self.payloads, [])
            self.assertNotIn(persisted.pk, EFacturaDocument.get_pending_submissions().values_list("pk", flat=True))

            with freeze_time("2026-10-07 09:01:00+00:00"):
                with patch("apps.billing.efactura.client.safe_request", side_effect=self._transport):
                    summary = self.service_under_test.process_pending_submissions()
                persisted = EFacturaDocument.objects.get(pk=self.document.pk)
                self.assertEqual(summary, {"submitted": 1, "failed": 0, "skipped": 0})
                self.assertEqual(persisted.status, EFacturaStatus.SUBMITTED.value)
                self.assertEqual(persisted.retry_count, 1)
                self.assertEqual(persisted.anaf_upload_index, "EF2-ACCEPTED")
                self.assertEqual(self.payloads, [VALID_XML.encode("utf-8")])


@freeze_time("2026-10-07 09:00:00+00:00")
@override_settings(
    EFACTURA_ENABLED=True,
    EFACTURA_ENVIRONMENT="test",
    EFACTURA_ACCESS_TOKEN="review-token",
    EFACTURA_SUBMISSION_AUTO_SUBMIT_ENABLED=True,
    EFACTURA_RATE_LIMIT_GLOBAL_PER_MINUTE=0,
    EFACTURA_RETRY_MAX_RETRIES=2,
    EFACTURA_RETRY_DELAY_1_SECONDS=17,
    CACHES=LOCMEM_TEST_CACHE,
)
class RetryPolicyQueryReviewTests(_SubmissionClaimFixture, SimpleTestCase):
    # SimpleTestCase supplies no enclosing atomic block: the warm-cache test runs in autocommit.
    databases: ClassVar[set[str]] = {"default"}

    def setUp(self) -> None:
        super().setUp()
        cache.clear()
        self.addCleanup(cache.clear)
        self.documents: list[EFacturaDocument] = []
        for _index in range(3):
            invoice = self.create_invoice(f"EF2-BATCH-{uuid4().hex}")
            self.addCleanup(invoice.customer.delete)
            self.addCleanup(invoice.delete)
            self.documents.append(
                EFacturaDocument.objects.create(
                    invoice=invoice, xml_content=VALID_XML, status=EFacturaStatus.QUEUED.value
                )
            )
        self.service_under_test = EFacturaService(
            client=EFacturaClient(EFacturaConfig("review-client", "review-secret", "12345678"))
        )

    def _assert_batch(self) -> None:
        response = requests.Response()
        response.status_code = 400
        response._content = b'<header ExecutionStatus="1"><Errors errorMessage="Refused"/></header>'
        with (
            CaptureQueriesContext(connection) as queries,
            patch("apps.billing.efactura.client.safe_request", return_value=response),
        ):
            result = self.service_under_test.process_pending_submissions(limit=3)
        self.assertEqual(result, {"submitted": 0, "failed": 3, "skipped": 0})
        for document in self.documents:
            persisted = EFacturaDocument.objects.get(pk=document.pk)
            self.assertEqual(persisted.status, EFacturaStatus.ERROR.value)
            self.assertEqual(persisted.retry_count, 1)
            self.assertEqual(persisted.next_retry_at, timezone.now() + timedelta(seconds=17))
        policy_selects = [
            query["sql"]
            for query in queries
            if query["sql"].lstrip().upper().startswith("SELECT")
            and "setting_entries" in query["sql"]
            and "efactura.retry." in query["sql"]
        ]
        self.assertEqual(len(policy_selects), 1, policy_selects)

    def test_batch_resolves_policy_once_with_warm_cache(self) -> None:
        self.assertFalse(connection.in_atomic_block)
        SettingsService.get_integer_setting("efactura.retry.max_retries", 5)
        self._assert_batch()

    def test_batch_resolves_policy_once_inside_transaction(self) -> None:
        with transaction.atomic():
            self._assert_batch()


@freeze_time("2026-10-07 09:00:00+00:00")
@override_settings(
    EFACTURA_RATE_LIMIT_GLOBAL_PER_MINUTE=0,
    EFACTURA_RATE_LIMIT_STATUS_PER_MESSAGE_DAY=0,
)
class QuotaConcurrencyReviewTests(SimpleTestCase):
    databases: ClassVar[set[str]] = {"default"}

    def _race(self, *, global_limit: int, endpoint_limit: int) -> None:
        start = Barrier(2)
        readers = Barrier(2)
        with (
            override_settings(
                EFACTURA_RATE_LIMIT_GLOBAL_PER_MINUTE=global_limit,
                EFACTURA_RATE_LIMIT_STATUS_PER_MESSAGE_DAY=endpoint_limit,
            ),
            counter_database(),
        ):
            tracker = ANAFQuotaTracker()
            global_key = tracker._get_global_minute_key()
            endpoint_key = tracker._get_cache_key(QuotaEndpoint.STATUS, "12345678", "last-slot")
            counters.reset(global_key)
            counters.reset(endpoint_key)
            self.addCleanup(counters.reset, global_key)
            self.addCleanup(counters.reset, endpoint_key)

            def reserve() -> bool:
                connections.close_all()
                wrote = False
                parked = False

                def synchronize_reads(
                    execute: Callable[..., object],
                    sql: str,
                    params: object,
                    many: bool,
                    context: dict[str, object],
                ) -> object:
                    nonlocal wrote, parked
                    result = execute(sql, params, many, context)
                    if "common_counters" in sql:
                        if sql.lstrip().upper().startswith("INSERT"):
                            wrote = True
                        elif sql.lstrip().upper().startswith("SELECT") and not wrote and not parked:
                            parked = True
                            readers.wait(timeout=10)
                    return result

                try:
                    with connection.execute_wrapper(synchronize_reads):
                        start.wait(timeout=10)
                        try:
                            ANAFQuotaTracker().check_and_increment(QuotaEndpoint.STATUS, "12345678", "last-slot")
                        except QuotaExceededError:
                            return False
                        return True
                finally:
                    connections.close_all()

            with ThreadPoolExecutor(max_workers=2) as executor:
                futures = [executor.submit(reserve) for _index in range(2)]
                accepted = [future.result(timeout=20) for future in futures]
            self.assertEqual(sorted(accepted), [False, True])
            self.assertEqual(counters.peek(global_key), 1)
            self.assertEqual(counters.peek(endpoint_key), 1)

    def test_two_workers_cannot_take_the_last_global_slot(self) -> None:
        self._race(global_limit=1, endpoint_limit=0)

    def test_two_workers_cannot_take_the_last_endpoint_slot(self) -> None:
        self._race(global_limit=0, endpoint_limit=1)
