"""Retain sibling line-fulfilment jobs when one ORM enqueue fails."""

from unittest.mock import patch

from django.db import OperationalError, connection
from django_q.models import OrmQ

from apps.orders.services import _enqueue_service_line_fulfilment
from tests.common._provisioning_queue_isolation import ProvisioningQueueIsolationTestCase


class OrderQueueIsolationTests(ProvisioningQueueIsolationTestCase):
    def _dispatch(self) -> None:
        with self.captureOnCommitCallbacks(execute=True):
            _enqueue_service_line_fulfilment(self.order)

    def test_second_enqueue_failure_preserves_first_and_continues(self) -> None:
        self.assert_jobs_survive(
            self._dispatch,
            function="apps.orders.tasks.provision_order_item",
            expected_args=[(str(item.pk),) for item in (self.items[0], self.items[2])],
        )

    def test_second_job_savepoint_entry_failure_propagates_and_preserves_first(self) -> None:
        failure = OperationalError("job savepoint entry failed")
        savepoint = connection.savepoint
        entries = 0

        def fail_second_job_entry() -> str | None:
            nonlocal entries
            entries += 1
            if entries == 2:  # First job, then second job.
                raise failure
            return savepoint()

        with (
            patch("django_q.conf.Conf.SYNC", False),
            self.captureOnCommitCallbacks() as callbacks,
        ):
            _enqueue_service_line_fulfilment(self.order)
        with (
            patch("django_q.conf.Conf.SYNC", False),
            patch.object(connection, "savepoint", side_effect=fail_second_job_entry),
            self.assertRaises(OperationalError) as raised,
        ):
            for callback in callbacks:
                callback()
        self.assertIs(raised.exception, failure)
        jobs = list(OrmQ.objects.order_by("pk"))
        self.assertEqual(len(jobs), 1, "Keep the first job; failed entry must stop the batch")
        self.assertEqual(jobs[0].args(), (str(self.items[0].pk),))
