"""Retain sibling order jobs when one ORM enqueue fails."""

from unittest.mock import patch

from django.db import OperationalError, connection
from django_q.models import OrmQ

from apps.orders.signals import _trigger_service_provisioning
from tests.common._provisioning_queue_isolation import ProvisioningQueueIsolationTestCase


class OrderQueueIsolationTests(ProvisioningQueueIsolationTestCase):
    def test_second_enqueue_failure_preserves_first_and_continues(self) -> None:
        self.assert_jobs_survive(
            lambda: _trigger_service_provisioning(self.order),
            function="apps.orders.tasks.provision_order_item",
            expected_args=[(str(item.pk),) for item in (self.items[0], self.items[2])],
        )

    def test_loading_savepoint_entry_failure_propagates(self) -> None:
        failure = OperationalError("loading savepoint entry failed")
        with patch.object(connection, "savepoint", side_effect=failure), self.assertRaises(OperationalError) as raised:
            _trigger_service_provisioning(self.order)
        self.assertIs(raised.exception, failure)
        self.assertFalse(OrmQ.objects.exists())

    def test_second_job_savepoint_entry_failure_propagates_and_preserves_first(self) -> None:
        failure = OperationalError("job savepoint entry failed")
        savepoint = connection.savepoint
        entries = 0

        def fail_second_job_entry() -> str | None:
            nonlocal entries
            entries += 1
            if entries == 3:  # Loading, first job, then second job.
                raise failure
            return savepoint()

        with (
            patch("django_q.conf.Conf.SYNC", False),
            patch.object(connection, "savepoint", side_effect=fail_second_job_entry),
            self.assertRaises(OperationalError) as raised,
        ):
            _trigger_service_provisioning(self.order)
        self.assertIs(raised.exception, failure)
        jobs = list(OrmQ.objects.order_by("pk"))
        self.assertEqual(len(jobs), 1, "Keep the first job; failed entry must stop the batch")
        self.assertEqual(jobs[0].args(), (str(self.items[0].pk),))
