"""Retain sibling order jobs when one ORM enqueue fails."""

from apps.orders.signals import _trigger_service_provisioning
from tests.common._provisioning_queue_isolation import ProvisioningQueueIsolationTestCase


class OrderQueueIsolationTests(ProvisioningQueueIsolationTestCase):
    def test_second_enqueue_failure_preserves_first_and_continues(self) -> None:
        self.assert_jobs_survive(
            lambda: _trigger_service_provisioning(self.order),
            function="apps.orders.tasks.provision_order_item",
            expected_args=[(str(item.pk),) for item in (self.items[0], self.items[2])],
        )
