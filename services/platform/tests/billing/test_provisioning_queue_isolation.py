"""Retain sibling Virtualmin jobs when one ORM enqueue fails."""

from apps.billing.signals import _trigger_virtualmin_provisioning_on_payment
from tests.common._provisioning_queue_isolation import ProvisioningQueueIsolationTestCase


class VirtualminQueueIsolationTests(ProvisioningQueueIsolationTestCase):
    def test_second_enqueue_failure_preserves_first_and_continues(self) -> None:
        expected: list[tuple[object, ...]] = [
            ({"service_id": str(service.pk), "domain": service.domain, "template": "Default"},)
            for service in (self.services[0], self.services[2])
        ]
        self.assert_jobs_survive(
            lambda: _trigger_virtualmin_provisioning_on_payment(self.invoice),
            function="apps.provisioning.virtualmin_tasks.provision_virtualmin_account",
            expected_args=expected,
        )
