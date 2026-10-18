"""The leases outlive what they guard (ADR-0061 P1.4, P1.10).

A worker the queue still lets run must never lose its lease, and a node step must fit its task. Each
bound is derived from the timeouts that actually limit the work, so a change to one of them that breaks
the relation fails here instead of in production.
"""

from __future__ import annotations

from django.conf import settings
from django.test import SimpleTestCase

from apps.infrastructure.ansible_service import AnsibleService
from apps.provisioning import account_name_certificates as certs
from apps.provisioning import account_name_node, acme_client
from apps.provisioning.account_name_lease import ACCOUNT_NAME_TASK_TIMEOUT_SECONDS, NODE_LEASE

SSH_WAIT_SECONDS = 180  # AnsibleService._wait_for_ssh's default, waited before every playbook
ACME_REQUESTS = 8  # account, order, authorizations, answers, polls and finalisation, each request-bounded


def _acme_exchange_seconds() -> float:
    """The longest the ACME exchange can run: its poll deadline, the settle wait, each request's timeout."""
    return (
        acme_client.ORDER_DEADLINE_SECONDS
        + certs.DNS_SETTLE_SECONDS
        + ACME_REQUESTS * acme_client._REQUEST_TIMEOUT_SECONDS
    )


class BoundsTests(SimpleTestCase):
    def test_the_ssh_wait_this_file_assumes_is_the_services(self) -> None:
        self.assertEqual(AnsibleService._wait_for_ssh.__defaults__[1], SSH_WAIT_SECONDS)  # type: ignore[index]  # (port, timeout, interval)

    def test_an_attempt_lease_outlives_the_acme_exchange(self) -> None:
        self.assertGreater(certs.ATTEMPT_LEASE.total_seconds(), _acme_exchange_seconds())

    def test_a_node_step_fits_its_task(self) -> None:
        playbooks = 2 * SSH_WAIT_SECONDS + certs.INSTALL_TIMEOUT_SECONDS + account_name_node.LINK_TIMEOUT_SECONDS
        self.assertGreater(ACCOUNT_NAME_TASK_TIMEOUT_SECONDS, playbooks + _acme_exchange_seconds())

    def test_the_node_lease_outlives_the_task_and_the_queue_retries_after_it(self) -> None:
        self.assertGreater(NODE_LEASE.total_seconds(), ACCOUNT_NAME_TASK_TIMEOUT_SECONDS)
        self.assertGreater(settings.Q_CLUSTER["retry"], ACCOUNT_NAME_TASK_TIMEOUT_SECONDS)


class DispatchTests(SimpleTestCase):
    def test_every_account_name_task_is_queued_with_its_own_timeout(self) -> None:
        from unittest.mock import patch  # noqa: PLC0415

        with patch("django_q.tasks.async_task") as enqueue:
            certs._dispatch(certs.INSTALL_TASK, "row-id")

        enqueue.assert_called_once_with(certs.INSTALL_TASK, "row-id", timeout=ACCOUNT_NAME_TASK_TIMEOUT_SECONDS)
