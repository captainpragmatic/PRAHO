"""The leases outlive what they guard (ADR-0061 P1.4, P1.10).

A worker the queue still lets run must never lose its lease, and a node step must fit its task. Each
bound is derived from the timeouts that actually limit the work, so a change to one of them that breaks
the relation fails here instead of in production.
"""

from __future__ import annotations

import inspect

from django.conf import settings
from django.test import SimpleTestCase

from apps.infrastructure import dns_gateway
from apps.infrastructure.ansible_service import AnsibleService
from apps.provisioning import account_name_certificates as certs
from apps.provisioning import account_name_node, acme_client
from apps.provisioning.account_name_lease import ACCOUNT_NAME_TASK_TIMEOUT_SECONDS, NODE_LEASE

SSH_WAIT_SECONDS = 180  # AnsibleService._wait_for_ssh's default, waited before every playbook
VIRTUALMIN_CALL_SECONDS = (30 + 10) * 3 + 0.5 + 1.0  # read+connect timeouts, three attempts and gateway backoff
NODE_STEP_CALLS = 7  # listing (twice), create, re-list, state (twice), enable or disable
NEUTRAL_GUARD_CALLS = 4  # placement, certificate preflight, certificate refresh, final readiness
ACME_REQUESTS = 8  # account, order, authorizations, answers, polls and finalisation, each request-bounded
DNS_CHALLENGE_CALLS = 4  # TXT list/create, then owned-record list/delete for one ordinary challenge


def _dns_request_seconds() -> float:
    """All permitted attempts and Retry-After waits of one logical provider request."""
    policy = dns_gateway.CLOUDFLARE_POLICY
    return (policy.connect_timeout_seconds + policy.timeout_seconds) * (
        dns_gateway.DEFAULT_MAX_RETRIES + 1
    ) + dns_gateway.DEFAULT_MAX_RETRIES * dns_gateway._MAX_IN_PROCESS_RETRY_SECONDS


def _acme_exchange_seconds() -> float:
    """The longest the ACME exchange can run: its poll deadline, the settle wait, each request's timeout."""
    return (
        acme_client.ORDER_DEADLINE_SECONDS
        + certs.DNS_SETTLE_SECONDS
        + ACME_REQUESTS * (acme_client._REQUEST_TIMEOUT_SECONDS + 10)  # Default outbound connect budget
        + DNS_CHALLENGE_CALLS * _dns_request_seconds()
    )


def _placement_seconds() -> float:
    # _wait_for_ssh checks its deadline between a 5s socket attempt and 3s sleep.
    ssh_wait = SSH_WAIT_SECONDS + 8
    return (
        (NEUTRAL_GUARD_CALLS + 2) * ssh_wait
        + 30  # First managed bootstrap host-key scan (subprocess deadline)
        + certs.INSTALL_TIMEOUT_SECONDS
        + NEUTRAL_GUARD_CALLS * account_name_node.NEUTRAL_TIMEOUT_SECONDS
        + NODE_STEP_CALLS * VIRTUALMIN_CALL_SECONDS
        + _acme_exchange_seconds()
    )


class BoundsTests(SimpleTestCase):
    def test_the_ssh_wait_this_file_assumes_is_the_services(self) -> None:
        self.assertEqual(AnsibleService._wait_for_ssh.__defaults__[1], SSH_WAIT_SECONDS)  # type: ignore[index]  # (port, timeout, interval)

    def test_an_attempt_lease_outlives_the_acme_exchange(self) -> None:
        self.assertGreater(certs.ATTEMPT_LEASE.total_seconds(), _acme_exchange_seconds())

    def test_placement_and_certificate_work_fit_their_separate_task_budget(self) -> None:
        self.assertGreater(ACCOUNT_NAME_TASK_TIMEOUT_SECONDS, _placement_seconds())

    def test_placement_also_fits_one_supported_ssh_port_recovery(self) -> None:
        # Actual port 2222 and recorded port 22 recover with a nested hardening playbook.
        # It uses the service default timeout, its own SSH readiness wait, two
        # port+root proofs (3+20 each) and the final pinned idle-root proof (20).
        transport = inspect.signature(AnsibleService).parameters["timeout"].default + SSH_WAIT_SECONDS + 8 + 66
        self.assertGreater(ACCOUNT_NAME_TASK_TIMEOUT_SECONDS, _placement_seconds() + transport)

    def test_an_ordinary_dual_stack_publication_fits_its_own_budget(self) -> None:
        guard = SSH_WAIT_SECONDS + account_name_node.NEUTRAL_TIMEOUT_SECONDS
        # Zone proof, RRset listing, A and AAAA mutations. Large duplicate cleanups
        # remain subject to the task's hard timeout and retry their durable intent.
        self.assertGreater(ACCOUNT_NAME_TASK_TIMEOUT_SECONDS, guard + 4 * _dns_request_seconds())

    def test_an_ordinary_dual_stack_retirement_fits_its_own_budget(self) -> None:
        guard = SSH_WAIT_SECONDS + account_name_node.NEUTRAL_TIMEOUT_SECONDS
        # Owned-record listing/deletes, then one native absence listing and guard retirement.
        self.assertGreater(
            ACCOUNT_NAME_TASK_TIMEOUT_SECONDS, guard + VIRTUALMIN_CALL_SECONDS + 3 * _dns_request_seconds()
        )

    def test_the_node_lease_outlives_the_task_and_the_queue_retries_after_it(self) -> None:
        self.assertGreater(NODE_LEASE.total_seconds(), ACCOUNT_NAME_TASK_TIMEOUT_SECONDS)
        self.assertGreater(settings.Q_CLUSTER["retry"], ACCOUNT_NAME_TASK_TIMEOUT_SECONDS)


class DispatchTests(SimpleTestCase):
    def test_every_account_name_task_is_queued_with_its_own_timeout(self) -> None:
        from unittest.mock import patch  # noqa: PLC0415

        with patch("django_q.tasks.async_task") as enqueue:
            certs._dispatch(certs.INSTALL_TASK, "row-id")

        enqueue.assert_called_once_with(certs.INSTALL_TASK, "row-id", timeout=ACCOUNT_NAME_TASK_TIMEOUT_SECONDS, sync=False)
