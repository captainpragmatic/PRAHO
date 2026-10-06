"""The reconciler is the single writer of a hosting account's enabled state (#566, ADR-0051).

Hosting is enabled exactly when the Service is active and no domain bound to it is in
`Domain.HOSTING_DISABLING_STATUSES`. Before this change two writers decided it: the domain
status sync called Virtualmin directly, and the reconciler converged on `Service.status`
alone and could only veto, never suspend. Now a domain change only queues a reconcile, and
the reconciler applies the predicate in both directions.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

from django.utils import timezone

from apps.domains.models import Domain
from apps.provisioning.models import Service
from apps.provisioning.virtualmin_models import VirtualminAccount
from apps.provisioning.virtualmin_tasks import reconcile_divergent_services_task, retry_virtualmin_job
from tests.mocks.virtualmin_mock import MockVirtualminGateway
from tests.provisioning.test_virtualmin_domain_veto import _DomainVetoBase

ENQUEUE = "apps.provisioning.virtualmin_tasks.reconcile_virtualmin_service_state_async"
GATEWAY = "apps.provisioning.virtualmin_service.VirtualminGateway"


class _SingleWriterBase(_DomainVetoBase):
    def setUp(self) -> None:
        super().setUp()
        self.account.status = "active"
        self.account.save(update_fields=["status"])

    def _gateway(self, *, enabled: bool) -> MockVirtualminGateway:
        gateway = MockVirtualminGateway()
        gateway.seed_domain(self.account.domain, enabled=enabled)
        return gateway


class ReconcilerAppliesTheDomainHoldTests(_SingleWriterBase):
    def test_an_expired_bound_domain_suspends_an_active_account(self) -> None:
        """FAILS on master: the reconciler never suspended for domain reasons."""
        self._domain("expired", service=self.service)
        gateway = self._gateway(enabled=True)

        result = self._reconcile(gateway)

        self.assertEqual(result["action"], "domain_suspended")
        self.assertEqual(len(gateway.get_calls("disable-domain")), 1)
        self.account.refresh_from_db()
        self.assertEqual(self.account.status, "suspended")
        self.assertEqual(self.account.status_message, "domain_expired")

    def test_a_pending_or_transferring_domain_leaves_hosting_on(self) -> None:
        """Guard: only expired, suspended and cancelled hold hosting off (ADR-0051 item 3)."""
        for status in ("pending", "transfer_in", "transfer_out"):
            with self.subTest(status=status):
                domain = self._domain(status, service=self.service)
                gateway = self._gateway(enabled=True)

                self.assertEqual(self._reconcile(gateway)["action"], "noop")
                self.assertEqual(gateway.get_calls("disable-domain"), [])
                domain.delete()

    def test_a_reactivated_domain_lets_the_account_back_on(self) -> None:
        """Guard: the hold lifts when the domain is active again."""
        self.account.status = "suspended"
        self.account.save(update_fields=["status"])
        self._domain("active", service=self.service)

        self.assertEqual(self._reconcile(self._gateway(enabled=False))["action"], "unsuspended")

    def test_a_domain_that_expires_during_an_unsuspend_queues_another_reconcile(self) -> None:
        """FAILS on master: the follow-up only watched Service.status, so the race stuck."""
        self.account.status = "suspended"
        self.account.save(update_fields=["status"])
        domain = self._domain("active", service=self.service)
        gateway = self._gateway(enabled=False)
        real_call = gateway.call

        def expire_mid_flight(program: str, params: dict[str, Any], **kwargs: Any) -> Any:
            if program == "enable-domain":
                Domain.objects.filter(pk=domain.pk).update(status="expired")
            return real_call(program, params, **kwargs)

        with patch.object(gateway, "call", side_effect=expire_mid_flight), patch(ENQUEUE) as enqueue:
            self.assertEqual(self._reconcile(gateway)["action"], "unsuspended")

        enqueue.assert_called_once_with(str(self.service.id))


class DomainChangeOnlyQueuesAReconcileTests(_SingleWriterBase):
    def test_a_domain_status_change_calls_no_gateway_and_queues_each_bound_service(self) -> None:
        """FAILS on master: the domain sync called disable-domain itself."""
        domain = self._domain("active", service=self.service)
        gateway = self._gateway(enabled=True)

        with (
            patch(GATEWAY, return_value=gateway),
            patch(ENQUEUE) as enqueue,
            self.captureOnCommitCallbacks(execute=True),
        ):
            domain.expire()
            domain.save()

        self.assertEqual(gateway.get_calls(), [])
        enqueue.assert_called_once_with(str(self.service.id))


class DivergenceSweepFindsDomainHeldAccountsTests(_SingleWriterBase):
    def test_an_active_account_under_a_name_matched_hold_is_queued(self) -> None:
        """FAILS on master: the sweep had no signature for "should be off but is on"."""
        self._domain("expired", service=self.service)
        addon_service = Service.objects.create(
            customer=self.customer,
            service_plan=self.plan,
            currency=self.currency,
            service_name="addon.example.com",
            domain="addon.example.com",
            username="addon",
            billing_cycle="monthly",
            price=self.service.price,
            status="active",
        )
        VirtualminAccount.objects.create(
            domain="addon.example.com",
            service=addon_service,
            server=self.server,
            virtualmin_username="addon",
            status="active",
        )
        # Bound, expired, but not the account's own domain: the reconciler would ignore it,
        # so the sweep must not keep queueing it either.
        self._domain("expired", name="other-addon.example.org", service=addon_service)

        with patch(ENQUEUE) as enqueue:
            reconcile_divergent_services_task()

        queued = {call.args[0] for call in enqueue.call_args_list}
        self.assertIn(str(self.service.id), queued)
        self.assertNotIn(str(addon_service.id), queued)


class SuspendRetryUnderADomainHoldTests(_SingleWriterBase):
    def test_a_failed_domain_suspend_is_retried_not_superseded(self) -> None:
        """FAILS on master: the retry saw an active Service and discarded the suspend."""
        self._domain("expired", service=self.service)
        job = self._failed_job(operation="suspend_domain", status="pending", retry_count=1, claimed_at=timezone.now())
        gateway = self._gateway(enabled=True)

        with patch(GATEWAY, return_value=gateway), patch(ENQUEUE) as enqueue:
            result = retry_virtualmin_job(str(job.id))

        self.assertTrue(result["success"], result)
        self.assertEqual(len(gateway.get_calls("disable-domain")), 1)
        self.account.refresh_from_db()
        self.assertEqual(self.account.status, "suspended")
        enqueue.assert_not_called()
