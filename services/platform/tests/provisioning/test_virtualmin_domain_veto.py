"""A bound domain's hold on hosting is never reversed by a Service-only path (#566).

``reconcile_virtualmin_service_state`` used to converge on ``Service.status`` alone, so an
account disabled for an expired domain was re-enabled on the next reconcile, by the
15-minute divergence sweep, or by a retried unsuspend job. Under ADR-0051 the reconciler
is the single writer and applies the domain hold in both directions: it keeps a held
account off, and it now also suspends an active account for it.
"""

from __future__ import annotations

import uuid
from decimal import Decimal
from unittest.mock import patch

from django.utils import timezone

from apps.domains.models import TLD, Domain, Registrar
from apps.provisioning.models import Service
from apps.provisioning.relationship_models import ServiceDomain
from apps.provisioning.virtualmin_models import VirtualminAccount
from apps.provisioning.virtualmin_tasks import (
    reconcile_divergent_services_task,
    reconcile_virtualmin_service_state,
    retry_virtualmin_job,
)
from tests.mocks.virtualmin_mock import MockVirtualminGateway
from tests.provisioning.test_virtualmin_tasks import VirtualminTaskTestBase


class _DomainVetoBase(VirtualminTaskTestBase):
    def setUp(self) -> None:
        super().setUp()
        self.account.status = "suspended"
        self.account.save(update_fields=["status"])
        tld = TLD.objects.create(
            extension="com",
            description=".com",
            registration_price_cents=5000,
            renewal_price_cents=5000,
            transfer_price_cents=5000,
            min_registration_period=1,
            max_registration_period=10,
            is_active=True,
        )
        self.tld = tld
        self.registrar = Registrar.objects.create(
            name="veto-registrar", display_name="Veto Registrar", website_url="https://example.test", status="active"
        )

    def _domain(self, status: str, *, name: str = "test.example.com", service: Service | None = None) -> Domain:
        domain = Domain.objects.create(
            name=name, tld=self.tld, registrar=self.registrar, customer=self.customer, status=status
        )
        if service is not None:
            ServiceDomain.objects.create(service=service, domain=domain)
        return domain

    def _reconcile(self, gateway: MockVirtualminGateway) -> dict[str, object]:
        with patch("apps.provisioning.virtualmin_service.VirtualminGateway", return_value=gateway):
            return reconcile_virtualmin_service_state(str(self.service.id))


class ReconcilerDomainVetoTests(_DomainVetoBase):
    def test_bound_disabling_domain_keeps_account_suspended(self) -> None:
        for status in sorted(Domain.HOSTING_DISABLING_STATUSES):
            with self.subTest(status=status):
                domain = self._domain(status, service=self.service)
                gateway = MockVirtualminGateway()
                gateway.seed_domain(self.account.domain, enabled=False)

                result = self._reconcile(gateway)

                self.assertEqual(result["action"], "domain_disabled")
                self.assertEqual(gateway.get_calls("enable-domain"), [])
                self.account.refresh_from_db()
                self.assertEqual(self.account.status, "suspended")
                domain.delete()

    def test_non_disabling_domain_statuses_still_unsuspend(self) -> None:
        # Narrower than the domain path's "not active" on purpose: a pending or in-transfer
        # domain must not hold hosting off for a reactivated service.
        for status in ("pending", "transfer_in", "transfer_out", "active"):
            with self.subTest(status=status):
                domain = self._domain(status, service=self.service)
                gateway = MockVirtualminGateway()
                gateway.seed_domain(self.account.domain, enabled=False)

                result = self._reconcile(gateway)

                self.assertEqual(result["action"], "unsuspended")
                self.account.status = "suspended"
                self.account.save(update_fields=["status"])
                domain.delete()

    def test_unbound_same_name_domain_does_not_block(self) -> None:
        # The domain path only reaches accounts of services the domain is bound to.
        self._domain("expired")
        gateway = MockVirtualminGateway()
        gateway.seed_domain(self.account.domain, enabled=False)

        self.assertEqual(self._reconcile(gateway)["action"], "unsuspended")

    def test_active_account_with_disabling_domain_is_suspended(self) -> None:
        # ADR-0051 settled it: the reconciler is the one writer, so it suspends for the domain.
        self.account.status = "active"
        self.account.save(update_fields=["status"])
        self._domain("expired", service=self.service)
        gateway = MockVirtualminGateway()
        gateway.seed_domain(self.account.domain)

        self.assertEqual(self._reconcile(gateway)["action"], "domain_suspended")
        self.assertEqual(len(gateway.get_calls("disable-domain")), 1)


class UnsuspendRetryDomainVetoTests(_DomainVetoBase):
    def test_unsuspend_retry_is_terminalized_when_domain_disables_hosting(self) -> None:
        self._domain("expired", service=self.service)
        job = self._failed_job(operation="unsuspend_domain", status="pending", retry_count=1, claimed_at=timezone.now())
        gateway = MockVirtualminGateway()
        gateway.seed_domain(self.account.domain, enabled=False)

        with patch("apps.provisioning.virtualmin_service.VirtualminGateway", return_value=gateway):
            result = retry_virtualmin_job(str(job.id))

        self.assertFalse(result["success"])
        self.assertEqual(gateway.get_calls("enable-domain"), [])
        job.refresh_from_db()
        self.assertIsNone(job.next_retry_at)
        self.account.refresh_from_db()
        self.assertEqual(self.account.status, "suspended")


class DivergenceSweepDomainVetoTests(_DomainVetoBase):
    def _blocked_service(self, index: int) -> Service:
        name = f"blocked{index}.example.com"
        service = Service.objects.create(
            customer=self.customer,
            service_plan=self.plan,
            currency=self.currency,
            service_name=name,
            domain=name,
            username=f"blocked{index}",
            billing_cycle="monthly",
            price=Decimal("10.00"),
            status="active",
        )
        VirtualminAccount.objects.create(
            id=uuid.UUID(int=index + 1),  # sorts ahead of the eligible account below
            domain=name,
            service=service,
            server=self.server,
            virtualmin_username=f"blocked{index}",
            status="suspended",
        )
        self._domain("expired", name=name, service=service)
        return service

    def test_domain_blocked_accounts_are_filtered_before_the_cap(self) -> None:
        blocked = [self._blocked_service(i) for i in range(50)]
        VirtualminAccount.objects.filter(pk=self.account.pk).update(id=uuid.UUID(int=10**6))

        with patch(
            "apps.provisioning.virtualmin_tasks.reconcile_virtualmin_service_state_async", return_value="t-1"
        ) as queue:
            reconcile_divergent_services_task()

        queued = {call.args[0] for call in queue.call_args_list}
        self.assertIn(str(self.service.id), queued)
        self.assertFalse(queued & {str(service.id) for service in blocked})
