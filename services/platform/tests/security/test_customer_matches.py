"""Recent customer matches take priority without changing local ban enforcement."""

from __future__ import annotations

from dataclasses import asdict
from datetime import timedelta
from uuid import uuid4

from django.test import TestCase
from django.utils import timezone

from apps.customers.models import Customer
from apps.security.addresses import address_bounds, pack_address
from apps.security.models import CustomerIPObservation, SecurityDecision, SecuritySource
from apps.users.models import CustomerMembership, User


class SecurityCustomerMatchViewTests(TestCase):
    def setUp(self) -> None:
        self.staff = User.objects.create_user(
            email="customer-match-support@example.test", staff_role="support", is_staff=True
        )
        self.client.force_login(self.staff)
        self.user = User.objects.create_user(email="customer-match@example.test")
        self.customer = Customer.objects.create(name="Qualified customer", customer_type="company", status="active")
        self.membership = CustomerMembership.objects.create(user=self.user, customer=self.customer, role="owner")
        self.source = SecuritySource.objects.create(
            kind="portal",
            transport="local",
            hostname="localhost",
            port=0,
            installation_id=uuid4(),
            configuration_digest="a" * 64,
        )
        self.now = timezone.now()

    def observation(self, address: str, *, age: timedelta = timedelta()) -> CustomerIPObservation:
        family, packed = pack_address(address)
        return CustomerIPObservation.objects.create(
            user=self.user, customer=self.customer, address_family=family, address=packed, last_seen_at=self.now - age
        )

    def decision(self, remote_id: int, address: str, **kwargs: object) -> SecurityDecision:
        scope = "range" if "/" in address else "ip"
        return SecurityDecision.objects.create(
            source=self.source,
            remote_id=remote_id,
            source_created_at=self.now,
            expires_at=self.now + timedelta(minutes=remote_id),
            scenario=f"qualification/customer-match-{remote_id}",
            type="ban",
            scope=scope,
            value=address,
            origin="crowdsec",
            **asdict(address_bounds(scope, address)),
            **kwargs,
        )

    def test_matching_ipv4_cidr_and_ipv6_bans_are_critical_and_sorted_first(self) -> None:
        ordinary = self.decision(1, "198.51.100.30")
        v4 = self.decision(4, "198.51.100.8/30")
        v6 = self.decision(5, "2001:db8:767::9")
        self.observation("198.51.100.9")
        self.observation("2001:db8:767::9")
        response = self.client.get("/security/")
        self.assertContains(response, "CRITICAL")
        self.assertContains(response, "Recent customer IP match")
        self.assertEqual([row.pk for row in response.context["security_page"]], [v4.pk, v6.pk, ordinary.pk])
        self.assertTrue(all(row.ended_at is None for row in SecurityDecision.objects.all()))

    def test_old_observations_and_inactive_memberships_do_not_warn(self) -> None:
        self.decision(1, "198.51.100.8")
        row = self.observation("198.51.100.8", age=timedelta(days=8))
        self.assertNotContains(self.client.get("/security/"), "CRITICAL")
        row.last_seen_at = self.now
        row.save(update_fields=["last_seen_at"])
        self.membership.is_active = False
        self.membership.save(update_fields=["is_active"])
        self.assertNotContains(self.client.get("/security/"), "CRITICAL")

    def test_simulated_and_ended_decisions_do_not_warn(self) -> None:
        self.observation("198.51.100.8")
        self.decision(1, "198.51.100.8", simulated=True)
        ended = self.decision(2, "198.51.100.8")
        ended.ended_at = self.now
        ended.save(update_fields=["ended_at"])
        self.assertNotContains(self.client.get("/security/", {"state": "all"}), "CRITICAL")

    def test_all_active_memberships_and_mapped_host_addresses_match(self) -> None:
        other = Customer.objects.create(name="Second active customer", customer_type="company", status="active")
        CustomerMembership.objects.create(user=self.user, customer=other, role="owner")
        self.membership.is_active = False
        self.membership.save(update_fields=["is_active"])
        family, packed = pack_address("::ffff:198.51.100.8")
        CustomerIPObservation.objects.create(user=self.user, customer=other, address_family=family, address=packed)
        self.decision(1, "198.51.100.8")
        self.assertContains(self.client.get("/security/"), "CRITICAL")
