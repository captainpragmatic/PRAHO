"""The account sync never turns an unknown domain into a service of some customer.

A domain found on a node with no PRAHO account used to be imported as an active service of
``Customer.objects.first()``: a stranger's hosting billed to (and visible to) an arbitrary
customer. Unknown domains are now only reported to staff as unassigned. The sync also saved the
whole account row after the remote usage call, which wrote a stale copy over concurrent changes.
"""

from __future__ import annotations

from typing import Any, cast
from unittest.mock import patch

from django.http import HttpResponse
from django.urls import reverse

from apps.common.types import Ok
from apps.customers.models import Customer
from apps.provisioning.models import Service
from apps.provisioning.virtualmin_models import VirtualminAccount
from tests.provisioning.test_cov_virtualmin_views_servers import VirtualminViewsFixture

SYNC = "provisioning:virtualmin_accounts_sync"


def listing_row(domain: str, username: str) -> dict[str, Any]:
    return {"name": domain, "values": {"Username": [username], "Status": ["Enabled"]}}


class UnknownDomainSyncTests(VirtualminViewsFixture):
    def setUp(self) -> None:
        super().setUp()
        Customer.objects.create(name="Other SRL", primary_email="other@example.com", customer_type="company")

    def test_an_unknown_domain_creates_no_service_and_no_account(self) -> None:
        self.payload["data"] = [listing_row("stranger.example.org", "stranger")]
        services_before = Service.objects.count()
        accounts_before = VirtualminAccount.objects.count()

        response = cast("HttpResponse", self.client.post(reverse(SYNC)))

        self.assertEqual(response.status_code, 302)
        self.assertEqual(Service.objects.count(), services_before)
        self.assertEqual(VirtualminAccount.objects.count(), accounts_before)
        self.assertFalse(Service.objects.filter(username="stranger").exists())
        self.assertFalse(Service.objects.filter(domain="stranger.example.org").exists())

    def test_an_unknown_domain_is_reported_to_staff_as_unassigned(self) -> None:
        self.payload["data"] = [
            listing_row("stranger.example.org", "stranger"),
            listing_row("alias.stranger.example.org", "stranger"),
        ]

        response = cast("HttpResponse", self.client.post(reverse(SYNC)))

        text = self.messages(response)
        self.assertIn("1 unassigned", text)
        self.assertIn("stranger", text)
        self.assertIn("stranger.example.org", text)
        self.assertNotIn("created", text)

    def test_unknown_domains_never_reach_any_customer_when_several_exist(self) -> None:
        self.payload["data"] = [listing_row("a.example.org", "usera"), listing_row("b.example.org", "userb")]

        self.client.post(reverse(SYNC), HTTP_HX_REQUEST="true")

        for customer in Customer.objects.all():
            self.assertEqual(
                Service.objects.filter(customer=customer).exclude(pk=self.service.pk).count(),
                0,
                f"{customer.name} received an imported service",
            )

    def test_a_known_account_is_still_updated(self) -> None:
        self.payload["data"] = [
            listing_row(self.account.domain, self.account.virtualmin_username),
            listing_row("stranger.example.org", "stranger"),
        ]

        response = cast("HttpResponse", self.client.post(reverse(SYNC)))

        self.account.refresh_from_db()
        self.assertIsNotNone(self.account.last_sync_at)
        text = self.messages(response)
        self.assertIn("1 updated", text)
        self.assertIn("1 unassigned", text)


class StaleSaveSyncTests(VirtualminViewsFixture):
    def test_a_change_made_during_the_remote_call_survives_the_sync(self) -> None:
        self.payload["data"] = [listing_row(self.account.domain, self.account.virtualmin_username)]

        def usage_call(_gateway: object, _domain: str) -> Ok[dict[str, int]]:
            # Staff suspend the account while the sync is waiting on Virtualmin.
            VirtualminAccount.objects.filter(pk=self.account.pk).update(status="suspended")
            return Ok({"disk_usage_mb": 5, "bandwidth_usage_mb": 6})

        with patch("apps.provisioning.virtualmin_gateway.VirtualminGateway.get_domain_info", usage_call):
            self.client.post(reverse(SYNC))

        self.account.refresh_from_db()
        self.assertEqual(self.account.status, "suspended")
        self.assertEqual(self.account.current_disk_usage_mb, 5)
        self.assertIsNotNone(self.account.last_sync_at)


class StaffAccountFormDefaultTests(VirtualminViewsFixture):
    def test_a_new_row_is_not_pre_selected_as_active(self) -> None:
        response = self.client.get(reverse("provisioning:virtualmin_account_new"))

        self.assertEqual(response.context["form"].fields["status"].initial, "provisioning")
