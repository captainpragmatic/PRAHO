"""Coverage additions for signed, tenant-scoped ticket searches."""

from __future__ import annotations

from typing import TypedDict, cast

from django.test import TestCase, override_settings

from apps.customers.models import Customer
from apps.tickets.models import Ticket
from apps.users.models import CustomerMembership, User
from tests.helpers.hmac import HMAC_TEST_MIDDLEWARE, HMAC_TEST_SECRET, HMACTestMixin


class _TicketIdentity(TypedDict):
    id: int


class _SearchData(TypedDict):
    tickets: list[_TicketIdentity]
    pagination: dict[str, int]


class _SearchResponse(TypedDict):
    success: bool
    data: _SearchData


@override_settings(PLATFORM_API_SECRET=HMAC_TEST_SECRET, MIDDLEWARE=HMAC_TEST_MIDDLEWARE, LANGUAGE_CODE="en")
class CustomerTicketSearchTests(HMACTestMixin, TestCase):
    def setUp(self) -> None:
        self.owner = User.objects.create_user(email="search-owner@example.com")
        self.customer = Customer.objects.create(
            name="Search Customer", customer_type="company", status="active", primary_email=self.owner.email
        )
        CustomerMembership.objects.create(user=self.owner, customer=self.customer, role="owner", is_active=True)
        other_owner = User.objects.create_user(email="search-other@example.com")
        self.other_customer = Customer.objects.create(
            name="Other Customer", customer_type="company", status="active", primary_email=other_owner.email
        )
        CustomerMembership.objects.create(user=other_owner, customer=self.other_customer, role="owner", is_active=True)
        self.matches: dict[str, int] = {}
        self.foreign_ids: set[int] = set()
        for customer, owner, suffix in (
            (self.customer, self.owner, "OWN"),
            (self.other_customer, other_owner, "OTHER"),
        ):
            for query, title, description, number in (
                ("title-needle", "TITLE-NEEDLE request", "Ordinary details", f"TK-TITLE-{suffix}"),
                ("body-needle", "Ordinary request", "BODY-NEEDLE details", f"TK-BODY-{suffix}"),
                ("number-needle", "Ordinary request", "Ordinary details", f"NUMBER-NEEDLE-{suffix}"),
            ):
                ticket = Ticket.objects.create(
                    customer=customer,
                    created_by=owner,
                    title=title,
                    description=description,
                    ticket_number=number,
                    status="open",
                )
                if customer == self.customer:
                    self.matches[query] = ticket.pk
                else:
                    self.foreign_ids.add(ticket.pk)
        Ticket.objects.create(customer=self.customer, title="Unrelated", description="Unrelated", status="open")

    def test_search_matches_title_description_and_number_without_foreign_tickets(self) -> None:
        for query, expected_id in self.matches.items():
            with self.subTest(query=query):
                response = self.portal_post(
                    "/api/tickets/",
                    {
                        "customer_id": self.customer.pk,
                        "user_id": self.owner.pk,
                        "action": "get_tickets",
                        "search": query,
                        "page": 1,
                        "limit": 20,
                    },
                )
                self.assertEqual(response.status_code, 200, response.content)
                payload = cast(_SearchResponse, response.json())
                self.assertTrue(payload["success"])
                ticket_ids = [ticket["id"] for ticket in payload["data"]["tickets"]]
                self.assertEqual(ticket_ids, [expected_id])
                self.assertEqual(payload["data"]["pagination"]["total"], 1)
                self.assertTrue(self.foreign_ids.isdisjoint(ticket_ids))
