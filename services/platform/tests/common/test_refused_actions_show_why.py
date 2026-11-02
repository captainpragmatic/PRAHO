"""A control the view would refuse is shown disabled with the reason, using the view's own rule.

- Proforma Send showed to anyone who can open the proforma; proforma_send is billing-staff only and redirected
  everyone else to the dashboard, so the page's script got HTML instead of JSON and showed a generic error.
  Page and view now share User.can_manage_financial_data (billing_staff_required delegates to it).
- Region Enable/Disable showed to all staff; region_toggle needs can_manage_regions (a superuser or the explicit
  permission), so others got a 403 and a generic alert.
"""

from __future__ import annotations

from datetime import timedelta

from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from apps.billing.models import Currency, ProformaInvoice
from apps.customers.models import Customer
from apps.infrastructure.models import CloudProvider, NodeRegion
from apps.infrastructure.permissions import can_manage_regions
from apps.users.models import User
from tests.ui.node_harness import Markup


def controls(html: str, attribute: str, value: str) -> list[dict[str, str]]:
    return [attrs for tag, attrs in Markup(html).elements if tag in ("a", "button") and attrs.get(attribute) == value]


class ProformaSendGateTests(TestCase):
    REASON = "Only billing staff can send proformas."

    def setUp(self) -> None:
        currency, _ = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei"})
        customer = Customer.objects.create(name="Send gate", primary_email="send-gate@example.test")
        self.proforma = ProformaInvoice.objects.create(
            customer=customer, currency=currency, number="SEND-GATE-1", valid_until=timezone.now() + timedelta(days=7)
        )

    def page(self, role: str) -> str:
        user = User.objects.create_user(email=f"send-gate-{role}@example.test", is_staff=True, staff_role=role)
        self.client.force_login(user)
        return self.client.get(reverse("billing:proforma_detail", args=[self.proforma.pk])).content.decode()

    def test_support_sees_send_disabled_with_why_and_the_view_agrees(self) -> None:
        html = self.page("support")
        self.assertEqual(controls(html, "data-invoke", "sendProformaAction"), [])
        self.assertIn(self.REASON, html)
        refused = self.client.post(reverse("billing:proforma_send", args=[self.proforma.pk]))
        self.assertEqual(refused.status_code, 302)  # billing_staff_required sends them to the dashboard

    def test_billing_staff_can_send(self) -> None:
        html = self.page("billing")
        self.assertEqual(len(controls(html, "data-invoke", "sendProformaAction")), 1)
        self.assertNotIn(self.REASON, html)


class RegionToggleGateTests(TestCase):
    REASON = "Only region managers can enable or disable regions."

    def setUp(self) -> None:
        provider = CloudProvider.objects.create(
            name="Gate Cloud", provider_type="hetzner", code="gat", credential_identifier="c"
        )
        self.region = NodeRegion.objects.create(
            provider=provider,
            name="Gate Zone",
            provider_region_id="gz1",
            normalized_code="gz1",
            country_code="de",
            city="X",
        )

    def page(self, user: User) -> str:
        self.client.force_login(user)
        return self.client.get(reverse("infrastructure:region_list")).content.decode()

    def test_staff_without_the_permission_see_the_toggle_disabled_with_why(self) -> None:
        staff = User.objects.create_user(email="region-staff@example.test", is_staff=True, staff_role="admin")
        self.assertFalse(can_manage_regions(staff))
        html = self.page(staff)
        submits = [
            a
            for t, a in Markup(html).elements
            if t == "button" and a.get("type") == "submit" and "ui-btn" in a.get("class", "") and "disabled" not in a
        ]
        self.assertEqual(submits, [])
        self.assertIn(self.REASON, html)

    def test_a_region_manager_gets_a_working_toggle(self) -> None:
        html = self.page(User.objects.create_superuser(email="region-root@example.test", password="pw"))
        submits = [
            a
            for t, a in Markup(html).elements
            if t == "button" and a.get("type") == "submit" and "ui-btn" in a.get("class", "") and "disabled" not in a
        ]
        self.assertEqual(len(submits), 1)
        self.assertNotIn(self.REASON, html)
