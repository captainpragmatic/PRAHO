"""H6: services_list must keep service_name XSS-safe.

#284 moved the suspend/reactivate controls from inline onclick handlers (a JS
string context that required |escapejs) to delegated data-action buttons that
carry service_name in a data-* attribute (an HTML attribute context, where
Django's default autoescape is the correct — and sufficient — protection, and
|escapejs would be WRONG). This guards the new contract: no JS-context sink for
service_name survives, and the data-* sink stays autoescaped.
"""

import re
from decimal import Decimal
from pathlib import Path

from django.test import SimpleTestCase, TestCase
from django.urls import reverse

from apps.billing.models import Currency
from apps.customers.models import Customer
from apps.provisioning.service_models import Service, ServicePlan
from apps.users.models import User
from tests.ui.node_harness import Markup

_TEMPLATE = Path(__file__).resolve().parents[2] / "templates/provisioning/partials/services_list.html"


class ServicesListXSSTests(SimpleTestCase):
    def test_no_service_name_in_js_onclick_context(self) -> None:
        """The old JS-injection surface (service_name inside onclick) must be gone."""
        content = _TEMPLATE.read_text()
        onclick_matches = re.findall(
            r"onclick=\"[^\"]*\{\{[^}]*service\.service_name[^}]*\}\}[^\"]*\"",
            content,
        )
        self.assertEqual(
            onclick_matches,
            [],
            f"service_name must not appear in an onclick JS context: {onclick_matches}",
        )


class ServicesListConfirmationRenderingTests(TestCase):
    """The confirmation that names the service reaches the browser as written, and can't add an attribute (#821).

    The view builds the suspend/reactivate data-confirm (prompt plus service name) into the button's attrs mapping,
    which the button component escapes.
    """

    HOSTILE = 'x" onmouseover="evil()" data-href="/evil/" <b>bold</b>'

    def test_a_hostile_service_name_is_decoded_text_and_injects_nothing(self) -> None:
        admin = User.objects.create_user(email="sink-admin@example.com", password="x-pass-123", staff_role="admin")
        self.client.force_login(admin)
        customer = Customer.objects.create(name="Sink customer", customer_type="company", status="active")
        currency, _created = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei", "decimals": 2})
        plan = ServicePlan.objects.create(
            name="Sink plan", plan_type="shared_hosting", price_monthly=Decimal("10.00"), disk_space_gb=1
        )
        service = Service.objects.create(
            customer=customer,
            service_plan=plan,
            currency=currency,
            service_name=self.HOSTILE,
            domain="sink.example.com",
            username="sink",
            price=Decimal("10.00"),
            status="active",
        )
        page = Markup(self.client.get(reverse("provisioning:services")).content.decode())
        controls = [attrs for tag, attrs in page.elements if attrs.get("data-action") == "confirm-navigate"]
        self.assertEqual(len(controls), 2)  # desktop row and mobile card
        for attrs in controls:
            self.assertEqual(attrs["data-confirm"], "Suspend service? " + self.HOSTILE)
            self.assertEqual(attrs["data-href"], reverse("provisioning:service_suspend", args=[service.pk]))
            self.assertNotIn("onmouseover", attrs)
        self.assertNotIn("b", [tag for tag, _attrs in page.elements])
