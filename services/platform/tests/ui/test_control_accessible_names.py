"""Icon-only controls that had no accessible name have one now (#821).

The audit log's expand chevrons, the services list's suspend and reactivate icons, the settings history drawer's close
glyph and the MFA backup codes' copy icons were hand-written buttons with nothing for a screen reader to say. They are
icon_buttons, which can't render without a name.
"""

from decimal import Decimal

from django.test import TestCase
from django.urls import reverse

from apps.audit.services import AuditService
from apps.billing.models import Currency
from apps.customers.models import Customer
from apps.provisioning.service_models import Service, ServicePlan
from apps.users.models import User
from apps.users.views import _render_backup_codes
from tests.ui.node_harness import Markup


def named(html: str, **match: str) -> list[str]:
    """The aria-label of every button carrying the given attribute values."""
    return [
        attrs.get("aria-label", "")
        for tag, attrs in Markup(html).elements
        if tag == "button" and all(attrs.get(name) == value for name, value in match.items())
    ]


class AccessibleNameTests(TestCase):
    def setUp(self) -> None:
        self.admin = User.objects.create_user(
            email="names-admin@example.com", password="x-pass-123", is_staff=True, staff_role="admin"
        )
        self.client.force_login(self.admin)

    def test_the_audit_log_s_expand_chevrons(self) -> None:
        event = AuditService.log_simple_event("login_success", user=self.admin, description="signed in")
        html = self.client.get(reverse("audit:logs_list")).content.decode()
        self.assertEqual(named(html, **{"data-event-id": str(event.pk)}), ["View Details"])

    def test_the_services_list_s_suspend_and_reactivate_icons(self) -> None:
        customer = Customer.objects.create(name="Named customer", customer_type="company", status="active")
        currency, _created = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei", "decimals": 2})
        plan = ServicePlan.objects.create(
            name="Named plan", plan_type="shared_hosting", price_monthly=Decimal("10.00"), disk_space_gb=1
        )
        for status, name in (("active", "named-active"), ("suspended", "named-suspended")):
            Service.objects.create(
                customer=customer,
                service_plan=plan,
                currency=currency,
                service_name=name,
                domain=f"{name}.example.com",
                username=name.replace("-", ""),
                price=Decimal("10.00"),
                status=status,
            )
        html = self.client.get(reverse("provisioning:services")).content.decode()
        # Each row has a desktop and a mobile control.
        self.assertEqual(
            sorted(named(html, **{"data-action": "confirm-navigate"})), ["Reactivate"] * 2 + ["Suspend"] * 2
        )

    def test_the_settings_history_drawer_s_close_glyph(self) -> None:
        html = self.client.get(
            reverse("settings:setting_history", args=["billing.proforma_validity_days"])
        ).content.decode()
        self.assertEqual(named(html, **{"hx-target": "#history-drawer"}), ["Close"])

    def test_the_backup_codes_copy_icons(self) -> None:
        request = self.client.get(reverse("users:user_profile")).wsgi_request
        html = _render_backup_codes(request, ["ab12cd34", "ef56ab78"]).content.decode()
        self.assertEqual(named(html, **{"data-invoke": "copyCodeAction"}), ["Copy", "Copy"])
        codes = [
            attrs.get("data-code")
            for tag, attrs in Markup(html).elements
            if attrs.get("data-invoke") == "copyCodeAction"
        ]
        self.assertEqual(codes, ["ab12cd34", "ef56ab78"])
