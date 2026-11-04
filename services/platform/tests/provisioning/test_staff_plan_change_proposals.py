"""Staff can share the real customer checkout without accepting terms or taking money."""

from urllib.parse import parse_qs, urlsplit

from django.test import TransactionTestCase
from django.urls import reverse

from apps.billing.models import Payment
from apps.billing.plan_change_models import PlanChange
from apps.customers.models import Customer
from apps.provisioning.hosting_limit_models import ServiceHostingLimits
from apps.settings.services import SettingsService
from apps.users.models import User
from tests.helpers.plan_change_checkout import VerifiedPlanChangeCheckoutFixture


class StaffPlanChangeProposalTests(VerifiedPlanChangeCheckoutFixture, TransactionTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.staff = User.objects.create_user(email="plan-proposal-staff@example.test", staff_role="billing")
        self.path = reverse("provisioning:service_detail", args=[self.service.pk]) + "plan-change/"
        self.assertTrue(SettingsService.update_setting("portal.public_base_url", "https://portal.example.test").is_ok())

    def test_billing_staff_shares_a_live_customer_checkout_link_without_financial_or_resource_mutations(self) -> None:
        self.client.force_login(self.staff)
        before = (
            PlanChange.objects.count(),
            Payment.objects.count(),
            ServiceHostingLimits.objects.get(service=self.service).revision,
        )
        response = self.client.get(self.path)
        self.assertEqual(response.status_code, 200, response.content)
        option = next(row for row in response.context["options"] if row["product_id"] == str(self.target.pk))
        self.assertEqual((option["net_cents"], option["tax_cents"], option["total_cents"]), (20000, 4200, 24200))
        link = urlsplit(option["proposal_url"])
        self.assertEqual((link.scheme, link.netloc, link.path), ("https", "portal.example.test", "/login/"))
        target = parse_qs(link.query)["next"][0]
        self.assertIn(f"/services/{self.service.pk}/change-plan/", target)
        self.assertIn(str(self.target.pk), target)
        self.assertNotIn("user_id", target)
        self.assertEqual(
            (
                PlanChange.objects.count(),
                Payment.objects.count(),
                ServiceHostingLimits.objects.get(service=self.service).revision,
            ),
            before,
        )
        self.assertContains(response, "The customer reviews and accepts the final quote in Portal.")
        self.assertEqual(self.client.post(self.path, {"target_product_id": str(self.target.pk)}).status_code, 405)

    def test_support_role_cannot_prepare_financial_plan_links(self) -> None:
        self.staff.staff_role = "support"
        self.staff.save(update_fields=["staff_role"])
        self.client.force_login(self.staff)
        response = self.client.get(self.path)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(PlanChange.objects.count(), 0)

    def test_public_owner_transfer_does_not_offer_the_previous_customers_checkout(self) -> None:
        change = self.quote()
        other = Customer.objects.create(name="Current proposal customer", status="active")
        admin = User.objects.create_user(email="proposal-transfer-admin@example.test", staff_role="admin")
        self.client.force_login(admin)
        transferred = self.client.post(
            reverse("provisioning:service_edit", args=[self.service.pk]),
            {"customer_id": other.pk, "domain": self.service.domain},
        )
        self.assertEqual(transferred.status_code, 302, transferred.content)
        self.service.refresh_from_db()
        self.assertEqual(self.service.customer_id, other.pk)
        self.client.force_login(self.staff)
        response = self.client.get(self.path)
        self.assertEqual(response.status_code, 200, response.content)
        self.assertIsNone(response.context["current_change"])
        self.assertNotContains(response, str(change.pk))
