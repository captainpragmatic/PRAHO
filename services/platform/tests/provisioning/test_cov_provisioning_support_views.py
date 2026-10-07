"""Coverage additions for service management through the real URL configuration."""

from __future__ import annotations

from decimal import Decimal

from django.test import override_settings
from django.urls import reverse

from apps.billing.currency_policy import get_selling_currency_policy
from apps.customers.models import Customer
from apps.provisioning.models import Service, ServicePlanPrice
from tests.factories.core_factories import create_staff_user, create_user
from tests.provisioning.test_virtualmin_tasks import VirtualminTaskTestBase


@override_settings(LANGUAGE_CODE="en")
class ProvisioningServicePageTests(VirtualminTaskTestBase):
    def setUp(self) -> None:
        super().setUp()
        self.staff = create_staff_user("support-coverage")
        self.client.force_login(self.staff)
        self.price, _ = ServicePlanPrice.objects.update_or_create(
            service_plan=self.plan, currency=self.currency, defaults={"monthly_price_cents": 2345}
        )

    def create_data(self, domain: str = "newtenant.example.com") -> dict[str, str]:
        policy = get_selling_currency_policy()
        return {
            "customer_id": str(self.customer.pk),
            "plan_id": str(self.plan.pk),
            "domain": domain,
            "currency": policy.currency_code,
            "currency_revision": str(policy.revision),
        }

    def test_list_customer_and_status_filters_render_matching_rows(self) -> None:
        other = Customer.objects.create(name="Other support tenant", primary_email="other-support@example.com")
        foreign = Service.objects.create(
            customer=other,
            service_plan=self.plan,
            currency=self.currency,
            service_name="Foreign support hosting",
            domain="foreign.example.com",
            username="foreign-support",
            price=Decimal("23.45"),
            status="pending",
        )
        response = self.client.get(reverse("provisioning:services"), {"customer": str(other.pk), "status": "pending"})
        self.assertContains(response, foreign.service_name)
        self.assertNotContains(response, self.service.service_name)
        self.assertEqual(list(response.context["services"]), [foreign])
        self.assertEqual(response.context["active_count"], 1)
        self.assertEqual(response.context["total_count"], 1)
        self.assertEqual(response.context["display_status"], "pending")
        empty = self.client.get(reverse("provisioning:services"), {"customer": str(other.pk), "status": "active"})
        self.assertEqual(list(empty.context["services"]), [])
        self.assertEqual(empty.context["active_count"], 0)
        self.assertEqual(empty.context["total_count"], 1)

    def test_edit_get_and_post_persist_domain_change(self) -> None:
        url = reverse("provisioning:service_edit", args=[self.service.pk])
        self.assertContains(self.client.get(url), self.service.domain)
        response = self.client.post(url, self.create_data("renamed.example.com"), follow=True)
        self.assertContains(response, "renamed.example.com")
        self.assertEqual(Service.objects.get(pk=self.service.pk).domain, "renamed.example.com")
        self.assertEqual(response.context["service"].pk, self.service.pk)

    def test_edit_missing_fields_renders_error_and_preserves_service(self) -> None:
        response = self.client.post(reverse("provisioning:service_edit", args=[self.service.pk]), {"domain": ""})
        self.assertContains(response, "All fields are required.")
        self.assertEqual(Service.objects.get(pk=self.service.pk).domain, self.service.domain)
        self.assertTrue(response.context["is_edit"])

    def test_missing_service_customer_and_plan_return_404_without_creating_rows(self) -> None:
        count = Service.objects.count()
        missing = max(Service.objects.values_list("pk", flat=True)) + 1
        for name in ("service_detail", "service_edit", "service_suspend", "service_activate"):
            with self.subTest(view=name):
                response = self.client.get(reverse(f"provisioning:{name}", args=[missing]))
                self.assertContains(response, "Not Found", status_code=404)
        for field, value in (
            ("customer_id", str(self.customer.pk + 10000)),
            ("plan_id", str(self.plan.pk + 10000)),
        ):
            data = self.create_data()
            data[field] = value
            with self.subTest(field=field):
                response = self.client.post(reverse("provisioning:service_create"), data)
                self.assertContains(response, "Not Found", status_code=404)
        self.assertEqual(Service.objects.count(), count)

    def test_nonstaff_cannot_manage_services_and_cannot_read_another_customer_service(self) -> None:
        self.client.force_login(create_user())
        for name, args in (
            ("service_create", []),
            ("service_edit", [self.service.pk]),
            ("service_suspend", [self.service.pk]),
            ("service_activate", [self.service.pk]),
        ):
            with self.subTest(view=name):
                response = self.client.post(reverse(f"provisioning:{name}", args=args), self.create_data())
                self.assertContains(response, "Staff privileges required", status_code=403)
        response = self.client.get(reverse("provisioning:service_detail", args=[self.service.pk]), follow=True)
        self.assertContains(response, "You do not have permission to access this service.")
        self.assertNotContains(response, self.service.domain)
        self.assertEqual(Service.objects.get(pk=self.service.pk).status, "active")

    def test_suspend_and_activate_persist_lifecycle_fields_and_render_messages(self) -> None:
        suspend = reverse("provisioning:service_suspend", args=[self.service.pk])
        self.assertContains(self.client.get(suspend), self.service.domain)
        response = self.client.post(suspend, {"reason": "Coverage suspension"}, follow=True)
        self.assertContains(response, "has been suspended")
        saved = Service.objects.get(pk=self.service.pk)
        self.assertEqual(saved.status, "suspended")
        self.assertEqual(saved.suspension_reason, "Coverage suspension")
        self.assertIsNotNone(saved.suspended_at)
        activate = reverse("provisioning:service_activate", args=[self.service.pk])
        self.assertContains(self.client.get(activate), self.service.domain)
        response = self.client.post(activate, follow=True)
        self.assertContains(response, "has been activated")
        saved = Service.objects.get(pk=self.service.pk)
        self.assertEqual(saved.status, "active")
        self.assertEqual(saved.suspension_reason, "")
        self.assertIsNone(saved.suspended_at)
        self.assertIsNotNone(saved.activated_at)

    def test_invalid_transitions_preserve_status_and_render_failure(self) -> None:
        response = self.client.post(reverse("provisioning:service_activate", args=[self.service.pk]), follow=True)
        self.assertContains(response, "cannot be activated from status")
        self.assertEqual(Service.objects.get(pk=self.service.pk).status, "active")
        self.service.suspend("Already suspended")
        self.service.save(update_fields=["status", "suspended_at", "suspension_reason"])
        response = self.client.post(
            reverse("provisioning:service_suspend", args=[self.service.pk]), {"reason": "Replacement"}, follow=True
        )
        self.assertContains(response, "cannot be suspended from status")
        saved = Service.objects.get(pk=self.service.pk)
        self.assertEqual(saved.status, "suspended")
        self.assertEqual(saved.suspension_reason, "Already suspended")

    def test_create_resolves_username_collision_and_persists_retail_price(self) -> None:
        domain = "collision.example.com"
        base = f"srv_{self.customer.pk}_collision_example_com"
        self.service.username = base
        self.service.save(update_fields=["username"])
        response = self.client.post(reverse("provisioning:service_create"), self.create_data(domain), follow=True)
        self.assertContains(response, "has been created")
        saved = Service.objects.get(domain=domain)
        self.assertEqual(saved.username, f"{base}_1")
        self.assertEqual(saved.price, Decimal("23.45"))
        self.assertEqual(saved.currency_id, "RON")
        self.assertEqual(saved.status, "pending")
        self.assertEqual(response.context["service"].pk, saved.pk)

    def test_create_refuses_missing_fields_stale_currency_and_unpriced_plan(self) -> None:
        before = Service.objects.count()
        missing = self.client.post(reverse("provisioning:service_create"), {"domain": ""})
        self.assertContains(missing, "All fields are required.")
        data = self.create_data()
        data["currency_revision"] = "invalid"
        stale = self.client.post(reverse("provisioning:service_create"), data)
        self.assertContains(stale, "Prices have changed.", status_code=409)
        self.price.is_active = False
        self.price.save(update_fields=["is_active"])
        unpriced = self.client.post(reverse("provisioning:service_create"), self.create_data())
        self.assertContains(unpriced, "This plan has no current price.", status_code=400)
        self.assertEqual(Service.objects.count(), before)
