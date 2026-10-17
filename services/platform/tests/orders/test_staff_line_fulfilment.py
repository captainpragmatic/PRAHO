"""Staff finish the lines PRAHO does not provision itself, and the stuck ones, from the order page."""

from __future__ import annotations

from django.urls import reverse

from apps.audit.models import AuditEvent
from apps.orders.hosting_fulfilment import complete_line_for_staff, fulfil_hosting_line
from apps.orders.models import OrderItem
from apps.provisioning.models import Service
from apps.users.models import User

from .test_hosting_fulfilment import HostingLineCase


class StaffLineFulfilmentTests(HostingLineCase):
    plan_type = "ssl"

    def setUp(self) -> None:
        super().setUp()
        fulfil_hosting_line(self.line.pk)  # an SSL line: started, then left for staff
        self.url = reverse("orders:order_item_fulfil", kwargs={"pk": self.order.pk, "item_pk": self.line.pk})

    def _staff(self, role: str) -> User:
        return User.objects.create_user(email=f"{role}-fulfil@example.test", is_staff=True, staff_role=role)

    def test_staff_marks_in_progress_hosting_line_fulfilled(self) -> None:
        for role in ("admin", "manager"):
            with self.subTest(role=role):
                OrderItem.objects.filter(pk=self.line.pk).update(provisioning_status="in_progress")
                Service.objects.filter(pk=self.service.pk).update(status="provisioning")
                self.order.__class__.objects.filter(pk=self.order.pk).update(status="provisioning")
                self.client.force_login(self._staff(role))
                response = self.client.post(self.url, {"activate_service": "on"}, HTTP_HX_REQUEST="true")
                self.assertEqual(response.status_code, 200, response.content)
                self._reload()
                self.assertEqual((self.line.provisioning_status, self.service.status), ("completed", "active"))
                self.assertEqual(self.order.status, "completed")  # its only line is done
        events = AuditEvent.objects.filter(action="order_item_fulfilled_by_staff", object_id=str(self.line.pk))
        self.assertEqual(events.count(), 2)

    def test_marking_fulfilled_without_activation_leaves_the_service(self) -> None:
        self.client.force_login(self._staff("admin"))
        self.client.post(self.url)
        self._reload()
        self.assertEqual((self.line.provisioning_status, self.service.status), ("completed", "provisioning"))

    def test_support_and_billing_cannot_mark_a_line_fulfilled(self) -> None:
        for role in ("support", "billing"):
            with self.subTest(role=role):
                self.client.force_login(self._staff(role))
                self.assertEqual(self.client.post(self.url).status_code, 403)
        self._reload()
        self.assertEqual(self.line.provisioning_status, "in_progress")

    def test_only_an_open_line_on_a_provisioning_order_can_be_marked(self) -> None:
        actor = self._staff("admin")
        self.order.__class__.objects.filter(pk=self.order.pk).update(status="cancelled")
        self.assertTrue(complete_line_for_staff(self.line.pk, actor=actor, activate_service=False).is_err())
        self._reload()
        self.assertEqual(self.line.provisioning_status, "in_progress")

    def test_order_page_offers_the_action_only_to_admin_and_manager(self) -> None:
        detail = reverse("orders:order_detail", kwargs={"pk": self.order.pk})
        self.client.force_login(self._staff("manager"))
        page = self.client.get(detail)
        self.assertContains(page, f'hx-post="{self.url}"')
        self.assertContains(page, "hx-confirm=")
        self.client.force_login(self._staff("support"))
        self.assertNotContains(self.client.get(detail), self.url)
