"""Staff reveal transfer codes in one audited response, without retaining them in pages."""
from __future__ import annotations

import json

from django.test import TestCase
from django.urls import reverse
from django.utils.html import escape

from apps.audit.models import AuditEvent
from apps.domains.models import DomainOrderItem
from apps.orders.models import Order, OrderItem
from apps.users.models import User

from .test_domain_order_transfers import TransferLineFixture


class StaffTransferCodeTests(TransferLineFixture, TestCase):
    def setUp(self) -> None:
        super().setUp()
        self.staff = User.objects.create_user(email="transfer-staff@example.test", password="test", staff_role="admin", is_staff=True)
        self.client.force_login(self.staff)

    def _path(self, order: Order, line: OrderItem) -> str:
        return reverse("orders:order_detail", kwargs={"pk": order.pk}) + f"items/{line.pk}/domain/transfer-code/"

    def test_a_reveal_is_audited_escaped_and_never_cached_or_retained_in_the_next_page(self) -> None:
        order, line = self._transfer_order()
        OrderItem.objects.filter(pk=line.pk).update(provisioning_status="failed")
        code = "EPP<&>!123"
        encrypted = self._code(line, code)
        response = self.client.post(self._path(order, line))
        self.assertEqual(response.status_code, 200, response.content)
        self.assertContains(response, escape(code), count=1)
        self.assertNotContains(response, code)
        self.assertIn("no-store", response.headers["Cache-Control"])
        self.assertEqual(DomainOrderItem.objects.get(order_item=line).epp_code, encrypted)
        events = AuditEvent.objects.filter(action="domain_transfer_code_revealed", object_id=str(line.domain_order_item.pk))
        self.assertTrue(events.exists())
        event = events.get()
        self.assertEqual(event.user, self.staff)
        evidence = json.dumps(list(AuditEvent.objects.values("metadata", "old_values", "new_values", "description")), default=str)
        for secret in (code, encrypted):
            self.assertNotIn(secret, evidence)
            self.assertNotIn(secret, json.dumps(dict(self.client.session)))
        page = self.client.get(reverse("orders:order_detail", kwargs={"pk": order.pk}))
        self.assertNotContains(page, escape(code))
        self.assertContains(page, "Show transfer code")
        self.assertContains(page, "hx-confirm=")

    def test_only_admin_and_billing_can_reveal_and_only_by_post(self) -> None:
        order, line = self._transfer_order()
        self._code(line)
        for role in ("support", "manager"):
            User.objects.filter(pk=self.staff.pk).update(staff_role=role)
            response = self.client.post(self._path(order, line))
            self.assertEqual(response.status_code, 403)
            self.assertFalse(AuditEvent.objects.filter(action="domain_transfer_code_revealed").exists())
        User.objects.filter(pk=self.staff.pk).update(staff_role="billing")
        response = self.client.get(self._path(order, line))
        self.assertEqual(response.status_code, 405)
        self.assertFalse(AuditEvent.objects.filter(action="domain_transfer_code_revealed").exists())
        response = self.client.post(self._path(order, line))
        self.assertContains(response, "Transfer-Secret!123")
        self.assertTrue(AuditEvent.objects.filter(action="domain_transfer_code_revealed", user=self.staff).exists())

    def test_a_reveal_requires_a_transfer_code_and_the_line_on_that_order(self) -> None:
        order, line = self._transfer_order()
        other, _other_line = self._transfer_order("other-reveal.ro")
        response = self.client.post(self._path(order, line))
        self.assertEqual(response.status_code, 400)
        self.assertFalse(AuditEvent.objects.filter(action="domain_transfer_code_revealed").exists())
        self._code(line)
        response = self.client.post(self._path(other, line))
        self.assertEqual(response.status_code, 404)
        self.assertFalse(AuditEvent.objects.filter(action="domain_transfer_code_revealed").exists())
        DomainOrderItem.objects.filter(order_item=line).update(action="register")
        response = self.client.post(self._path(order, line))
        self.assertEqual(response.status_code, 400)
        self.assertFalse(AuditEvent.objects.filter(action="domain_transfer_code_revealed").exists())
