"""Real signed requests scope transfer codes to active owner and billing members."""
from __future__ import annotations

import json
from unittest.mock import patch

from django.core.cache import cache
from django.test import TestCase, override_settings
from django.urls import resolve

from apps.audit.models import AuditEvent
from apps.common.performance.rate_limiting import PortalHMACBurstThrottle, PortalHMACRateThrottle
from apps.customers.models import Customer
from apps.domains.models import Domain, DomainOrderItem
from apps.orders.models import Order, OrderItem
from apps.users.models import CustomerMembership, User
from tests.helpers.hmac import HMAC_TEST_MIDDLEWARE, HMAC_TEST_SECRET, HMACTestMixin

from .test_domain_order_transfers import TransferLineFixture


@override_settings(PLATFORM_API_SECRET=HMAC_TEST_SECRET, MIDDLEWARE=HMAC_TEST_MIDDLEWARE)
class TransferCodeAPITests(HMACTestMixin, TransferLineFixture, TestCase):
    def setUp(self) -> None:
        super().setUp()
        cache.clear()
        self.users: dict[str, User] = {}
        for role in ("owner", "billing", "tech", "viewer"):
            user = User.objects.create_user(email=f"transfer-{role}@example.test")
            CustomerMembership.objects.create(customer=self.customer, user=user, role=role, is_active=True)
            self.users[role] = user
        self.outsider = User.objects.create_user(email="transfer-outsider@example.test")

    def _path(self, order: Order, line: OrderItem) -> str:
        return f"/api/orders/{order.pk}/items/{line.pk}/transfer-code/"

    def _payload(self, role: str = "owner", code: object = "Transfer-Secret!123") -> dict[str, object]:
        return {"customer_id": self.customer.pk, "user_id": self.users[role].pk, "transfer_code": code}

    def test_owner_and_billing_can_submit_but_only_provisioning_requeues_by_order_id(self) -> None:
        for state in ("awaiting_payment", "paid", "in_review", "provisioning"):
            for role in ("owner", "billing"):
                with self.subTest(state=state, role=role):
                    order, line = self._transfer_order(f"code-{state.replace('_', '-')}-{role}.ro")
                    Order.objects.filter(pk=order.pk).update(status=state)
                    with patch("django_q.tasks.async_task") as enqueue, self.captureOnCommitCallbacks(execute=True):
                        response = self.portal_post(self._path(order, line), self._payload(role, "  printable!~123  "))
                    self.assertEqual(response.status_code, 200, response.content)
                    item = DomainOrderItem.objects.get(order_item=line)
                    self.assertEqual(item.get_decrypted_epp_code(), "printable!~123")
                    self.assertNotIn("printable", item.epp_code)
                    self.assertEqual(response.json(), {"success": True})
                    events = AuditEvent.objects.filter(action="domain_transfer_code_received", object_id=str(item.pk))
                    self.assertTrue(events.exists())
                    event = events.get()
                    self.assertEqual(event.user, self.users[role])
                    if state == "provisioning":
                        enqueue.assert_called_once_with("apps.domains.tasks.process_order_domain_items", str(order.pk))
                    else:
                        enqueue.assert_not_called()
                    evidence = json.dumps(list(AuditEvent.objects.values("metadata", "old_values", "new_values", "description")), default=str)
                    self.assertNotIn("printable!~123", evidence)
                    self.assertNotIn(item.epp_code, evidence)

    def test_unsigned_tech_viewer_outsider_and_inactive_members_cannot_set_a_code(self) -> None:
        order, line = self._transfer_order()
        path = self._path(order, line)
        response = self.client.post(path, self._payload(), content_type="application/json")
        self.assertEqual(response.status_code, 401)
        self.assertEqual(DomainOrderItem.objects.get(order_item=line).epp_code, "")
        payloads = [self._payload(role) for role in ("tech", "viewer")]
        payloads.append({**self._payload(), "user_id": self.outsider.pk})
        for payload in payloads:
            response = self.portal_post(path, payload)
            self.assertEqual(response.status_code, 403, response.content)
            self.assertEqual(DomainOrderItem.objects.get(order_item=line).epp_code, "")
        CustomerMembership.objects.filter(user=self.users["owner"]).update(is_active=False)
        response = self.portal_post(path, self._payload())
        self.assertEqual(response.status_code, 403)
        self.assertFalse(AuditEvent.objects.filter(action="domain_transfer_code_received").exists())

    def test_codes_are_one_to_sixty_four_printable_nonspace_ascii_characters(self) -> None:
        order, line = self._transfer_order()
        Order.objects.filter(pk=order.pk).update(status="awaiting_payment")
        for code in ("", "  ", "x" * 65, "has space", "line\nbreak", "\x00", "café", 123, None, ["code"]):
            with self.subTest(code=code):
                response = self.portal_post(self._path(order, line), self._payload(code=code))
                self.assertEqual(response.status_code, 400, response.content)
                self.assertEqual(DomainOrderItem.objects.get(order_item=line).epp_code, "")
                if isinstance(code, str) and code.strip():
                    self.assertNotIn(code, response.content.decode())
        for code in ("!", "~" * 64):
            response = self.portal_post(self._path(order, line), self._payload(code=code))
            self.assertEqual(response.status_code, 200, response.content)
            self.assertEqual(DomainOrderItem.objects.get(order_item=line).get_decrypted_epp_code(), code)

    def test_unpaid_draft_cancelled_completed_and_dispatched_lines_reject_codes(self) -> None:
        order, line = self._transfer_order()
        for state in ("draft", "cancelled", "completed"):
            Order.objects.filter(pk=order.pk).update(status=state)
            response = self.portal_post(self._path(order, line), self._payload())
            self.assertEqual(response.status_code, 400, response.content)
            self.assertEqual(DomainOrderItem.objects.get(order_item=line).epp_code, "")
        Order.objects.filter(pk=order.pk).update(status="provisioning")
        for state in ("in_progress", "completed", "cancelled"):
            OrderItem.objects.filter(pk=line.pk).update(provisioning_status=state)
            response = self.portal_post(self._path(order, line), self._payload())
            self.assertEqual(response.status_code, 400, response.content)
            self.assertEqual(DomainOrderItem.objects.get(order_item=line).epp_code, "")

    def test_a_failed_unlinked_transfer_can_retry_but_a_linked_one_cannot(self) -> None:
        order, line = self._transfer_order()
        OrderItem.objects.filter(pk=line.pk).update(provisioning_status="failed")
        with patch("django_q.tasks.async_task"), self.captureOnCommitCallbacks(execute=True):
            response = self.portal_post(self._path(order, line), self._payload())
        self.assertEqual(response.status_code, 200, response.content)
        line.refresh_from_db()
        self.assertEqual(line.provisioning_status, "pending")
        domain = Domain.objects.create(name=line.domain_name, tld=self.ro, registrar=self.ro_registrar, customer=self.customer)
        DomainOrderItem.objects.filter(order_item=line).update(domain=domain)
        OrderItem.objects.filter(pk=line.pk).update(provisioning_status="failed")
        response = self.portal_post(self._path(order, line), self._payload(code="replacement"))
        self.assertEqual(response.status_code, 400, response.content)
        self.assertEqual(DomainOrderItem.objects.get(order_item=line).get_decrypted_epp_code(), "Transfer-Secret!123")

    def test_the_line_must_belong_to_the_signed_customers_order_and_be_a_transfer(self) -> None:
        order, line = self._transfer_order()
        other_order, other_line = self._transfer_order("other-transfer.ro")
        response = self.portal_post(self._path(other_order, line), self._payload())
        self.assertEqual(response.status_code, 404)
        self.assertEqual(DomainOrderItem.objects.get(order_item=line).epp_code, "")
        DomainOrderItem.objects.filter(order_item=line).update(order=other_order)
        response = self.portal_post(self._path(order, line), self._payload())
        self.assertEqual(response.status_code, 400)
        self.assertEqual(DomainOrderItem.objects.get(order_item=line).epp_code, "")
        for action in ("register", "renew"):
            DomainOrderItem.objects.filter(order_item=other_line).update(action=action)
            response = self.portal_post(self._path(other_order, other_line), self._payload())
            self.assertEqual(response.status_code, 400)
            self.assertEqual(DomainOrderItem.objects.get(order_item=other_line).epp_code, "")
        DomainOrderItem.objects.filter(order_item=other_line).update(action="transfer")
        OrderItem.objects.filter(pk=other_line.pk).update(product_type="shared_hosting")
        response = self.portal_post(self._path(other_order, other_line), self._payload())
        self.assertEqual(response.status_code, 400)
        self.assertEqual(DomainOrderItem.objects.get(order_item=other_line).epp_code, "")
        OrderItem.objects.filter(pk=other_line.pk).update(product_type="domain")
        other_customer = Customer.objects.create(name="Other owner", primary_email="other-owner@example.test", status="active")
        Order.objects.filter(pk=other_order.pk).update(customer=other_customer)
        response = self.portal_post(self._path(other_order, other_line), self._payload())
        self.assertEqual(response.status_code, 404)
        self.assertEqual(DomainOrderItem.objects.get(order_item=other_line).epp_code, "")

    def test_the_signed_endpoint_declares_both_hmac_throttles(self) -> None:
        order, line = self._transfer_order()
        callback = resolve(self._path(order, line)).func
        self.assertIn(PortalHMACRateThrottle, callback.cls.throttle_classes)
        self.assertIn(PortalHMACBurstThrottle, callback.cls.throttle_classes)
