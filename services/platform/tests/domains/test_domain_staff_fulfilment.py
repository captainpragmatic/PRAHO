"""Staff record the registrar's answer against the paid line, without dispatching it again."""

from __future__ import annotations

from datetime import timedelta
from unittest.mock import patch
from uuid import UUID

from django.db.models import Model, QuerySet
from django.http import HttpResponse
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from apps.audit.models import AuditEvent
from apps.customers.models import Customer
from apps.domains.models import Domain, DomainOperation, DomainOrderItem
from apps.domains.operation_services import DomainOperationService
from apps.domains.staff_fulfilment import record_paid_domain
from apps.orders.models import Order, OrderItem
from apps.users.models import User

from .test_domain_order_flow import ALERT, REGISTER, DomainOrderLineFixture


class StaffDomainLineTests(DomainOrderLineFixture, TestCase):
    def setUp(self) -> None:
        super().setUp()
        self.staff = User.objects.create_user(email="domain-staff@example.test", password="test", staff_role="admin", is_staff=True)
        self.client.force_login(self.staff)
        self.expires_on = (timezone.localdate() + timedelta(days=365)).isoformat()

    def _url(self, action: str, order: Order, line: OrderItem) -> str:
        return reverse(f"orders:domain_{action}", kwargs={"pk": order.pk, "item_pk": line.pk})

    def _record(self, order: Order, line: OrderItem) -> HttpResponse:
        with self.captureOnCommitCallbacks(execute=True):
            return self.client.post(self._url("record", order, line), {"expires_on": self.expires_on, "registrar_domain_id": "registry-123"})

    def _link(self, line: OrderItem, status: str = "pending") -> Domain:
        domain = Domain.objects.create(name=line.domain_name, tld=self.ro, registrar=self.ro_registrar, customer=self.customer, status=status)
        DomainOrderItem.objects.filter(order_item=line).update(domain=domain)
        return domain

    def test_record_creates_and_completes_pending_failed_and_in_progress_lines_with_the_paid_options(self) -> None:
        for status in ("pending", "failed", "in_progress"):
            with self.subTest(status):
                order, line = self._domain_order(f"staff-{status.replace('_', '-')}.ro")
                OrderItem.objects.filter(pk=line.pk).update(provisioning_status=status)
                DomainOrderItem.objects.filter(order_item=line).update(whois_privacy=True, auto_renew=False, epp_code="encrypted-sentinel")
                with patch(REGISTER) as register:
                    response = self._record(order, line)
                self.assertEqual(response.status_code, 302)
                register.assert_not_called()
                domain = Domain.objects.get(name=line.domain_name)
                self.assertEqual((domain.status, domain.registrar, domain.whois_privacy, domain.auto_renew), ("active", self.ro_registrar, True, False))
                self.assertEqual((domain.registrar_domain_id, domain.expires_at.date().isoformat()), ("registry-123", self.expires_on))
                line.refresh_from_db()
                order.refresh_from_db()
                self.assertEqual((line.provisioning_status, order.status), ("completed", "completed"))
                self.assertEqual(line.domain_order_item.epp_code, "")
                self.assertTrue(AuditEvent.objects.filter(action="domain_recorded_by_staff", user=self.staff, object_id=str(line.domain_order_item.pk)).exists())

    def test_record_activates_a_linked_pending_or_transfer_domain_and_accepts_an_active_one(self) -> None:
        for status in ("pending", "transfer_in", "active"):
            with self.subTest(status):
                order, line = self._domain_order(f"linked-{status.replace('_', '-')}.ro")
                OrderItem.objects.filter(pk=line.pk).update(provisioning_status="in_progress")
                domain = self._link(line, status)
                DomainOrderItem.objects.filter(order_item=line).update(epp_code="encrypted-sentinel")
                registered_at = timezone.now() - timedelta(days=30)
                Domain.objects.filter(pk=domain.pk).update(registered_at=registered_at)
                response = self._record(order, line)
                self.assertEqual(response.status_code, 302)
                domain.refresh_from_db()
                line.refresh_from_db()
                self.assertEqual((domain.status, domain.registered_at, line.provisioning_status), ("active", registered_at, "completed"))
                self.assertEqual(Domain.objects.filter(name=line.domain_name).count(), 1)

    def test_refusal_discards_only_an_unconfirmed_domain_and_fails_the_line_without_a_second_alert(self) -> None:
        discarded_states: list[str] = []
        discard = DomainOperationService.discard_unconfirmed

        def observe_discard(domain_id: UUID) -> bool:
            discarded_states.extend(DomainOperation.objects.filter(domain_id=domain_id).values_list("state", flat=True))
            return discard(domain_id)

        for status in ("pending", "transfer_in"):
            with self.subTest(status):
                order, line = self._domain_order(f"refused-{status.replace('_', '-')}.ro")
                OrderItem.objects.filter(pk=line.pk).update(provisioning_status="in_progress")
                domain = self._link(line, status)
                operation = DomainOperation.objects.create(domain=domain, registrar=self.ro_registrar, operation_type="register", state="submitted", intent_key="staff-refusal")
                DomainOrderItem.objects.filter(order_item=line).update(epp_code="encrypted-sentinel")
                discarded_states.clear()
                with patch(ALERT) as alert, patch.object(DomainOperationService, "discard_unconfirmed", side_effect=observe_discard), self.captureOnCommitCallbacks(execute=True):
                    response = self.client.post(self._url("refuse", order, line))
                self.assertEqual(response.status_code, 302)
                line.refresh_from_db()
                self.assertEqual(line.provisioning_status, "failed")
                self.assertTrue(line.provisioning_notes)
                self.assertFalse(Domain.objects.filter(pk=domain.pk).exists())
                self.assertFalse(DomainOperation.objects.filter(pk=operation.pk).exists())
                self.assertEqual(discarded_states, ["failed"])
                self.assertIsNone(line.domain_order_item.domain_id)
                self.assertEqual(line.domain_order_item.epp_code, "")
                self.assertTrue(AuditEvent.objects.filter(action="domain_refusal_recorded_by_staff", user=self.staff).exists())
                alert.assert_not_called()

    def test_both_actions_accept_a_cancelled_orders_in_flight_line(self) -> None:
        for action in ("record", "refuse"):
            with self.subTest(action):
                order, line = self._domain_order(f"cancelled-{action}.ro")
                OrderItem.objects.filter(pk=line.pk).update(provisioning_status="in_progress")
                self._link(line)
                Order.objects.filter(pk=order.pk).update(status="cancelled")
                with patch(ALERT), self.captureOnCommitCallbacks(execute=True):
                    response = self._record(order, line) if action == "record" else self.client.post(self._url(action, order, line))
                self.assertEqual(response.status_code, 302)
                order.refresh_from_db()
                line.refresh_from_db()
                self.assertEqual(order.status, "cancelled")
                self.assertEqual(line.provisioning_status, "completed" if action == "record" else "failed")

    def test_record_refuses_past_dates_missing_registry_ids_and_an_unrelated_existing_domain(self) -> None:
        order, line = self._domain_order()
        payloads = [
            {"expires_on": "2000-01-01", "registrar_domain_id": "id"},
            {"expires_on": timezone.localdate().isoformat(), "registrar_domain_id": "id"},
            {"expires_on": "2026-02-31", "registrar_domain_id": "id"},
            {"expires_on": self.expires_on, "registrar_domain_id": ""},
            {"expires_on": self.expires_on, "registrar_domain_id": "x" * 101},
        ]
        for payload in payloads:
            response = self.client.post(self._url("record", order, line), payload)
            self.assertEqual(response.status_code, 400)
            self.assertFalse(Domain.objects.filter(name=line.domain_name).exists())
        self._link(line, "suspended")
        response = self._record(order, line)
        self.assertEqual(response.status_code, 400)
        line.refresh_from_db()
        self.assertEqual(line.provisioning_status, "pending")
        DomainOrderItem.objects.filter(order_item=line).update(domain=None)
        with patch.object(Domain.objects, "create", wraps=Domain.objects.create) as create:
            response = self._record(order, line)
        self.assertEqual(response.status_code, 400)
        create.assert_not_called()
        self.assertEqual(Domain.objects.filter(name=line.domain_name).count(), 1)

    def test_actions_require_a_provisioning_order_or_a_cancelled_in_flight_line(self) -> None:
        order, line = self._domain_order()
        for status in ("draft", "awaiting_payment", "paid", "in_review", "completed", "cancelled"):
            Order.objects.filter(pk=order.pk).update(status=status)
            for action in ("record", "refuse"):
                response = self.client.post(self._url(action, order, line), {"expires_on": self.expires_on, "registrar_domain_id": "id"})
                self.assertEqual(response.status_code, 400)
                self.assertFalse(Domain.objects.filter(name=line.domain_name).exists())
        line.refresh_from_db()
        self.assertEqual(line.provisioning_status, "pending")

    def test_actions_reject_renewals_wrong_orders_and_mismatched_linked_domains(self) -> None:
        order, line = self._domain_order()
        other, _other_line = self._domain_order("other.ro")
        OrderItem.objects.filter(pk=line.pk).update(provisioning_status="in_progress")
        domain = self._link(line)
        for action in ("record", "refuse"):
            with self.subTest(action):
                response = self.client.post(self._url(action, other, line), {"expires_on": self.expires_on, "registrar_domain_id": "id"})
                self.assertEqual(response.status_code, 404)
                DomainOrderItem.objects.filter(order_item=line).update(action="renew")
                response = self.client.post(self._url(action, order, line), {"expires_on": self.expires_on, "registrar_domain_id": "id"})
                self.assertEqual(response.status_code, 400)
                DomainOrderItem.objects.filter(order_item=line).update(action="register", order=other)
                response = self.client.post(self._url(action, order, line), {"expires_on": self.expires_on, "registrar_domain_id": "id"})
                self.assertEqual(response.status_code, 400)
                DomainOrderItem.objects.filter(order_item=line).update(order=order)
                Domain.objects.filter(pk=domain.pk).update(name="mismatched.ro")
                response = self.client.post(self._url(action, order, line), {"expires_on": self.expires_on, "registrar_domain_id": "id"})
                self.assertEqual(response.status_code, 400)
                Domain.objects.filter(pk=domain.pk).update(name=line.domain_name)
        line.refresh_from_db()
        self.assertEqual(line.provisioning_status, "in_progress")
        self.assertFalse(AuditEvent.objects.filter(action="domain_recorded_by_staff").exists())

    def test_refusal_cannot_discard_an_active_domain(self) -> None:
        order, line = self._domain_order()
        OrderItem.objects.filter(pk=line.pk).update(provisioning_status="in_progress")
        domain = self._link(line, "active")
        with patch.object(DomainOperationService, "discard_unconfirmed", wraps=DomainOperationService.discard_unconfirmed) as discard:
            response = self.client.post(self._url("refuse", order, line))
        self.assertEqual(response.status_code, 400)
        discard.assert_not_called()
        domain.refresh_from_db()
        line.refresh_from_db()
        self.assertEqual((domain.status, line.provisioning_status), ("active", "in_progress"))

    def test_actions_refuse_a_hosting_line_even_if_a_domain_item_is_linked_to_it(self) -> None:
        order, line = self._domain_order()
        OrderItem.objects.filter(pk=line.pk).update(product_type="shared_hosting", provisioning_status="in_progress")
        domain = self._link(line)
        for action in ("record", "refuse"):
            response = self.client.post(self._url(action, order, line), {"expires_on": self.expires_on, "registrar_domain_id": "id"})
            self.assertEqual(response.status_code, 400)
            domain.refresh_from_db()
            line.refresh_from_db()
            self.assertEqual((domain.status, line.provisioning_status), ("pending", "in_progress"))

    def test_actions_refuse_each_mismatched_domain_identity(self) -> None:
        other_customer = Customer.objects.create(name="Other domain owner", primary_email="other@example.test")
        mismatches = {"customer_id": other_customer.pk, "tld_id": self.com_ro.pk, "registrar_id": self.com_ro_registrar.pk}
        for field, value in mismatches.items():
            for action in ("record", "refuse"):
                with self.subTest(field=field, action=action):
                    order, line = self._domain_order(f"mismatch-{field.replace('_', '-')}-{action}.ro")
                    OrderItem.objects.filter(pk=line.pk).update(provisioning_status="in_progress")
                    domain = self._link(line)
                    Domain.objects.filter(pk=domain.pk).update(**{field: value})
                    response = self.client.post(self._url(action, order, line), {"expires_on": self.expires_on, "registrar_domain_id": "id"})
                    self.assertEqual(response.status_code, 400)
                    domain.refresh_from_db()
                    line.refresh_from_db()
                    self.assertEqual((domain.status, line.provisioning_status), ("pending", "in_progress"))

    def test_completed_and_cancelled_lines_cannot_be_recorded_again(self) -> None:
        order, line = self._domain_order()
        for status in ("completed", "cancelled"):
            OrderItem.objects.filter(pk=line.pk).update(provisioning_status=status)
            for action in ("record", "refuse"):
                response = self.client.post(self._url(action, order, line), {"expires_on": self.expires_on, "registrar_domain_id": "id"})
                self.assertEqual(response.status_code, 400)
                line.refresh_from_db()
                self.assertEqual(line.provisioning_status, status)
                self.assertFalse(Domain.objects.filter(name=line.domain_name).exists())

    def test_refusal_requires_an_in_progress_line_and_a_linked_domain(self) -> None:
        order, line = self._domain_order()
        domain = self._link(line)
        with patch.object(DomainOperationService, "discard_unconfirmed", wraps=DomainOperationService.discard_unconfirmed) as discard:
            response = self.client.post(self._url("refuse", order, line))
        self.assertEqual(response.status_code, 400)
        discard.assert_not_called()
        self.assertTrue(Domain.objects.filter(pk=domain.pk).exists())
        domain.delete()
        OrderItem.objects.filter(pk=line.pk).update(provisioning_status="in_progress")
        response = self.client.post(self._url("refuse", order, line))
        self.assertEqual(response.status_code, 400)
        line.refresh_from_db()
        self.assertEqual(line.provisioning_status, "in_progress")

    def test_a_domain_product_without_its_domain_item_is_rejected(self) -> None:
        order, line = self._domain_order()
        line.domain_order_item.delete()
        for action in ("record", "refuse"):
            response = self.client.post(self._url(action, order, line), {"expires_on": self.expires_on, "registrar_domain_id": "id"})
            self.assertEqual(response.status_code, 400)
            self.assertFalse(Domain.objects.filter(name=line.domain_name).exists())

    def test_the_service_refuses_a_missing_purchased_registrar(self) -> None:
        order, line = self._domain_order()
        DomainOrderItem.objects.filter(order_item=line).update(registrar=None)

        with patch.object(Domain.objects, "create", side_effect=ValueError("Unexpected domain creation")) as create:
            with self.assertRaises(ValueError):
                record_paid_domain(order.pk, line.pk, expires_on=timezone.localdate() + timedelta(days=365), registrar_domain_id="id", actor=self.staff)
            create.assert_not_called()

        self.assertFalse(Domain.objects.filter(name=line.domain_name).exists())
        line.refresh_from_db()
        self.assertEqual(line.provisioning_status, "pending")

    def test_both_actions_lock_the_order_line_domain_item_and_domain_in_that_order(self) -> None:
        original_fetch = QuerySet._fetch_all
        locks: list[type[Model]] = []

        def observe(queryset: QuerySet[Model]) -> None:
            if queryset.query.select_for_update:
                locks.append(queryset.model)
            original_fetch(queryset)

        for action in ("record", "refuse"):
            with self.subTest(action):
                order, line = self._domain_order(f"lock-{action}.ro")
                OrderItem.objects.filter(pk=line.pk).update(provisioning_status="in_progress")
                self._link(line)
                locks.clear()
                with patch.object(QuerySet, "_fetch_all", new=observe), self.captureOnCommitCallbacks(execute=True):
                    response = self._record(order, line) if action == "record" else self.client.post(self._url(action, order, line))

                self.assertEqual(response.status_code, 302)
                self.assertEqual(locks[:4], [Order, OrderItem, DomainOrderItem, Domain])

    def test_admin_and_billing_only_post_actions_and_the_page_requests_confirmation(self) -> None:
        order, line = self._domain_order()
        for role in ("support", "manager"):
            User.objects.filter(pk=self.staff.pk).update(staff_role=role, is_superuser=False)
            for action in ("record", "refuse"):
                response = self.client.post(self._url(action, order, line))
                self.assertEqual(response.status_code, 403)
                line.refresh_from_db()
                self.assertEqual(line.provisioning_status, "pending")
        User.objects.filter(pk=self.staff.pk).update(staff_role="billing")
        for action in ("record", "refuse"):
            response = self.client.get(self._url(action, order, line))
            self.assertEqual(response.status_code, 405)
            self.assertFalse(Domain.objects.filter(name=line.domain_name).exists())
        response = self.client.get(reverse("orders:order_detail", kwargs={"pk": order.pk}))
        self.assertContains(response, "Registered at the registrar")
        self.assertContains(response, "hx-confirm=")
        response = self._record(order, line)
        self.assertEqual(response.status_code, 302)
        line.refresh_from_db()
        self.assertEqual(line.provisioning_status, "completed")
