"""A domain that cannot be fulfilled is refused before payment, not failed and refunded after it.

Fulfilment always creates a Domain and Domain.name is unique, so a name already managed here can never be
registered or transferred again. A name on another order that can still be paid would be fulfilled twice.
A registration the registrar has just reported as taken would fail at the registrar. Each was accepted at
checkout, paid for, then failed by fail_order_line with a staff alert and a manual refund.
"""

from __future__ import annotations

from unittest.mock import patch

from django.core.cache import cache
from django.test import TestCase, override_settings

from apps.audit.models import AuditEvent
from apps.billing.proforma_models import ProformaInvoice
from apps.domains.availability import DomainAvailabilityService, recorded_availability, verdict_cache_key
from apps.domains.models import Domain, DomainOrderItem
from apps.domains.services import DomainOrderService
from apps.orders.models import Order, OrderItem
from apps.orders.preflight import OrderPreflightValidationService
from apps.orders.services import OrderCreateData, OrderService, StatusChangeData
from config.settings.test import LOCMEM_TEST_CACHE
from tests.orders.test_calculate_cart import _call_calculate

from .test_domain_order_flow import DomainOrderLineFixture, _domain_line

GATEWAY_CHECK = "apps.domains.services.DomainRegistrarGateway.check_domain_availability"


class DomainAvailabilityGateFixture(DomainOrderLineFixture):
    def _price(self, name: str, action: str = "register") -> int:
        return DomainOrderService.quote_order_line(name, action, "RON").unwrap().total_cents

    def _line(self, name: str, action: str = "register", price: int | None = None) -> dict[str, object]:
        line = _domain_line(self.domain_product, name, self._price(name, action) if price is None else price)
        line["meta"] = {"domain_mode": action}
        return line

    def _create(self, *lines: dict[str, object]):
        return OrderService.create_order(
            OrderCreateData(customer=self.customer, currency="RON", billing_address=self._billing(), items=list(lines))
        )

    def _submit(self, order: Order):
        return OrderService.update_order_status(order, StatusChangeData(new_status="awaiting_payment"))

    def _local_domain(self, name: str, customer=None) -> Domain:
        return Domain.objects.create(
            customer=customer or self.customer, tld=self.ro, registrar=self.ro_registrar, name=name
        )

    def _orders_for(self, name: str) -> int:
        return Order.objects.filter(domain_items__domain_name=name).distinct().count()


class LocalAdmissionTests(DomainAvailabilityGateFixture, TestCase):
    def test_register_line_for_a_local_domain_is_refused_in_preflight_and_create_order(self) -> None:
        # A draft taken before the name became managed here: its preflight must now refuse it.
        draft = self._create(self._line("later.ro")).unwrap()
        price = self._price("taken.ro")
        self._local_domain("taken.ro", customer=self.other_customer())
        self._local_domain("later.ro", customer=self.other_customer())

        self.assertTrue(DomainOrderService.quote_order_line("taken.ro", "register", "RON").is_err())
        result = self._create(self._line("taken.ro", price=price))
        self.assertTrue(result.is_err())
        self.assertEqual(self._orders_for("taken.ro"), 0)
        errors, _warnings = OrderPreflightValidationService.validate(Order.objects.get(pk=draft.pk))
        self.assertTrue(any("already managed here" in str(error) for error in errors), errors)

    def test_transfer_line_for_a_local_domain_is_refused(self) -> None:
        price = self._price("mine.ro", "transfer")
        self._local_domain("mine.ro")
        self._local_domain("theirs.ro", customer=self.other_customer())
        for name in ("mine.ro", "theirs.ro"):
            with self.subTest(name=name):
                self.assertTrue(self._create(self._line(name, "transfer", price)).is_err())
                self.assertEqual(self._orders_for(name), 0)

    def test_same_name_twice_in_one_request_is_refused(self) -> None:
        line = self._line("twice.ro")
        self.assertTrue(self._create(line, dict(line)).is_err())
        self.assertEqual(self._orders_for("twice.ro"), 0)

    def test_cart_sells_a_name_once_and_warns_about_the_repeat(self) -> None:
        from apps.billing.currency_models import Currency  # noqa: PLC0415

        item = {
            "product_id": self.domain_product.pk,
            "quantity": 1,
            "billing_period": "annual",
            "config": {"domain_mode": "register"},
            "domain_name": "cart-twice.ro",
        }
        data = _call_calculate(
            self.customer, Currency.objects.get(code="RON"), [item, {**item, "domain_name": "CART-TWICE.ro"}]
        )
        self.assertEqual([line["domain_name"] for line in data["items"]], ["cart-twice.ro"])
        self.assertEqual([warning["type"] for warning in data["warnings"]], ["domain_unavailable"])

    def test_name_on_another_payable_order_is_refused(self) -> None:
        held = self._create(self._line("held.ro")).unwrap()
        for payable in ("awaiting_payment", "paid", "in_review", "provisioning"):
            with self.subTest(status=payable):
                Order.objects.filter(pk=held.pk).update(status=payable)
                self.assertTrue(DomainOrderService.quote_order_line("held.ro", "register", "RON").is_err())
                self.assertTrue(self._create(self._line("held.ro", price=self._price("hold-free.ro"))).is_err())
        self.assertEqual(self._orders_for("held.ro"), 1)

    def test_name_on_a_cancelled_or_draft_order_does_not_block_creation(self) -> None:
        other = self._create(self._line("loose.ro")).unwrap()
        for status in ("draft", "cancelled", "failed"):
            with self.subTest(status=status):
                Order.objects.filter(pk=other.pk).update(status=status)
                self.assertTrue(DomainOrderService.quote_order_line("loose.ro", "register", "RON").is_ok())

    def test_requote_of_the_same_order_does_not_refuse_itself(self) -> None:
        order = self._create(self._line("self.ro")).unwrap()
        Order.objects.filter(pk=order.pk).update(status="awaiting_payment")
        line = OrderItem.objects.get(order=order, domain_name="self.ro")
        self.assertTrue(DomainOrderService.quote_order_item(line, "RON").is_ok())

    def test_second_draft_cannot_become_payable_for_a_held_name(self) -> None:
        first = self._create(self._line("race.ro")).unwrap()
        second = self._create(self._line("race.ro")).unwrap()
        self.assertTrue(self._submit(first).is_ok())
        refused = self._submit(second)
        self.assertTrue(refused.is_err())
        self.assertEqual(Order.objects.get(pk=second.pk).status, "draft")
        self.assertFalse(ProformaInvoice.objects.filter(pk=Order.objects.get(pk=second.pk).proforma_id).exists())

    def test_failed_order_retry_is_refused_when_another_order_holds_the_name(self) -> None:
        failed = self._create(self._line("retry.ro")).unwrap()
        Order.objects.filter(pk=failed.pk).update(status="failed")
        holder = self._create(self._line("retry.ro")).unwrap()
        self.assertTrue(self._submit(holder).is_ok())
        refused = self._submit(Order.objects.get(pk=failed.pk))
        self.assertTrue(refused.is_err())
        self.assertEqual(Order.objects.get(pk=failed.pk).status, "failed")

    def test_order_with_two_attached_lines_for_one_name_cannot_become_payable(self) -> None:
        order = self._create(self._line("sibling.ro")).unwrap()
        first = order.items.get()
        second = OrderItem.objects.create(
            order=order,
            product=self.domain_product,
            quantity=1,
            unit_price_cents=first.unit_price_cents,
            tax_rate=first.tax_rate,
            tax_cents=first.tax_cents,
            line_total_cents=first.line_total_cents,
            product_name=first.product_name,
            product_type="domain",
            domain_name="sibling.ro",
            config={"domain_mode": "register", "billing_period": "once"},
        )
        DomainOrderService.create_domain_order_item(
            order, "sibling.ro", "register", years=1, order_item=second, registrar=self.ro_registrar
        )
        order.calculate_totals()
        self.assertEqual(DomainOrderItem.objects.filter(order=order, domain_name="sibling.ro").count(), 2)
        refused = self._submit(Order.objects.get(pk=order.pk))
        self.assertTrue(refused.is_err())
        self.assertIn("twice", refused.unwrap_err())
        self.assertEqual(Order.objects.get(pk=order.pk).status, "draft")

    def test_status_update_failure_after_the_save_rolls_back(self) -> None:
        order = self._create(self._line("rollback.ro")).unwrap()
        proformas = ProformaInvoice.objects.count()
        with patch.object(OrderService, "_create_status_history", side_effect=RuntimeError("history store down")):
            result = self._submit(order)
        self.assertTrue(result.is_err())
        self.assertEqual(Order.objects.get(pk=order.pk).status, "draft")
        self.assertEqual(ProformaInvoice.objects.count(), proformas)

    def other_customer(self):
        from apps.customers.models import Customer  # noqa: PLC0415

        return Customer.objects.create(
            name="Another Owner",
            company_name="Another Owner SRL",
            customer_type="company",
            primary_email="another-owner@example.test",
            primary_phone="+40712345679",
        )


@override_settings(CACHES=LOCMEM_TEST_CACHE)
class RegistrarVerdictTests(DomainAvailabilityGateFixture, TestCase):
    def setUp(self) -> None:
        super().setUp()
        cache.clear()
        self.addCleanup(cache.clear)

    def _lookup(self, name: str, answer: tuple[bool, bool]) -> None:
        with patch(GATEWAY_CHECK, return_value=answer):
            self.assertTrue(DomainAvailabilityService.check(name).is_ok())

    def test_recorded_taken_verdict_refuses_register_line(self) -> None:
        price = self._price("google.ro")
        self._lookup("  Google.RO ", (True, False))
        self.assertEqual(recorded_availability("google.ro"), "taken")
        self.assertTrue(DomainOrderService.quote_order_line("google.ro", "register", "RON").is_err())
        self.assertTrue(self._create(self._line("google.ro", price=price)).is_err())

    def test_transfer_line_not_refused_by_registrar_taken(self) -> None:
        self._lookup("move-me.ro", (True, False))
        self.assertTrue(self._create(self._line("move-me.ro", "transfer")).is_ok())

    def test_unknown_verdict_accepts_and_flags_the_line_once(self) -> None:
        order = self._create(self._line("unsure.ro")).unwrap()
        line = order.items.get()
        self.assertIs(line.config.get("availability_unconfirmed"), True)
        events = AuditEvent.objects.filter(action="domain_availability_unconfirmed")
        self.assertEqual(events.count(), 1)
        self.assertEqual(events.get().metadata["domain_name"], "unsure.ro")

    def test_order_detail_shows_unconfirmed_availability_badge(self) -> None:
        from django.urls import reverse  # noqa: PLC0415

        from apps.users.models import User  # noqa: PLC0415

        order = self._create(self._line("badge.ro")).unwrap()
        confirmed = self._create(self._line("plain.ro")).unwrap()
        OrderItem.objects.filter(order=confirmed).update(config={"domain_mode": "register"})
        staff = User.objects.create_user(email="badge-staff@example.test", is_staff=True, staff_role="admin")
        self.client.force_login(staff)
        badge = "Availability not confirmed by registrar"
        self.assertContains(self.client.get(reverse("orders:order_detail", kwargs={"pk": order.pk})), badge, count=1)
        self.assertNotContains(self.client.get(reverse("orders:order_detail", kwargs={"pk": confirmed.pk})), badge)

    def test_confirmed_available_line_is_not_flagged(self) -> None:
        self._lookup("free.ro", (True, True))
        line = self._create(self._line("free.ro")).unwrap().items.get()
        self.assertNotIn("availability_unconfirmed", line.config)
        self.assertFalse(AuditEvent.objects.filter(action="domain_availability_unconfirmed").exists())

    def test_unconfirmed_lookup_never_overwrites_a_recorded_verdict(self) -> None:
        self._lookup("kept.ro", (True, False))
        self._lookup("kept.ro", (False, False))
        self.assertEqual(recorded_availability("kept.ro"), "taken")

    def test_a_local_domain_is_never_recorded_as_a_registrar_verdict(self) -> None:
        self._local_domain("local.ro")
        with patch(GATEWAY_CHECK) as check:
            DomainAvailabilityService.check("local.ro")
        check.assert_not_called()
        self.assertEqual(recorded_availability("local.ro"), "unknown")

    def test_no_http_is_made_inside_create_order(self) -> None:
        with patch(GATEWAY_CHECK, side_effect=AssertionError("registrar called inside the order transaction")):
            created = self._create(self._line("offline.ro"))
            self.assertTrue(created.is_ok(), created)
            errors, _warnings = OrderPreflightValidationService.validate(created.unwrap())
        self.assertFalse(any("offline.ro" in str(error) for error in errors), errors)

    def test_verdict_key_fits_the_database_cache_for_a_253_character_name(self) -> None:
        name = ".".join(["a" * 63, "b" * 63, "c" * 63, "d" * 58, "ro"])
        self.assertEqual(len(name), 253)
        # DatabaseCache stores the key as varchar(255), prefixed "praho:1:" in production settings.
        self.assertLessEqual(len("praho:1:" + verdict_cache_key(name)), 255)
        self.assertEqual(verdict_cache_key(name), verdict_cache_key(name.upper()))
