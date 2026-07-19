"""Order discount concurrency regressions for issue #310."""

from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal
from unittest import mock

from django.db import close_old_connections, connection, transaction
from django.test import TestCase, TransactionTestCase
from django.utils import timezone

from apps.billing.models import Currency
from apps.customers.models import Customer
from apps.orders.models import Order, OrderItem
from apps.products.models import Product
from apps.promotions import services as promotion_services
from apps.promotions.models import Coupon, GiftCard
from apps.promotions.services import ApplyResult, CouponService, GiftCardService


class PromotionOrderLockTestCase(TestCase):
    """Promotion writes must preserve the latest committed Order discount."""

    def setUp(self) -> None:
        self.currency, _ = Currency.objects.get_or_create(
            code="RON", defaults={"name": "Romanian Leu", "symbol": "lei"}
        )
        self.customer = Customer.objects.create(
            name="Concurrent Promotions",
            customer_type="individual",
            status="active",
        )
        product = Product.objects.create(
            slug="concurrent-hosting",
            name="Concurrent Hosting",
            product_type="shared_hosting",
        )
        self.order = Order.objects.create(
            customer=self.customer,
            currency=self.currency,
            customer_email="concurrent@example.com",
            customer_name="Concurrent Promotions",
            subtotal_cents=10000,
            total_cents=10000,
        )
        OrderItem.objects.create(
            order=self.order,
            product=product,
            product_name=product.name,
            product_type=product.product_type,
            billing_period="monthly",
            quantity=1,
            unit_price_cents=10000,
            setup_cents=0,
            line_total_cents=10000,
        )

    def _coupon(self, code: str) -> Coupon:
        return Coupon.objects.create(
            code=code,
            name=f"Coupon {code}",
            discount_type="percent",
            discount_percent=Decimal("20.00"),
            status="active",
            is_active=True,
            is_stackable=True,
            valid_from=timezone.now() - timezone.timedelta(days=1),
        )

    def test_gift_card_deactivated_while_waiting_for_order_lock_is_refused(self) -> None:
        """Pre-lock validation races any status change; the Order lock widens that gap.

        A card deactivated between the unlocked validity check and the locked
        redemption must be refused on the locked row — not redeemed with its
        status silently overwritten to partially_used.
        """
        card = GiftCard.objects.create(
            code="TOCTOU-GIFT",
            initial_value_cents=5000,
            current_balance_cents=5000,
            currency=self.currency,
            status="active",
        )
        original_lock = promotion_services._lock_order_for_discount_update

        def deactivate_card_then_lock(order: Order) -> None:
            GiftCard.objects.filter(pk=card.pk).update(is_active=False)
            original_lock(order)

        with mock.patch.object(
            promotion_services, "_lock_order_for_discount_update", side_effect=deactivate_card_then_lock
        ):
            result = GiftCardService.redeem_gift_card(
                code=card.code, order=self.order, amount_cents=1000, customer=self.customer
            )

        self.assertFalse(result.success)
        card.refresh_from_db()
        self.assertEqual(card.status, "active")
        self.assertEqual(card.current_balance_cents, 5000)
        self.order.refresh_from_db()
        self.assertEqual(self.order.discount_cents, 0)

    def test_future_dated_gift_card_is_refused(self) -> None:
        """A card with valid_from in the future must not be redeemable today."""
        card = GiftCard.objects.create(
            code="FUTURE-GIFT",
            initial_value_cents=5000,
            current_balance_cents=5000,
            currency=self.currency,
            status="active",
            valid_from=timezone.now() + timezone.timedelta(days=1),
        )

        result = GiftCardService.redeem_gift_card(
            code=card.code, order=self.order, amount_cents=1000, customer=self.customer
        )

        self.assertFalse(result.success)
        card.refresh_from_db()
        self.assertEqual(card.current_balance_cents, 5000)

    def test_gift_card_deleted_while_waiting_for_order_lock_is_refused_not_500(self) -> None:
        """A card deleted in the lock-wait gap must yield a refusal, not DoesNotExist."""
        card = GiftCard.objects.create(
            code="VANISHING-GIFT",
            initial_value_cents=5000,
            current_balance_cents=5000,
            currency=self.currency,
            status="active",
        )
        original_lock = promotion_services._lock_order_for_discount_update

        def delete_card_then_lock(order: Order) -> None:
            GiftCard.objects.filter(pk=card.pk).delete()
            original_lock(order)

        with mock.patch.object(
            promotion_services, "_lock_order_for_discount_update", side_effect=delete_card_then_lock
        ):
            result = GiftCardService.redeem_gift_card(
                code=card.code, order=self.order, amount_cents=1000, customer=self.customer
            )

        self.assertFalse(result.success)
        self.order.refresh_from_db()
        self.assertEqual(self.order.discount_cents, 0)

    def test_coupon_preserves_a_concurrently_committed_discount(self) -> None:
        coupon = self._coupon("STALE20")
        Order.objects.filter(pk=self.order.pk).update(discount_cents=1000)

        result = CouponService.apply_coupon(code=coupon.code, order=self.order, customer=self.customer)

        self.assertTrue(result.success, f"coupon failed: {result.error_message}")
        self.assertEqual(self.order.discount_cents, 3000)
        self.assertEqual(self.order.total_cents, 7000)
        stored_order = Order.objects.get(pk=self.order.pk)
        self.assertEqual(stored_order.discount_cents, 3000)
        self.assertEqual(stored_order.total_cents, 7000)

    def test_gift_card_preserves_a_concurrently_committed_discount(self) -> None:
        card = GiftCard.objects.create(
            code="STALE-GIFT",
            initial_value_cents=5000,
            current_balance_cents=5000,
            currency=self.currency,
            status="active",
        )
        Order.objects.filter(pk=self.order.pk).update(discount_cents=1000, total_cents=9000)

        result = GiftCardService.redeem_gift_card(
            code=card.code,
            order=self.order,
            amount_cents=2000,
            customer=self.customer,
        )

        self.assertTrue(result.success, f"gift card failed: {result.error_message}")
        self.assertEqual(self.order.discount_cents, 3000)
        self.assertEqual(self.order.total_cents, 7000)
        stored_order = Order.objects.get(pk=self.order.pk)
        self.assertEqual(stored_order.discount_cents, 3000)
        self.assertEqual(stored_order.total_cents, 7000)

    def test_coupon_removal_preserves_other_committed_discounts(self) -> None:
        coupon = self._coupon("REMOVE20")
        applied = CouponService.apply_coupon(code=coupon.code, order=self.order, customer=self.customer)
        self.assertTrue(applied.success, f"coupon failed: {applied.error_message}")

        stale_order = Order.objects.get(pk=self.order.pk)
        Order.objects.filter(pk=self.order.pk).update(discount_cents=3000, total_cents=7000)

        removed = CouponService.remove_coupon(order=stale_order, redemption_id=applied.redemption_id)

        self.assertTrue(removed)
        self.assertEqual(stale_order.discount_cents, 1000)
        self.assertEqual(stale_order.total_cents, 9000)
        stored_order = Order.objects.get(pk=self.order.pk)
        self.assertEqual(stored_order.discount_cents, 1000)
        self.assertEqual(stored_order.total_cents, 9000)


class PromotionOrderPostgresConcurrencyTests(TransactionTestCase):
    """Exercise the real two-connection coupon/gift-card interleaving."""

    reset_sequences = True

    def setUp(self) -> None:
        self.currency, _ = Currency.objects.get_or_create(
            code="RON", defaults={"name": "Romanian Leu", "symbol": "lei"}
        )
        self.customer = Customer.objects.create(
            name="Concurrent Promotions",
            customer_type="individual",
            status="active",
        )
        product = Product.objects.create(
            slug="postgres-concurrent-hosting",
            name="PostgreSQL Concurrent Hosting",
            product_type="shared_hosting",
        )
        self.order = Order.objects.create(
            customer=self.customer,
            currency=self.currency,
            customer_email="postgres-concurrent@example.com",
            customer_name="Concurrent Promotions",
            subtotal_cents=10000,
            total_cents=10000,
        )
        OrderItem.objects.create(
            order=self.order,
            product=product,
            product_name=product.name,
            product_type=product.product_type,
            billing_period="monthly",
            quantity=1,
            unit_price_cents=10000,
            setup_cents=0,
            line_total_cents=10000,
        )
        self.coupon = Coupon.objects.create(
            code="CONCURRENT10",
            name="Concurrent coupon",
            discount_type="percent",
            discount_percent=Decimal("10.00"),
            status="active",
            is_active=True,
            is_stackable=True,
            valid_from=timezone.now() - timezone.timedelta(days=1),
        )
        self.card = GiftCard.objects.create(
            code="CONCURRENT-GIFT",
            initial_value_cents=5000,
            current_balance_cents=5000,
            currency=self.currency,
            status="active",
        )

    def test_concurrent_coupon_and_gift_card_keep_both_discounts(self) -> None:
        if connection.vendor != "postgresql":
            self.skipTest("PostgreSQL row-lock behavior required")

        stale_coupon_order = Order.objects.get(pk=self.order.pk)
        stale_gift_order = Order.objects.get(pk=self.order.pk)
        barrier = threading.Barrier(2)

        def apply_coupon() -> ApplyResult:
            close_old_connections()
            try:
                barrier.wait(timeout=10)
                return CouponService.apply_coupon(
                    code=self.coupon.code,
                    order=stale_coupon_order,
                    customer=self.customer,
                )
            finally:
                connection.close()

        def redeem_gift_card() -> ApplyResult:
            close_old_connections()
            try:
                barrier.wait(timeout=10)
                return GiftCardService.redeem_gift_card(
                    code=self.card.code,
                    order=stale_gift_order,
                    amount_cents=1000,
                    customer=self.customer,
                )
            finally:
                connection.close()

        with ThreadPoolExecutor(max_workers=2) as executor:
            coupon_future = executor.submit(apply_coupon)
            gift_future = executor.submit(redeem_gift_card)
            results = [coupon_future.result(), gift_future.result()]

        self.assertTrue(all(result.success for result in results))
        self.order.refresh_from_db()
        self.card.refresh_from_db()
        self.assertEqual(self.order.discount_cents, 2000)
        self.assertEqual(self.card.current_balance_cents, 4000)

    def test_promotion_blocks_until_order_lock_is_released(self) -> None:
        """Prove serialization, not just final values: while another connection
        holds the Order row lock, a promotion must NOT complete; it may finish
        only after the lock is released. Fails if the lock refresh is ever
        replaced with a plain (non-locking) refresh_from_db."""
        if connection.vendor != "postgresql":
            self.skipTest("PostgreSQL row-lock behavior required")

        lock_held = threading.Event()
        release_lock = threading.Event()

        def hold_order_lock() -> None:
            close_old_connections()
            try:
                with transaction.atomic():
                    Order.objects.select_for_update().get(pk=self.order.pk)
                    lock_held.set()
                    release_lock.wait(timeout=10)
            finally:
                connection.close()

        def apply_coupon() -> ApplyResult:
            close_old_connections()
            try:
                lock_held.wait(timeout=10)
                return CouponService.apply_coupon(
                    code=self.coupon.code,
                    order=Order.objects.get(pk=self.order.pk),
                    customer=self.customer,
                )
            finally:
                connection.close()

        with ThreadPoolExecutor(max_workers=2) as executor:
            holder = executor.submit(hold_order_lock)
            applier = executor.submit(apply_coupon)
            self.assertTrue(lock_held.wait(timeout=10))
            time.sleep(0.5)
            self.assertFalse(applier.done(), "promotion completed while the Order row lock was held")
            release_lock.set()
            result = applier.result(timeout=10)
            holder.result(timeout=10)

        self.assertTrue(result.success)
        self.order.refresh_from_db()
        self.assertGreater(self.order.discount_cents, 0)
