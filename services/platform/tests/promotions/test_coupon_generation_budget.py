"""Coupon generation exhaustion is recoverable and batch budgets are read once."""

from __future__ import annotations

from typing import ClassVar, cast
from unittest.mock import Mock, patch

from django.core.cache import cache
from django.db import connection, transaction
from django.test import SimpleTestCase, TestCase, override_settings
from django.test.utils import CaptureQueriesContext
from django.urls import reverse
from django.utils.translation import gettext as _

from apps.promotions.forms import CouponBatchForm, CouponForm
from apps.promotions.models import COUPON_CODE_LENGTH, Coupon
from apps.settings.services import SettingsService
from apps.users.models import User

BUDGET_KEY = "promotions.max_code_generation_attempts"
SINGLE_ERROR = "Could not generate a coupon code. Enter a code manually or try again."
BATCH_ERROR = "Could not generate the coupon batch. No coupons were created; please try again."


@override_settings(LANGUAGE_CODE="en")
class CouponGenerationCloseoutTests(TestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        self.staff = User.objects.create_user(
            email="coupon-generation@example.test", password="SecurePass123!", staff_role="admin", is_staff=True
        )
        self.client.force_login(self.staff)
        self.client.raise_request_exception = False

    def set_budget(self, attempts: int) -> None:
        result = SettingsService.update_setting(BUDGET_KEY, attempts)
        self.assertTrue(result.is_ok(), result)

    def test_zero_budget_renders_a_creation_form_with_a_manual_code_error(self) -> None:
        self.set_budget(0)
        before = Coupon.objects.count()
        response = self.client.get(reverse("promotions:coupon_create"))
        self.assertContains(response, _(SINGLE_ERROR))
        form = cast(CouponForm, response.context["form"])
        self.assertEqual(list(form.errors["code"]), [_(SINGLE_ERROR)])
        self.assertContains(response, 'name="code"')
        self.assertEqual(Coupon.objects.count(), before)

    def test_collision_exhaustion_renders_a_creation_form_error(self) -> None:
        self.set_budget(1)
        collision = "A" * COUPON_CODE_LENGTH
        Coupon.objects.create(code=collision, name="Existing", discount_percent=10)
        with patch("apps.promotions.models.secrets", Mock(choice=Mock(return_value="A"))):
            response = self.client.get(reverse("promotions:coupon_create"))
        self.assertContains(response, _(SINGLE_ERROR))
        self.assertEqual(Coupon.objects.count(), 1)
        self.assertEqual(Coupon.objects.get().code, collision)

    def test_batch_exhaustion_preserves_input_and_creates_no_rows(self) -> None:
        url = reverse("promotions:coupon_batch_create")
        for attempts in (0, 1):
            with self.subTest(attempts=attempts):
                Coupon.objects.all().delete()
                self.set_budget(attempts)
                collision = "A" * COUPON_CODE_LENGTH
                existing = Coupon.objects.create(code=collision, name="Existing", discount_percent=10)
                choices = ["B"] * COUPON_CODE_LENGTH + ["A"] * COUPON_CODE_LENGTH
                with patch("apps.promotions.models.secrets", Mock(choice=Mock(side_effect=choices))):
                    response = self.client.post(
                        url,
                        {
                            "count": "2",
                            "prefix": "",
                            "name": "Retry batch",
                            "discount_type": "percent",
                            "discount_percent": "10",
                            "discount_amount_cents": "",
                        },
                    )
                self.assertContains(response, _(BATCH_ERROR))
                form = cast(CouponBatchForm, response.context["form"])
                self.assertEqual(list(form.non_field_errors()), [_(BATCH_ERROR)])
                self.assertEqual(form.data["count"], "2")
                self.assertContains(response, "Retry batch")
                self.assertEqual(list(Coupon.objects.values_list("pk", flat=True)), [existing.pk])

        self.set_budget(1)
        choices = ["B"] * COUPON_CODE_LENGTH + ["C"] * COUPON_CODE_LENGTH
        with patch("apps.promotions.models.secrets", Mock(choice=Mock(side_effect=choices))):
            response = self.client.post(
                url,
                {
                    "count": "2",
                    "prefix": "",
                    "name": "Recovered batch",
                    "discount_type": "percent",
                    "discount_percent": "10",
                    "discount_amount_cents": "",
                },
            )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(
            set(Coupon.objects.filter(name="Recovered batch").values_list("code", flat=True)),
            {"B" * COUPON_CODE_LENGTH, "C" * COUPON_CODE_LENGTH},
        )


@override_settings(
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache", "LOCATION": "batch-budget"}}
)
class CouponBatchBudgetQueryTests(SimpleTestCase):
    databases: ClassVar[set[str]] = {"default"}

    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)

    def test_batch_uses_the_warm_cache_and_one_budget_read_inside_atomic(self) -> None:
        self.assertTrue(connection.get_autocommit())
        cache.set(SettingsService._get_cache_key(BUDGET_KEY), 2, version=SettingsService.CACHE_VERSION)
        try:
            with (
                patch("apps.promotions.models.secrets", Mock(choice=Mock(side_effect=["A", "B", "C"]))),
                CaptureQueriesContext(connection) as queries,
            ):
                coupons = Coupon.generate_batch(
                    count=3, length=1, prefix="WP18WARM", name="Warm batch", discount_percent=10
                )
            self.assertEqual(sum(BUDGET_KEY in query["sql"] for query in queries.captured_queries), 0)
            self.assertEqual([coupon.code for coupon in coupons], ["WP18WARMA", "WP18WARMB", "WP18WARMC"])
            self.assertEqual(Coupon.objects.filter(code__startswith="WP18WARM").count(), 3)
        finally:
            Coupon.objects.filter(code__startswith="WP18WARM").delete()

        with transaction.atomic():
            try:
                result = SettingsService.update_setting(BUDGET_KEY, 2)
                self.assertTrue(result.is_ok(), result)
                with (
                    patch("apps.promotions.models.secrets", Mock(choice=Mock(side_effect=["A", "B", "C"]))),
                    CaptureQueriesContext(connection) as queries,
                ):
                    coupons = Coupon.generate_batch(
                        count=3, length=1, prefix="WP18ATOMIC", name="Atomic batch", discount_percent=10
                    )
                reads = sum(BUDGET_KEY in query["sql"] for query in queries.captured_queries)
                self.assertEqual(reads, 1)
                self.assertEqual([coupon.code for coupon in coupons], ["WP18ATOMICA", "WP18ATOMICB", "WP18ATOMICC"])
                self.assertEqual(Coupon.objects.filter(code__startswith="WP18ATOMIC").count(), 3)
            finally:
                transaction.set_rollback(True)
