"""Public catalog relations do not grant mixed-resource or promotional tariff changes."""

from datetime import timedelta
from uuid import uuid4

from django.db import transaction
from django.test import TestCase

from apps.billing.plan_change_catalog import eligible_plan_targets
from apps.products.models import Product, ProductPrice, ProductRelationship
from apps.provisioning.hosting_limit_assignments import request_service_plan_change
from apps.provisioning.models import ServicePlan
from tests.billing.test_plan_change_models import _PlanChangeFixture


class PlanChangeCatalogTests(_PlanChangeFixture, TestCase):
    def setUp(self) -> None:
        super().setUp()
        self.plan.disk_space_gb, self.plan.bandwidth_gb = 10, 100
        self.plan.save(update_fields=["disk_space_gb", "bandwidth_gb"])
        self.product.module = "virtualmin"
        self.product.save(update_fields=["module"])
        with transaction.atomic():
            request_service_plan_change(
                service=self.service,
                target_plan_id=self.plan.pk,
                expected_revision=1,
                submission_id=uuid4(),
                reason="Initial explicit catalog selection fixture",
                authority={"kind": "staff_resource_override"},
            )

    def target(self, *, disk=20, bandwidth=200, price=20000, reverse=False, **price_fields):
        plan = ServicePlan.objects.create(
            name="Candidate",
            plan_type="shared_hosting",
            price_monthly=200,
            disk_space_gb=disk,
            bandwidth_gb=bandwidth,
        )
        product = Product.objects.create(
            name="Candidate",
            slug=uuid4().hex,
            product_type="hosting",
            module="virtualmin",
            default_service_plan=plan,
        )
        tariff = ProductPrice.objects.create(
            product=product,
            currency=self.currency,
            monthly_price_cents=price,
            **price_fields,
        )
        ProductRelationship.objects.create(
            source_product=product if reverse else self.product,
            target_product=self.product if reverse else product,
            relationship_type="upgrades_to",
        )
        return product, plan, tariff

    def test_assigned_allowance_survives_catalog_baseline_edits(self) -> None:
        target, _, _ = self.target()
        ServicePlan.objects.filter(pk=self.plan.pk).update(disk_space_gb=99, bandwidth_gb=999)
        choices = eligible_plan_targets(self.subscription)
        self.assertEqual(
            [(item.product_id, item.direction, item.period_price_cents) for item in choices],
            [(target.pk, "upgrade", 20000)],
        )
        self.assertEqual(choices[0].limits.disk_allowance_mib, 20480)

    def test_standard_tariff_ignores_a_temporary_campaign_price(self) -> None:
        self.target(promo_price_cents=1000, promo_valid_until=self.now + timedelta(days=1))
        self.assertEqual([item.period_price_cents for item in eligible_plan_targets(self.subscription)], [20000])

    def test_reverse_curated_link_offers_only_a_resource_and_price_downgrade(self) -> None:
        target, _, _ = self.target(disk=5, bandwidth=50, price=4000, reverse=True)
        self.assertEqual(
            [(item.product_id, item.direction) for item in eligible_plan_targets(self.subscription)],
            [(target.pk, "downgrade")],
        )

    def test_mixed_resource_change_and_finite_to_unlimited_disk_need_staff_review(self) -> None:
        self.target(disk=20, bandwidth=50)
        self.target(disk=0)
        self.assertEqual(eligible_plan_targets(self.subscription), [])

    def test_template_change_or_setup_fee_is_not_a_plan_change_target(self) -> None:
        _, incompatible, _ = self.target()
        incompatible.features = {"template": "different"}
        incompatible.save(update_fields=["features"])
        self.target(setup_cents=500)
        self.assertEqual(eligible_plan_targets(self.subscription), [])

    def test_quarterly_price_must_be_explicit_and_never_guessed(self) -> None:
        self.subscription.billing_cycle = "quarterly"
        self.subscription.save(update_fields=["billing_cycle"])
        self.target()
        priced, _, _ = self.target(quarterly_price_cents=50000)
        choices = eligible_plan_targets(self.subscription)
        self.assertEqual([(item.product_id, item.period_price_cents) for item in choices], [(priced.pk, 50000)])
