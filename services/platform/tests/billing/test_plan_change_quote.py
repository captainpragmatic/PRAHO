"""Quote money and fiscal documents are frozen without embedding buyer identity."""

import json
from decimal import Decimal
from uuid import uuid4

from django.core.exceptions import ValidationError
from django.test import TestCase

from apps.billing.models import ProformaInvoice
from apps.billing.plan_change_quote_service import (
    _build_quote,
    _commercial_context,
    _confirm_new_quote,
    _tax_quote,
    plan_change_options,
)
from apps.customers.profile_models import CustomerTaxProfile
from apps.products.models import Product, ProductPrice, ProductRelationship
from apps.provisioning.hosting_limit_assignments import request_service_plan_change
from apps.provisioning.models import ServicePlan
from apps.settings.services import SettingsService
from apps.users.models import CustomerMembership
from tests.billing.test_plan_change_intervals import _PlanChangeCoverageFixture


class PlanChangeQuoteCoreTests(_PlanChangeCoverageFixture, TestCase):
    def setUp(self):
        super().setUp()
        CustomerTaxProfile.objects.create(customer=self.customer, is_vat_payer=True, vat_rate=Decimal("21"))
        self.customer.refresh_from_db()

    def test_tax_quote_uses_canonical_line_rounding_and_stores_no_buyer_identity(self):
        result = _tax_quote(self.customer, [11, 11])
        self.assertEqual((result["net_cents"], result["tax_cents"], result["total_cents"]), (22, 4, 26))
        self.assertEqual(result["taxes"], [2, 2])
        self.assertNotIn(self.customer.name, json.dumps(result))
        self.assertNotIn("vat_number", json.dumps(result))

    def test_public_options_fail_closed_without_managed_native_proof(self):
        self.assertTrue(SettingsService.update_setting("billing.hosting_plan_changes_enabled", True).is_ok())
        CustomerMembership.objects.create(customer=self.customer, user=self.actor, role="owner", is_active=True)
        with self.assertRaises(ValidationError):
            plan_change_options(self.service.pk, customer_id=self.customer.pk, actor_id=self.actor.pk)

    def target(self, *, reverse=False, price=20000):
        CustomerMembership.objects.create(customer=self.customer, user=self.actor, role="owner", is_active=True)
        self.plan.disk_space_gb, self.plan.bandwidth_gb = 10, 100
        self.plan.save(update_fields=["disk_space_gb", "bandwidth_gb"])
        self.product.module = "virtualmin"
        self.product.save(update_fields=["module"])
        request_service_plan_change(
            service=self.service,
            target_plan_id=self.plan.pk,
            expected_revision=1,
            submission_id=uuid4(),
            reason="Explicit assigned catalog fixture",
            authority={"kind": "staff_resource_override"},
        )
        plan = ServicePlan.objects.create(
            name="Target",
            plan_type="shared_hosting",
            price_monthly=200,
            disk_space_gb=5 if reverse else 20,
            bandwidth_gb=50 if reverse else 200,
        )
        product = Product.objects.create(
            name="Target", slug="quoted-target", product_type="hosting", module="virtualmin", default_service_plan=plan
        )
        ProductPrice.objects.create(product=product, currency=self.currency, monthly_price_cents=price)
        ProductRelationship.objects.create(
            source_product=product if reverse else self.product,
            target_product=self.product if reverse else product,
            relationship_type="upgrades_to",
        )
        return product

    def core_quote(self, target, *, submission_id=None):
        # This tests the commercial core under its REAL row locks. Public native
        # admission remains separately fail-closed; no mocked validator grants it.
        with _commercial_context(self.service.pk, customer_id=self.customer.pk, actor_id=self.actor.pk) as context:
            return _build_quote(
                *context,
                actor_id=self.actor.pk,
                target_product_id=target.pk,
                submission_id=submission_id or uuid4(),
                expected_limit_revision=2,
                at=self.now,
            )

    def test_core_quote_and_confirmation_create_one_standalone_fiscal_document(self):
        target = self.target()
        self.cycle()
        change = self.core_quote(target)
        self.assertEqual((change.net_cents, change.tax_cents, change.total_cents), (6000, 1260, 7260))
        with _commercial_context(self.service.pk, customer_id=self.customer.pk, actor_id=self.actor.pk) as context:
            _confirm_new_quote(change, *context, at=self.now, accept_zero_due=False)
        change.refresh_from_db()
        self.assertIsNotNone(change.proforma_id)
        proforma = change.proforma
        self.assertTrue(proforma.number.startswith("PRO-PC-"))
        self.assertEqual((proforma.subtotal_cents, proforma.tax_cents, proforma.total_cents), (6000, 1260, 7260))
        line = proforma.lines.get()
        self.assertEqual(line.quantity, 1)
        self.assertIsNone(line.billing_cycle_id)
        self.assertEqual(line.service_id, self.service.pk)
        self.assertEqual(change.status, "awaiting_payment")

    def test_core_idempotency_does_not_reprice_after_catalog_edit(self):
        target = self.target()
        self.cycle()
        submission_id = uuid4()
        original = self.core_quote(target, submission_id=submission_id)
        ProductPrice.objects.filter(product=target).update(monthly_price_cents=99999)
        replay = self.core_quote(target, submission_id=submission_id)
        self.assertEqual(replay.pk, original.pk)
        self.assertEqual(replay.target_period_price_cents, 20000)
        self.assertEqual(ProformaInvoice.objects.count(), 0)
