"""Real quote→confirmation→claim→Stripe SDK seam with persisted native capability."""

import hashlib
import hmac
import json
import logging
import secrets
import time
from datetime import timedelta
from decimal import Decimal
from types import SimpleNamespace
from unittest.mock import MagicMock, patch
from uuid import uuid4

import stripe
from django.utils import timezone

from apps.billing.gateways.stripe_gateway import StripeGateway
from apps.billing.models import InvoiceSequence, Subscription
from apps.billing.plan_change_models import PlanChange
from apps.billing.plan_change_payment_models import PlanChangePaymentAttempt
from apps.billing.plan_change_payment_service import (
    reserve_plan_change_payment,
    submit_plan_change_payment,
)
from apps.billing.plan_change_quote_service import confirm_plan_change, quote_plan_change
from apps.customers.profile_models import CustomerTaxProfile
from apps.integrations.models import WebhookEvent
from apps.integrations.webhooks.stripe import StripeWebhookProcessor
from apps.products.models import Product, ProductPrice, ProductRelationship
from apps.provisioning.hosting_limit_execution import apply_hosting_limits
from apps.provisioning.models import ServicePlan
from apps.settings.services import SettingsService
from apps.users.models import CustomerMembership, User
from tests.billing.test_plan_change_intervals import _PlanChangeCoverageFixture
from tests.helpers.task_queue import quiet_task_queue
from tests.provisioning import test_hosting_limit_surfaces as native_surfaces
from tests.provisioning.test_hosting_limit_execution import HostingLimitWorkerFixture
from tests.provisioning.test_virtualmin_tasks import VirtualminTaskTestBase


class VerifiedPlanChangeCheckoutFixture:
    period_remaining = timedelta(days=15)
    receipt = HostingLimitWorkerFixture.receipt
    cycle = _PlanChangeCoverageFixture.cycle
    publish_usage = native_surfaces.VerifiedHostingLimitSurfaceTests.publish_usage

    def setUp(self) -> None:
        quiet_task_queue(self)
        VirtualminTaskTestBase.setUp(self)
        HostingLimitWorkerFixture.setup_native_fixture(self)
        self.identity = self.native_identity
        self.publish_usage(1, 1)
        with (
            patch("apps.provisioning.hosting_limit_transport.probe_account_quota", return_value=self.receipt()),
            patch(
                "apps.provisioning.hosting_limit_transport.run_quota_operation",
                side_effect=lambda server, action, request: self.receipt(
                    cap=request["disk_limit_kib"] // 1024, request=request
                ),
            ),
        ):
            self.assertEqual(apply_hosting_limits(self.application.pk), "completed")
        self.setup_commercial_fixture()

    def setup_commercial_fixture(self) -> None:
        """Add real commercial evidence to an already-qualified managed account."""
        self.service.refresh_from_db()
        self.plan = self.service.service_plan
        self.now = timezone.now()
        self.actor = User.objects.create_user(email="checkout-billing@example.test")
        CustomerMembership.objects.create(customer=self.customer, user=self.actor, role="billing", is_active=True)
        CustomerTaxProfile.objects.create(customer=self.customer, is_vat_payer=True, vat_rate=Decimal("21"))
        self.customer.refresh_from_db()
        self.product = Product.objects.create(
            name="Verified base",
            slug="checkout-base",
            product_type="hosting",
            module="virtualmin",
            default_service_plan=self.plan,
        )
        self.subscription = Subscription.objects.create(
            customer=self.customer,
            product=self.product,
            service=self.service,
            currency=self.currency,
            subscription_number="SUB-REAL-CHECKOUT",
            unit_price_cents=8000,
            status="active",
            quantity=1,
            current_period_start=self.now + self.period_remaining - timedelta(days=30),
            current_period_end=self.now + self.period_remaining,
            next_billing_date=self.now + self.period_remaining,
        )
        InvoiceSequence.objects.get_or_create(scope="default", defaults={"prefix": "INV"})
        self.cycle()
        target_plan = ServicePlan.objects.create(
            name="Checkout target", plan_type="shared_hosting", price_monthly=200, disk_space_gb=20, bandwidth_gb=100
        )
        self.target = Product.objects.create(
            name="Checkout target",
            slug="checkout-target",
            product_type="hosting",
            module="virtualmin",
            default_service_plan=target_plan,
        )
        ProductPrice.objects.create(product=self.target, currency=self.currency, monthly_price_cents=20000)
        ProductRelationship.objects.create(
            source_product=self.product, target_product=self.target, relationship_type="upgrades_to"
        )
        self.assertTrue(SettingsService.update_setting("billing.hosting_plan_changes_enabled", True).is_ok())

    def quote(self) -> PlanChange:
        return quote_plan_change(
            self.service.pk,
            customer_id=self.customer.pk,
            actor_id=self.actor.pk,
            target_product_id=self.target.pk,
            submission_id=uuid4(),
            expected_limit_revision=2,
            at=self.now,
        )

    def confirm(self, change: PlanChange) -> PlanChange:
        return confirm_plan_change(
            change.pk,
            customer_id=self.customer.pk,
            actor_id=self.actor.pk,
            expected_fingerprint=change.request_fingerprint,
        )

    def ready_attempt(self) -> tuple[PlanChange, PlanChangePaymentAttempt, MagicMock]:
        change = self.confirm(self.quote())
        attempt = reserve_plan_change_payment(
            change.pk,
            customer_id=self.customer.pk,
            actor_id=self.actor.pk,
            expected_fingerprint=change.request_fingerprint,
        )
        sdk = MagicMock()
        sdk.error = stripe.error
        sdk.PaymentIntent.create.return_value = SimpleNamespace(
            id="pi_signed_plan",
            client_secret="opaque-provider-secret",  # noqa: S106 -- Synthetic provider boundary response.
        )
        gateway = StripeGateway.__new__(StripeGateway)
        gateway._stripe, gateway.logger = sdk, logging.getLogger("test.signed-plan")
        with patch("apps.billing.plan_change_payment_service._gateway", return_value=gateway):
            self.assertEqual(submit_plan_change_payment(attempt.pk)["state"], "ready")
        return change, attempt, sdk

    def signed_delivery(
        self, metadata: dict[str, str], *, valid: bool = True, status: str = "succeeded"
    ) -> tuple[bool, str, WebhookEvent | None]:
        payload = {
            "id": f"evt_plan_{uuid4().hex}",
            "type": f"payment_intent.{status}",
            "api_version": "2023-10-16",
            "data": {
                "object": {
                    "id": "pi_signed_plan",
                    "status": status,
                    "amount": 7260,
                    "amount_received": 7260 if status == "succeeded" else 0,
                    "currency": "ron",
                    "customer": None,
                    "metadata": metadata,
                    "client_secret": "opaque-provider-secret",
                }
            },
        }
        return self.deliver_signed_payload(payload, valid=valid)

    def deliver_signed_payload(
        self, payload: dict[str, object], *, valid: bool = True
    ) -> tuple[bool, str, WebhookEvent | None]:
        secret = secrets.token_hex(32)
        self.assertTrue(SettingsService.update_setting("integrations.stripe_webhook_secret", secret).is_ok())
        body = json.dumps(payload).encode()
        timestamp = str(int(time.time()))
        digest = hmac.new(secret.encode(), timestamp.encode() + b"." + body, hashlib.sha256).hexdigest()
        return StripeWebhookProcessor().process_webhook(
            payload, signature=f"t={timestamp},v1={digest if valid else 'bad'}", raw_body=body
        )
