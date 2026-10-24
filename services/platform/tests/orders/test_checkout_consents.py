"""What a customer accepts at checkout, recorded with the order and sent to them (ADR-0062).

The portal asked for the terms and sent nothing: the order recorded no acceptance. An order now
names the Terms of Service release its customer accepted, and an EU consumer must ask for the
services to start within the 14-day withdrawal period. The confirmation email is the durable copy:
it attaches that release and states the request.
"""

from __future__ import annotations

import json
import secrets
import uuid
from io import StringIO
from typing import Any
from unittest.mock import patch

from django.core import mail
from django.core.cache import cache
from django.core.management import call_command
from django.test import RequestFactory, TestCase, override_settings

from apps.audit.models import AuditEvent
from apps.billing.models import Currency
from apps.customers.models import Customer
from apps.orders.models import Order
from apps.products.models import Product, ProductPrice
from tests.helpers.legal import publish_release
from tests.helpers.task_queue import run_queued


@override_settings(COMPANY_COUNTRY_CODE="RO")
class CheckoutConsentTests(TestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        call_command("setup_email_templates", stdout=StringIO())
        self.terms = publish_release(body_markdown="## Hosting terms\n\nSample, not legal text.")
        currency, _ = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei", "decimals": 2})
        self.product = Product.objects.create(
            slug="consent-hosting", name="Consent Hosting", product_type="shared_hosting", is_active=True, is_public=True
        )
        ProductPrice.objects.create(product=self.product, currency=currency, monthly_price_cents=2500, is_active=True)
        self.consumer = Customer.objects.create(
            name="Ana Pop", customer_type="individual", primary_email="ana@example.test", status="active"
        )

    def place(self, customer: Customer, **consents: Any) -> tuple[int, dict[str, Any]]:
        from apps.api.orders.views import create_order  # noqa: PLC0415

        key = secrets.token_urlsafe(32)
        body = {
            "customer_id": customer.id,
            "items": [{"product_slug": self.product.slug, "quantity": 1, "billing_period": "monthly"}],
            "currency": "RON",
            "currency_revision": 1,
            **consents,
        }
        request = RequestFactory().post(
            "/api/orders/create/", data=json.dumps(body, default=str), content_type="application/json",
            HTTP_IDEMPOTENCY_KEY=key,
        )
        with (
            patch("apps.api.secure_auth.get_authenticated_customer", return_value=(customer, None)),
            self.captureOnCommitCallbacks(execute=True),
        ):
            response = create_order(request)
        return response.status_code, response.data  # type: ignore[union-attr]  # DRF Response

    def test_consumer_order_requires_early_start_and_current_terms_document_and_email_attaches_that_document(
        self,
    ) -> None:
        accepted = {"terms_document_id": str(self.terms.pk)}
        refusals = (
            ({}, 400, "terms_required"),
            ({"terms_document_id": str(uuid.uuid4())}, 409, "terms_changed"),  # No such release
            (accepted, 400, "early_start_required"),  # An EU consumer must ask for an early start
        )
        for consents, status, code in refusals:
            with self.subTest(code=code):
                answer, data = self.place(self.consumer, **consents)
                self.assertEqual((answer, data.get("code")), (status, code))
        self.assertFalse(Order.objects.exists())

        superseded = self.terms
        self.terms = publish_release(body_markdown="## Newer hosting terms")
        self.assertEqual(self.place(self.consumer, terms_document_id=str(superseded.pk))[1]["code"], "terms_changed")

        mail.outbox.clear()
        status, data = self.place(self.consumer, terms_document_id=str(self.terms.pk), early_start_requested=True)
        self.assertEqual(status, 201, data)
        order = Order.objects.get(pk=data["order"]["id"])
        self.assertEqual(order.terms_document, self.terms)
        self.assertTrue(order.early_start_requested)
        accepted_event = AuditEvent.objects.get(action="order_terms_accepted", object_id=str(order.pk))
        self.assertEqual(accepted_event.metadata["terms_document"], self.terms.reference())
        self.assertTrue(AuditEvent.objects.filter(action="early_performance_requested", object_id=str(order.pk)).exists())

        run_queued("apps.notifications.tasks.send_email_task")  # As the worker sends it
        [message] = [m for m in mail.outbox if order.order_number in m.subject]
        self.assertIn(order.order_number, message.body)
        self.assertIn(str(order.total), message.body)  # The template's values reach the email
        # It states the early-start request, in whichever language the email goes out in.
        stated = ("start your services now", "începem furnizarea serviciilor")
        self.assertTrue(any(phrase in message.body for phrase in stated), message.body)
        [(filename, content, mimetype)] = message.attachments
        self.assertEqual((filename, mimetype), (f"terms-{self.terms.release}.html", "text/html"))
        self.assertIn("Newer hosting terms", content if isinstance(content, str) else content.decode())

    def test_a_business_customer_needs_no_early_start_request(self) -> None:
        business = Customer.objects.create(
            name="Firma SRL", customer_type="company", company_name="Firma SRL", primary_email="firma@example.test",
            status="active",
        )
        status, data = self.place(business, terms_document_id=str(self.terms.pk))
        self.assertEqual(status, 201, data)
        self.assertFalse(Order.objects.get(pk=data["order"]["id"]).early_start_requested)

    def test_the_order_records_its_first_touch_attribution_cleaned(self) -> None:
        # Sent with every order by the portal; the fields existed but nothing filled them.
        status, data = self.place(
            self.consumer,
            terms_document_id=str(self.terms.pk),
            early_start_requested=True,
            attribution={
                "utm_source": "newsletter",
                "utm_campaign": "autumn",
                "referrer": "https://blog.example.com/post?x=1",
                "product": "not-attribution",
            },
        )
        self.assertEqual(status, 201, data)
        order = Order.objects.get(pk=data["order"]["id"])
        self.assertEqual(
            (order.utm_source, order.utm_medium, order.utm_campaign, order.referrer),
            ("newsletter", "", "autumn", "https://blog.example.com"),
        )

    def test_an_order_placed_while_no_terms_are_in_force_is_refused(self) -> None:
        with (
            patch("apps.orders.checkout_consents.legal_document_in_force", return_value=None),
            patch("apps.orders.checkout_consents.any_legal_document_in_force", return_value=False),
        ):
            status, data = self.place(self.consumer, terms_document_id=str(self.terms.pk), early_start_requested=True)
        self.assertEqual((status, data["code"]), (409, "terms_unavailable"))

    def test_the_completion_email_names_the_order(self) -> None:
        from apps.orders.signals import _send_order_completed_email  # noqa: PLC0415

        # Email tasks are published when the row commits.
        with self.captureOnCommitCallbacks(execute=True):
            status, data = self.place(self.consumer, terms_document_id=str(self.terms.pk), early_start_requested=True)
        self.assertEqual(status, 201, data)
        order = Order.objects.get(pk=data["order"]["id"])
        run_queued("apps.notifications.tasks.send_email_task")  # The confirmation sent when it was placed
        mail.outbox.clear()
        with self.captureOnCommitCallbacks(execute=True):
            _send_order_completed_email(order)
        run_queued("apps.notifications.tasks.send_email_task")
        [message] = mail.outbox
        self.assertIn(order.order_number, message.body)  # Blank before: the template's values were never passed
        self.assertIn(order.customer_name, message.body)
