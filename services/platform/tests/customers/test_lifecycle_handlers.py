"""The customer status handlers, which no code ever triggered before staff could change a status (ADR-0066).

Each one is driven here through its real transition or called the way its post-commit callback calls
it, and the assertion is the state it leaves behind.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

from django.core.management import call_command

from apps.customers.models import Customer
from apps.customers.signals import (
    CUSTOMER_SUSPENSION_REASON,
    _handle_customer_activation,
    _resume_cascade_suspended_services,
    _send_customer_activation_email,
    _send_customer_deactivation_email,
    _send_customer_suspension_email,
    _send_customer_welcome_email,
    _suspend_customer_services,
)
from apps.notifications.models import EmailTemplate
from apps.notifications.services import render_template_safely
from apps.provisioning.models import Service
from tests.customers.test_customer_suspension_cascade import CustomerCascadeFixture
from tests.helpers.fsm_helpers import force_status


class CustomerLifecycleHandlerTests(CustomerCascadeFixture):
    def test_activating_a_prospect_turns_none_of_its_services_on(self) -> None:
        # Orders and billing own fulfilment. Activation once switched on every pending service,
        # paid or not, and raced the paid order's own confirmation.
        Customer.objects.filter(pk=self.customer.pk).update(status="prospect")
        paid = self._service(domain="paid-order.example.com", status="pending")
        unpaid = self._service(domain="unpaid-order.example.com", status="pending")
        self.customer.refresh_from_db()
        with (
            patch("apps.notifications.services.EmailService.send_template_email"),
            self.captureOnCommitCallbacks(execute=True),
        ):
            self.customer.activate()
            self.customer.save()
        self.customer.refresh_from_db()
        self.assertEqual(self.customer.status, "active")
        for service in (paid, unpaid):
            service.refresh_from_db()
            self.assertEqual(service.status, "pending", service.domain)

    def test_a_suspend_cascade_that_runs_after_the_unsuspension_changes_nothing(self) -> None:
        # The cascade runs after the suspension commits. Staff may have unsuspended in between.
        service = self._service(domain="late-suspend.example.com")
        self.assertEqual(self.customer.status, "active")
        _suspend_customer_services(self.customer)
        service.refresh_from_db()
        self.assertEqual(service.status, "active")

    def test_a_resume_cascade_that_runs_after_a_new_suspension_changes_nothing(self) -> None:
        service = self._service(domain="late-resume.example.com")
        force_status(service, "suspended")
        Service.objects.filter(pk=service.pk).update(suspension_reason=CUSTOMER_SUSPENSION_REASON)
        Customer.objects.filter(pk=self.customer.pk).update(status="suspended")
        self.customer.refresh_from_db()
        _resume_cascade_suspended_services(self.customer)
        service.refresh_from_db()
        self.assertEqual((service.status, service.suspension_reason), ("suspended", CUSTOMER_SUSPENSION_REASON))

    def test_the_activation_handler_queues_only_its_email(self) -> None:
        with self.captureOnCommitCallbacks() as callbacks:
            _handle_customer_activation(self.customer)
        self.assertEqual(len(callbacks), 1)


class CustomerStatusEmailTests(CustomerCascadeFixture):
    """Each status email renders its seeded template with the customer's name."""

    def setUp(self) -> None:
        super().setUp()
        call_command("setup_email_templates", verbosity=0)
        self.rendered: dict[str, str] = {}

        def render(*, template_key: str, context: dict[str, Any], **_kwargs: Any) -> None:
            template = EmailTemplate.objects.get(key=template_key, locale="en")
            self.rendered[template_key] = render_template_safely(
                template.body_html, {**context, "brand_name": "PRAHO", "support_email": "help@example.test"}
            )

        patcher = patch("apps.notifications.services.EmailService.send_template_email", side_effect=render)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_every_status_email_greets_the_customer_by_name(self) -> None:
        name = self.customer.get_display_name()
        for key, send in (
            ("customer_welcome", _send_customer_welcome_email),
            ("customer_activated", _send_customer_activation_email),
            ("customer_suspended", _send_customer_suspension_email),
            ("customer_deactivated", _send_customer_deactivation_email),
        ):
            with self.subTest(key):
                send(self.customer)
                self.assertIn(f"Hello {name},", self.rendered[key])

    def test_the_activation_email_does_not_invite_a_first_order(self) -> None:
        # A prospect becomes active by paying, so it has already ordered.
        _send_customer_activation_email(self.customer)
        self.assertNotIn("You can now order hosting services", self.rendered["customer_activated"])
