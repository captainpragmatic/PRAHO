"""The register view must not report a 202-accepted registration as a failure.

create_domain_registration returns Err for the accepted-but-unconfirmed outcome
(its Ok contract means "active"), but the staff-facing message must distinguish
"the registrar accepted this and the reconciler will finish it" from a real
rejection — a customer-facing 'Registration failed' for an accepted, chargeable
registration is a lie the reconciliation worker later makes obviously wrong.
"""

from __future__ import annotations

from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.contrib.messages import get_messages
from django.test import Client, TestCase
from django.urls import reverse

from apps.common.types import Err
from apps.customers.models import Customer
from apps.domains.models import TLD
from apps.domains.services import REGISTRATION_PENDING_MESSAGE

User = get_user_model()


class DomainRegisterViewPendingMessageTests(TestCase):
    def setUp(self) -> None:
        self.user = User.objects.create_user(
            email="register-pending-staff@example.test",
            password="StrongPass123!",
            staff_role="support",
        )
        self.customer = Customer.objects.create(
            name="Pending Register Customer",
            company_name="Pending Register SRL",
            customer_type="company",
            primary_email="pending-register@example.test",
        )
        TLD.objects.create(
            extension="ro",
            description=".ro",
            registration_price_cents=1000,
            renewal_price_cents=1200,
            transfer_price_cents=800,
        )
        self.client = Client()
        self.client.force_login(self.user)

    def test_accepted_registration_is_reported_as_pending_not_failed(self) -> None:
        with patch(
            "apps.domains.views.DomainLifecycleService.create_domain_registration",
            return_value=Err(str(REGISTRATION_PENDING_MESSAGE)),
        ):
            response = self.client.post(
                reverse("domains:register"),
                {
                    "domain_name": "accepted-pending.ro",
                    "customer_id": str(self.customer.pk),
                    "years": "1",
                },
            )

        rendered = [(m.level_tag, str(m)) for m in get_messages(response.wsgi_request)]
        self.assertTrue(
            any(str(REGISTRATION_PENDING_MESSAGE) in body for _tag, body in rendered),
            rendered,
        )
        self.assertFalse(
            any("Registration failed" in body for _tag, body in rendered),
            rendered,
        )
