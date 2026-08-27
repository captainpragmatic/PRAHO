"""Staff renewal-view idempotency-token regressions (#259).

The gateway's renewal idempotency key collapses distinct intents when no token
is supplied ({domain}:{years} with a 1h TTL). The order path passes the durable
``order_item:{pk}``; the staff renew view was the last tokenless caller. It now
issues one UUID per rendered form and forwards ``staff_renew:{uuid}`` so a
double-submit replays while a fresh form is a fresh intent.
"""

from __future__ import annotations

import uuid
from datetime import timedelta
from unittest.mock import call, patch

from django.contrib.auth import get_user_model
from django.test import Client, TestCase
from django.urls import reverse
from django.utils import timezone

from apps.common.types import Ok
from apps.customers.models import Customer
from apps.domains.models import TLD, Domain, Registrar

User = get_user_model()


class DomainRenewViewTokenTests(TestCase):
    def setUp(self) -> None:
        self.user = User.objects.create_user(
            email="renewal-token-staff@example.test",
            password="StrongPass123!",
            staff_role="support",
        )
        self.customer = Customer.objects.create(
            name="Renewal Token Customer",
            company_name="Renewal Token Customer SRL",
            customer_type="company",
            primary_email="renewal-token@example.test",
        )
        self.tld = TLD.objects.create(
            extension="ro",
            description=".ro",
            registration_price_cents=1000,
            renewal_price_cents=1200,
            transfer_price_cents=800,
        )
        self.registrar = Registrar.objects.create(
            name="renewal-token-registrar",
            display_name="Renewal Token Registrar",
            website_url="https://renew-token.example.test",
            api_endpoint="https://api.renew-token.example.test",
        )
        self.domain = Domain.objects.create(
            name="renew-token.ro",
            tld=self.tld,
            registrar=self.registrar,
            customer=self.customer,
            status="active",
            registrar_domain_id="RENEW-TOKEN-1",
            expires_at=timezone.now() + timedelta(days=90),
        )
        self.client = Client()
        self.client.force_login(self.user)
        self.renew_url = reverse("domains:renew", kwargs={"domain_id": self.domain.id})

    def test_get_renders_uuid_renewal_token_hidden_input(self) -> None:
        response = self.client.get(self.renew_url)

        self.assertEqual(response.status_code, 200)
        renewal_token = response.context["renewal_token"]
        self.assertEqual(str(uuid.UUID(renewal_token)), renewal_token)
        self.assertContains(
            response,
            f'<input type="hidden" name="renewal_token" value="{renewal_token}">',
            html=True,
        )

    def test_post_passes_scoped_valid_token_to_renewal_service(self) -> None:
        renewal_token = str(uuid.uuid4())

        with patch(
            "apps.domains.views.DomainLifecycleService.process_domain_renewal",
            return_value=Ok("renewed"),
        ) as mock_renew:
            response = self.client.post(
                self.renew_url,
                {"years": "1", "renewal_token": renewal_token},
            )

        self.assertEqual(response.status_code, 302)
        mock_renew.assert_called_once_with(
            domain=self.domain,
            years=1,
            idempotency_token=f"staff_renew:{renewal_token}",
        )

    def test_post_with_garbage_token_uses_legacy_tokenless_key(self) -> None:
        with patch(
            "apps.domains.views.DomainLifecycleService.process_domain_renewal",
            return_value=Ok("renewed"),
        ) as mock_renew:
            response = self.client.post(
                self.renew_url,
                {"years": "1", "renewal_token": "not-a-uuid"},
            )

        self.assertEqual(response.status_code, 302)
        mock_renew.assert_called_once_with(
            domain=self.domain,
            years=1,
            idempotency_token=None,
        )

    def test_repeated_posts_with_same_token_forward_same_idempotency_value(self) -> None:
        renewal_token = str(uuid.uuid4())
        expected_token = f"staff_renew:{renewal_token}"

        with patch(
            "apps.domains.views.DomainLifecycleService.process_domain_renewal",
            return_value=Ok("renewed"),
        ) as mock_renew:
            first_response = self.client.post(
                self.renew_url,
                {"years": "1", "renewal_token": renewal_token},
            )
            second_response = self.client.post(
                self.renew_url,
                {"years": "1", "renewal_token": renewal_token},
            )

        self.assertEqual(first_response.status_code, 302)
        self.assertEqual(second_response.status_code, 302)
        self.assertEqual(mock_renew.call_count, 2)
        mock_renew.assert_has_calls(
            [
                call(domain=self.domain, years=1, idempotency_token=expected_token),
                call(domain=self.domain, years=1, idempotency_token=expected_token),
            ]
        )

    def test_pending_renewal_surfaces_the_awaiting_confirmation_message(self) -> None:
        """A registrar-accepted (pending) renewal must not be reported as completed."""
        accepted_message = "Renewal accepted by the registrar and awaiting confirmation."

        with patch(
            "apps.domains.views.DomainLifecycleService.process_domain_renewal",
            return_value=Ok(accepted_message),
        ):
            response = self.client.post(
                self.renew_url,
                {"years": "1", "renewal_token": str(uuid.uuid4())},
                follow=True,
            )

        rendered_messages = [str(message) for message in response.context["messages"]]
        self.assertTrue(
            any(accepted_message in message for message in rendered_messages),
            rendered_messages,
        )
        self.assertFalse(
            any("renewed for" in message for message in rendered_messages),
            rendered_messages,
        )

    def test_rerender_preserves_the_submitted_token(self) -> None:
        """A re-rendered form is the SAME intent being corrected — issuing a fresh
        token there is the double-charge vector: an ambiguous registrar outcome
        holds the claim under token A, and a fresh token B on the error page would
        let an immediate resubmit issue a second chargeable renewal."""
        submitted_token = str(uuid.uuid4())

        with patch("apps.domains.views.DomainLifecycleService.process_domain_renewal") as mock_renew:
            response = self.client.post(
                self.renew_url,
                {"years": "not-a-number", "renewal_token": submitted_token},
            )

        self.assertEqual(response.status_code, 200)
        mock_renew.assert_not_called()
        self.assertEqual(response.context["renewal_token"], submitted_token)

    def test_registrar_failure_rerender_preserves_the_submitted_token(self) -> None:
        from apps.common.types import Err  # noqa: PLC0415

        submitted_token = str(uuid.uuid4())

        with patch(
            "apps.domains.views.DomainLifecycleService.process_domain_renewal",
            return_value=Err("registrar did not confirm"),
        ):
            response = self.client.post(
                self.renew_url,
                {"years": "1", "renewal_token": submitted_token},
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["renewal_token"], submitted_token)

    def test_garbage_token_rerender_issues_a_fresh_token(self) -> None:
        with patch("apps.domains.views.DomainLifecycleService.process_domain_renewal") as mock_renew:
            response = self.client.post(
                self.renew_url,
                {"years": "not-a-number", "renewal_token": "not-a-uuid"},
            )

        self.assertEqual(response.status_code, 200)
        mock_renew.assert_not_called()
        replacement_token = response.context["renewal_token"]
        self.assertNotEqual(replacement_token, "not-a-uuid")
        self.assertEqual(str(uuid.UUID(replacement_token)), replacement_token)
