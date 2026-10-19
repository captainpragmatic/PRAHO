"""The customer is told once that their hosting name is live (ADR-0061 P1.12).

The email goes after the first sync that publishes the name with its certificate installed, never
before, and never twice: the claim on `activation_notified_at` is taken under the row lock, and the
message is sent only once that claim commits. A send that fails gives the claim back, so a later
sync tries again. Nothing in it names a node or an address.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

from django.core import mail
from django.core.management import call_command
from django.utils import timezone

from apps.notifications.services import EmailResult
from apps.provisioning import account_hostname_service as service
from apps.provisioning.account_hostname_hosting import ACTIVATION_TEMPLATE
from apps.provisioning.account_hostname_models import AccountHostname, AccountNameCertificateInstall
from tests.notifications.test_template_key_consistency import _extract_setup_template_keys
from tests.provisioning.test_account_hostname_service import DOMAIN, ZONE, AccountNameTestCase, FakeDnsGateway


class ActivationEmailTests(AccountNameTestCase):
    def setUp(self) -> None:
        super().setUp()
        FakeDnsGateway.reset({"0123456789abcdef0123456789abcdef": ZONE})
        from apps.infrastructure.dns_gateway import _DNS_PROVIDER_REGISTRY, register_dns_gateway  # noqa: PLC0415

        previous = _DNS_PROVIDER_REGISTRY.get(service.DNS_PROVIDER)
        register_dns_gateway(service.DNS_PROVIDER, FakeDnsGateway)
        self.addCleanup(lambda: register_dns_gateway(service.DNS_PROVIDER, previous) if previous else None)
        from apps.settings.services import SettingsService  # noqa: PLC0415

        SettingsService.update_setting("dns.account_hostnames_enabled", True).unwrap()
        AccountHostname.objects.filter(pk=self.hostname.pk).update(target_server=self.server)
        self.hostname.refresh_from_db()
        call_command("setup_email_templates", verbosity=0)
        self.customer.primary_email = "owner@customer.example.com"
        self.customer.save(update_fields=["primary_email"])

    def _certificate_installed(self) -> None:
        AccountNameCertificateInstall.objects.create(
            hostname=self.hostname,
            server=self.server,
            certificate_ref="acme_certificate:x",
            not_after=timezone.now() + timezone.timedelta(days=60),
        )

    def _sync(self) -> Any:
        with self.captureOnCommitCallbacks(execute=True):
            return service.sync_account_hostname(self.hostname).unwrap()

    def test_the_first_live_sync_tells_the_customer_once(self) -> None:
        self._certificate_installed()

        self.assertEqual(self._sync(), "published")
        self.assertEqual(self._sync(), "published")

        self.assertEqual(len(mail.outbox), 1)
        message = mail.outbox[0]
        self.assertEqual(message.to, ["owner@customer.example.com"])
        body = message.body + str(message.alternatives)
        self.assertIn(self.hostname.fqdn, body)
        self.assertIn(f"www.{DOMAIN}", body)
        for secret in ("95.217.0.10", "2a01:4f8::1", self.server.hostname):
            self.assertNotIn(secret, body)
        self.hostname.refresh_from_db()
        self.assertIsNotNone(self.hostname.activation_notified_at)

    def test_nothing_is_said_before_the_name_is_live(self) -> None:
        self.assertEqual(self._sync(), "skipped:certificate_not_ready")

        self.assertEqual(mail.outbox, [])
        self.hostname.refresh_from_db()
        self.assertIsNone(self.hostname.activation_notified_at)

    def test_a_send_that_fails_gives_the_claim_back_for_the_next_sync(self) -> None:
        self._certificate_installed()
        with patch(
            "apps.notifications.services.EmailService.send_template_email",
            return_value=EmailResult(success=False, error="smtp down"),
        ):
            self._sync()
        self.hostname.refresh_from_db()
        self.assertIsNone(self.hostname.activation_notified_at)

        self._sync()

        self.assertEqual(len(mail.outbox), 1)

    def test_a_claim_already_taken_sends_nothing(self) -> None:
        self._certificate_installed()
        AccountHostname.objects.filter(pk=self.hostname.pk).update(activation_notified_at=timezone.now())

        self._sync()

        self.assertEqual(mail.outbox, [])

    def test_a_suspended_account_is_not_told(self) -> None:
        self._certificate_installed()
        type(self.account).objects.filter(pk=self.account.pk).update(status="suspended")

        self._sync()

        self.assertEqual(mail.outbox, [])

    def test_the_template_is_seeded_in_both_languages(self) -> None:
        from apps.notifications.models import EmailTemplate  # noqa: PLC0415

        self.assertIn(ACTIVATION_TEMPLATE, _extract_setup_template_keys())
        self.assertEqual(
            set(EmailTemplate.objects.filter(key=ACTIVATION_TEMPLATE).values_list("locale", flat=True)), {"en", "ro"}
        )
