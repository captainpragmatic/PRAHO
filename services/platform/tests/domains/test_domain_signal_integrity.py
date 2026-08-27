"""Domain post_save signal integrity: security events must reflect REAL changes.

store_original_domain_values used to stash lock/privacy as ``str(bool)`` while the
post_save comparison used real booleans — ``"True" != True`` — so EVERY Domain
update emitted spurious domain_lock_changed and whois_privacy_changed security
audit events, drowning the audit trail in noise and making the real events
indistinguishable from the false ones.
"""

from __future__ import annotations

from datetime import timedelta
from unittest.mock import patch

from django.test import TestCase
from django.utils import timezone

from apps.customers.models import Customer
from apps.domains.models import TLD, Domain, Registrar


class DomainSecuritySignalIntegrityTests(TestCase):
    def setUp(self) -> None:
        self.customer = Customer.objects.create(
            name="Signal Customer",
            company_name="Signal Customer SRL",
            customer_type="company",
            primary_email="signal@example.test",
        )
        self.tld = TLD.objects.create(
            extension="ro",
            description=".ro",
            registration_price_cents=1000,
            renewal_price_cents=1200,
            transfer_price_cents=800,
        )
        self.registrar = Registrar.objects.create(
            name="signal-registrar",
            display_name="Signal Registrar",
            website_url="https://signal.example.test",
            api_endpoint="https://api.signal.example.test",
        )
        self.domain = Domain.objects.create(
            name="signal-test.ro",
            tld=self.tld,
            registrar=self.registrar,
            customer=self.customer,
            status="active",
            locked=True,
            whois_privacy=False,
            expires_at=timezone.now() + timedelta(days=90),
        )

    def test_unrelated_update_emits_no_security_events(self) -> None:
        """Touching notes only must NOT emit lock/privacy security events."""
        with patch("apps.domains.signals.DomainsAuditService.log_domain_security_event") as mock_security:
            self.domain.notes = "routine bookkeeping"
            self.domain.save(update_fields=["notes", "updated_at"])

        emitted = [call.kwargs.get("event_type") for call in mock_security.call_args_list]
        self.assertEqual(
            emitted,
            [],
            f"Unrelated save emitted spurious security events: {emitted}",
        )

    def test_lock_toggle_emits_exactly_one_lock_event_with_boolean_values(self) -> None:
        with patch("apps.domains.signals.DomainsAuditService.log_domain_security_event") as mock_security:
            self.domain.locked = False
            self.domain.save(update_fields=["locked", "updated_at"])

        lock_calls = [
            call for call in mock_security.call_args_list if call.kwargs.get("event_type") == "domain_lock_changed"
        ]
        self.assertEqual(len(lock_calls), 1)
        metadata = lock_calls[0].kwargs["security_metadata"]
        self.assertIs(metadata["old_locked"], True)
        self.assertIs(metadata["new_locked"], False)
        privacy_calls = [
            call
            for call in mock_security.call_args_list
            if call.kwargs.get("event_type") == "whois_privacy_changed"
        ]
        self.assertEqual(privacy_calls, [])

    def test_privacy_toggle_emits_exactly_one_privacy_event(self) -> None:
        with patch("apps.domains.signals.DomainsAuditService.log_domain_security_event") as mock_security:
            self.domain.whois_privacy = True
            self.domain.save(update_fields=["whois_privacy", "updated_at"])

        privacy_calls = [
            call
            for call in mock_security.call_args_list
            if call.kwargs.get("event_type") == "whois_privacy_changed"
        ]
        self.assertEqual(len(privacy_calls), 1)
        metadata = privacy_calls[0].kwargs["security_metadata"]
        self.assertIs(metadata["old_privacy"], False)
        self.assertIs(metadata["new_privacy"], True)


class TLDPricingSignalIntegrityTests(TestCase):
    """Sibling of the Domain str/bool bug: TLD originals were stored as str(int),
    so every price-neutral TLD update looked like a pricing change and then blew
    up on ``int - str`` inside the change calculator (swallowed into an exception
    log)."""

    def setUp(self) -> None:
        self.tld = TLD.objects.create(
            extension="com",
            description=".com",
            registration_price_cents=1000,
            renewal_price_cents=1200,
            transfer_price_cents=800,
        )

    def test_non_price_update_does_not_trigger_pricing_change_handling(self) -> None:
        with patch("apps.domains.signals._handle_tld_pricing_change") as mock_pricing:
            self.tld.description = ".com — international"
            self.tld.save(update_fields=["description", "updated_at"])

        mock_pricing.assert_not_called()

    def test_price_update_triggers_pricing_change_handling_once(self) -> None:
        with patch("apps.domains.signals._handle_tld_pricing_change") as mock_pricing:
            self.tld.registration_price_cents = 1500
            self.tld.save(update_fields=["registration_price_cents", "updated_at"])

        mock_pricing.assert_called_once()
        _tld, old_values, new_values = mock_pricing.call_args.args
        self.assertEqual(old_values["registration_price_cents"], 1000)
        self.assertEqual(new_values["registration_price_cents"], 1500)
