"""A stored email no key can decrypt is never proof of a domain currency notice, and never stops a lookup.

A notice is accepted only on an email whose body is exactly the offer's. One email stored under a
superseded format raised DecryptionError: the lookup over the offer's emails stopped at it, and the
acceptance escaped the ValidationError its callers handle (#751 follow-up, secret consumers).
"""

from __future__ import annotations

from datetime import timedelta

from django.core.exceptions import ValidationError
from django.test import TestCase
from django.utils import timezone

from apps.domains.currency_terms import _accepted_notice_email
from apps.domains.models import DomainCurrencyTransition
from apps.notifications.models import EmailLog
from tests.domains.test_currency_terms_lifecycle import DomainCurrencyFixture

LEGACY_CIPHERTEXT = "aes:v1:bm90LXJlYWRhYmxl"


class UnreadableNoticeProofTests(DomainCurrencyFixture, TestCase):
    def setUp(self) -> None:
        super().setUp()
        self.offer = DomainCurrencyTransition.objects.create(
            domain=self.domain,
            policy_revision=1,
            old_terms={},
            target_terms={},
            target_fingerprint="0" * 64,
            notice_recipient="owner@example.test",
            notice_subject="Your domain renews in EUR",
            notice_body="Exact notice text",
            notice_attempted_at=timezone.now() - timedelta(minutes=5),
        )

    def _email(self, *, readable: bool) -> EmailLog:
        log = EmailLog.objects.create(
            customer_id=self.domain.customer_id,
            to_addr=self.offer.notice_recipient,
            subject=self.offer.notice_subject,
            body_text=self.offer.notice_body,
            template_key=f"domain_currency_notice:{self.offer.pk}",
            status="sent",
        )
        if not readable:
            EmailLog.objects.filter(pk=log.pk).update(body_text=LEGACY_CIPHERTEXT)
        return EmailLog.objects.get(pk=log.pk)

    def test_the_lookup_skips_an_unreadable_email_and_finds_the_proof(self) -> None:
        self._email(readable=False)
        proof = self._email(readable=True)

        try:
            found = _accepted_notice_email(self.offer)
        except Exception as error:
            self.fail(f"one unreadable email must not stop the lookup ({type(error).__name__})")

        self.assertEqual(found, proof)

    def test_an_unreadable_email_is_refused_as_proof(self) -> None:
        self.offer.notice_email = self._email(readable=False)

        try:
            self.offer.accept_notice()
        except ValidationError:
            pass
        except Exception as error:
            self.fail(f"an unreadable proof must be refused as a mismatch, not raise {type(error).__name__}")
        else:
            self.fail("an unreadable email was accepted as proof")
