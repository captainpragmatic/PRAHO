"""The account holder is told by email when 2FA or the password changes (#689).

The notification preferences promise "security alerts (login attempts, 2FA)", but enabling,
disabling or resetting 2FA, regenerating backup codes and changing the password sent nothing.
The chokepoint every path goes through now writes the notice, so the staff pages, the Portal's
API and the operator command are all covered. A notice that cannot be written never undoes or
hides the change itself.

The notice is a queued email written in the change's own transaction, so the email queue
delivers it and retries it. It used to be queued only after the commit: a notice whose queueing
failed, or whose send failed, was lost.
"""

from __future__ import annotations

from unittest.mock import patch

from django.core import mail
from django.db import DatabaseError, transaction
from django.test import TestCase
from django.urls import reverse

from apps.notifications.models import EmailLog
from apps.notifications.services import EmailService, EmailSuppressionService
from apps.notifications.tasks import send_email_task
from apps.users.forms import apply_password_change
from apps.users.mfa import MFAService, TOTPService
from apps.users.models import User, UserProfile
from apps.users.tasks import deliver_security_notice

PASSWORD = "Original-secure123!"  # test fixture, not a credential
SEND = "apps.notifications.services.EmailService.send_email"


def _enrolled(email: str) -> User:
    user = User.objects.create_user(email=email, password=PASSWORD, first_name="Ana")
    user.two_factor_secret = TOTPService.generate_secret()
    user.two_factor_enabled = True
    user.save()
    return user


def _notices() -> list[tuple[str, str, str]]:
    rows = EmailLog.objects.filter(template_key__startswith="security_notice:").order_by("sent_at")
    return [(row.to_addr, row.template_key.removeprefix("security_notice:"), row.status) for row in rows]


def _deliver() -> None:
    """Run the email queue's send task for every queued notice, as its worker would."""
    for pk in EmailLog.objects.filter(template_key__startswith="security_notice:", status="queued").values_list(
        "pk", flat=True
    ):
        send_email_task(str(pk))


class NoticesWrittenTests(TestCase):
    def test_each_change_writes_exactly_one_queued_notice(self) -> None:
        user = User.objects.create_user(email="notice@example.ro", password=PASSWORD)
        admin = User.objects.create_user(email="admin@example.ro", password=PASSWORD, staff_role="admin")
        enrolled = _enrolled("enrolled@example.ro")
        cases = {
            "2fa_enabled": (user, lambda: MFAService.enable_totp(user, None)),
            "backup_codes": (user, lambda: MFAService.generate_backup_codes(User.objects.get(pk=user.pk))),
            "2fa_disabled": (user, lambda: MFAService.disable_totp(User.objects.get(pk=user.pk))),
            "2fa_reset": (enrolled, lambda: MFAService.disable_totp(enrolled, admin_user=admin)),
            "password_changed": (
                user,
                lambda: apply_password_change(
                    user.pk, "Brand-new-password-456!", still_authorised=lambda _locked: True
                ),
            ),
        }
        for event, (account, change) in cases.items():
            with self.subTest(event=event):
                EmailLog.objects.all().delete()
                change()  # no commit needed: the notice is written in the change's own transaction
                self.assertEqual(_notices(), [(account.email, event, "queued")])

    def test_a_change_that_rolls_back_writes_nothing(self) -> None:
        user = User.objects.create_user(email="rollback@example.ro", password=PASSWORD)

        def change_then_fail() -> None:
            with transaction.atomic():
                MFAService.enable_totp(user, None)
                raise RuntimeError("the rest of the request failed")

        with self.assertRaises(RuntimeError):
            change_then_fail()
        self.assertEqual(_notices(), [])

    def test_the_notice_stays_queued_when_its_send_cannot_be_started(self) -> None:
        user = User.objects.create_user(email="durable@example.ro", password=PASSWORD)
        with (
            patch("django_q.tasks.async_task", side_effect=RuntimeError("queue down")),
            self.captureOnCommitCallbacks(execute=True),
        ):
            MFAService.enable_totp(user, None)
        # The queue sweep sends a queued row whose task was lost; nothing is dropped.
        self.assertEqual(_notices(), [(user.email, "2fa_enabled", "queued")])

    def test_an_admin_reset_names_the_admin_and_an_operator_reset_names_support(self) -> None:
        admin = User.objects.create_user(email="boss@example.ro", password=PASSWORD, staff_role="admin")
        first, second = _enrolled("first@example.ro"), _enrolled("second@example.ro")
        UserProfile.objects.filter(user__in=[first, second]).update(preferred_language="en")
        MFAService.disable_totp(first, admin_user=admin)
        MFAService.disable_totp(second, operator="root")
        _deliver()
        by_admin, by_operator = sorted(mail.outbox, key=lambda message: message.to[0])
        self.assertIn("boss@example.ro", by_admin.body)
        self.assertIn("support", by_operator.body.lower())
        self.assertNotIn("boss@example.ro", by_operator.body)

    def test_the_queued_notice_is_delivered_in_the_account_language(self) -> None:
        romanian = User.objects.create_user(email="ro@example.ro", password=PASSWORD, first_name="Ana")
        UserProfile.objects.filter(user=romanian).update(preferred_language="ro")
        english = User.objects.create_user(email="en@example.ro", password=PASSWORD, first_name="Ann")
        UserProfile.objects.filter(user=english).update(preferred_language="en")
        for account in (romanian, english):
            MFAService.enable_totp(account, None)
        _deliver()
        english_mail, romanian_mail = sorted(mail.outbox, key=lambda message: message.to[0])
        self.assertEqual(romanian_mail.to, ["ro@example.ro"])
        self.assertIn("Two-factor authentication was turned on", english_mail.subject)
        self.assertIn('lang="ro"', romanian_mail.alternatives[0][0])
        self.assertIn('lang="en"', english_mail.alternatives[0][0])

    def test_an_inactive_account_gets_nothing(self) -> None:
        user = User.objects.create_user(email="gone@example.ro", password=PASSWORD, is_active=False)
        MFAService.enable_totp(user, None)
        self.assertEqual(_notices(), [])


class NoticeSuppressionTests(TestCase):
    """A marketing unsubscribe never silences what protects the account; a bounce still does."""

    def test_an_unsubscribed_address_still_gets_its_security_notice(self) -> None:
        user = User.objects.create_user(email="unsubscribed@example.ro", password=PASSWORD)
        EmailSuppressionService.suppress_email(user.email, "unsubscribe")
        MFAService.enable_totp(user, None)
        self.assertEqual(_notices(), [(user.email, "2fa_enabled", "queued")])

    def test_control_other_mail_to_an_unsubscribed_address_is_still_suppressed(self) -> None:
        EmailSuppressionService.suppress_email("unsubscribed@example.ro", "unsubscribe")
        result = EmailService.send_email(to="unsubscribed@example.ro", subject="News", body_text="Offers")
        self.assertFalse(result.success)

    def test_a_bounced_address_gets_no_notice(self) -> None:
        user = User.objects.create_user(email="bounced@example.ro", password=PASSWORD)
        EmailSuppressionService.suppress_email(user.email, "hard_bounce")
        MFAService.enable_totp(user, None)
        self.assertEqual(_notices(), [])


class NoticeWriteFailureTests(TestCase):
    def test_new_codes_are_still_shown_when_the_notice_cannot_be_written(self) -> None:
        user = _enrolled("codes@example.ro")
        codes = user.generate_backup_codes()
        self.client.force_login(user)
        for failure in (RuntimeError("email service down"), DatabaseError("notice row refused")):
            with self.subTest(failure=type(failure).__name__), patch(SEND, side_effect=failure):
                response = self.client.post(
                    reverse("users:mfa_regenerate_backup_codes"),
                    {"password": PASSWORD, "token": codes[0], "confirm_regenerate": "on"},
                )
                codes = response.context["backup_codes"]  # the new codes replace the ones used
                self.assertEqual(len(codes), 8)


class LegacyTaskTests(TestCase):
    """Notices queued by the previous release still arrive once this one is deployed."""

    def test_the_notice_goes_to_the_account_in_its_language(self) -> None:
        user = User.objects.create_user(email="ro@example.ro", password=PASSWORD, first_name="Ana")
        UserProfile.objects.filter(user=user).update(preferred_language="ro")
        self.assertEqual(deliver_security_notice(user.pk, "2fa_disabled", "", False)["sent"], True)
        self.assertIn('lang="ro"', mail.outbox[0].alternatives[0][0])

    def test_an_unknown_or_inactive_account_gets_nothing(self) -> None:
        user = User.objects.create_user(email="gone@example.ro", password=PASSWORD, is_active=False)
        self.assertFalse(deliver_security_notice(user.pk, "password_changed", "", False)["sent"])
        self.assertFalse(deliver_security_notice(999999, "password_changed", "", False)["sent"])
        self.assertEqual(mail.outbox, [])
