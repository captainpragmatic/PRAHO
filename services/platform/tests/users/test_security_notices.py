"""The account holder is told by email when 2FA or the password changes (#689).

The notification preferences promise "security alerts (login attempts, 2FA)", but enabling,
disabling or resetting 2FA, regenerating backup codes and changing the password sent nothing.
A notice is now queued once the change commits, by the chokepoint every path goes through, so
the staff pages, the Portal's API and the operator command are all covered. A notice that
cannot be queued never undoes or hides the change itself.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

from django.core import mail
from django.db import transaction
from django.test import TestCase
from django.urls import reverse

from apps.users.forms import apply_password_change
from apps.users.mfa import MFAService, TOTPService
from apps.users.models import User, UserProfile
from apps.users.tasks import deliver_security_notice

PASSWORD = "Original-secure123!"  # test fixture, not a credential
QUEUE = "apps.users.security_notices.async_task"


def _enrolled(email: str) -> User:
    user = User.objects.create_user(email=email, password=PASSWORD, first_name="Ana")
    user.two_factor_secret = TOTPService.generate_secret()
    user.two_factor_enabled = True
    user.save()
    return user


class NoticesQueuedTests(TestCase):
    def queued(self, change: Any) -> list[tuple[Any, ...]]:
        with patch(QUEUE) as queue, self.captureOnCommitCallbacks(execute=True):
            change()
        # async_task(task path, user id, event, actor email, by operator, ...)
        return [call.args[1:] for call in queue.call_args_list]

    def test_each_change_queues_exactly_one_notice(self) -> None:
        user = User.objects.create_user(email="notice@example.ro", password=PASSWORD)
        admin = User.objects.create_user(email="admin@example.ro", password=PASSWORD, staff_role="admin")
        enrolled = _enrolled("enrolled@example.ro")
        cases = {
            "2fa_enabled": lambda: MFAService.enable_totp(user, None),
            "backup_codes": lambda: MFAService.generate_backup_codes(User.objects.get(pk=user.pk)),
            "2fa_disabled": lambda: MFAService.disable_totp(User.objects.get(pk=user.pk)),
            "2fa_reset": lambda: MFAService.disable_totp(enrolled, admin_user=admin),
            "password_changed": lambda: apply_password_change(
                user.pk, "Brand-new-password-456!", still_authorised=lambda _locked: True
            ),
        }
        for event, change in cases.items():
            with self.subTest(event=event):
                notices = self.queued(change)
                self.assertEqual(len(notices), 1, notices)
                self.assertEqual(notices[0][1], event)
                self.assertIn(notices[0][0], {user.pk, enrolled.pk})

    def test_an_admin_reset_names_the_admin_and_an_operator_reset_names_support(self) -> None:
        admin = User.objects.create_user(email="boss@example.ro", password=PASSWORD, staff_role="admin")
        first, second = _enrolled("first@example.ro"), _enrolled("second@example.ro")
        by_admin = self.queued(lambda: MFAService.disable_totp(first, admin_user=admin))[0]
        by_operator = self.queued(lambda: MFAService.disable_totp(second, operator="root"))[0]
        self.assertEqual((by_admin[1], by_admin[2], by_admin[3]), ("2fa_reset", "boss@example.ro", False))
        self.assertEqual((by_operator[1], by_operator[2], by_operator[3]), ("2fa_reset", "", True))

    def test_a_change_that_rolls_back_sends_nothing(self) -> None:
        user = User.objects.create_user(email="rollback@example.ro", password=PASSWORD)

        def change_then_fail() -> None:
            with transaction.atomic():
                MFAService.enable_totp(user, None)
                raise RuntimeError("the rest of the request failed")

        with patch(QUEUE) as queue, self.captureOnCommitCallbacks(execute=True), self.assertRaises(RuntimeError):
            change_then_fail()
        queue.assert_not_called()


class NoticeQueueFailureTests(TestCase):
    def test_new_codes_are_still_shown_when_the_notice_cannot_be_queued(self) -> None:
        user = _enrolled("codes@example.ro")
        codes = user.generate_backup_codes()
        self.client.force_login(user)
        with patch(QUEUE, side_effect=RuntimeError("queue down")), self.captureOnCommitCallbacks(execute=True):
            response = self.client.post(
                reverse("users:mfa_regenerate_backup_codes"),
                {"password": PASSWORD, "token": codes[0], "confirm_regenerate": "on"},
            )
        self.assertEqual(len(response.context["backup_codes"]), 8)


class NoticeDeliveryTests(TestCase):
    def test_the_notice_goes_to_the_account_in_its_language(self) -> None:
        user = User.objects.create_user(email="ro@example.ro", password=PASSWORD, first_name="Ana")
        UserProfile.objects.filter(user=user).update(preferred_language="ro")
        english = User.objects.create_user(email="en@example.ro", password=PASSWORD, first_name="Ann")
        UserProfile.objects.filter(user=english).update(preferred_language="en")

        self.assertEqual(deliver_security_notice(user.pk, "2fa_disabled", "", False)["sent"], True)
        self.assertEqual(deliver_security_notice(english.pk, "2fa_disabled", "", False)["sent"], True)

        romanian_mail, english_mail = mail.outbox
        self.assertEqual(romanian_mail.to, ["ro@example.ro"])
        self.assertIn("Two-factor authentication was turned off", english_mail.subject)
        # Rendered in each account's language: the HTML part declares it.
        self.assertIn('lang="ro"', romanian_mail.alternatives[0][0])
        self.assertIn('lang="en"', english_mail.alternatives[0][0])

    def test_an_admin_reset_notice_says_who(self) -> None:
        user = User.objects.create_user(email="target@example.ro", password=PASSWORD)
        UserProfile.objects.filter(user=user).update(preferred_language="en")
        deliver_security_notice(user.pk, "2fa_reset", "boss@example.ro", False)
        deliver_security_notice(user.pk, "2fa_reset", "", True)
        by_admin, by_operator = mail.outbox
        self.assertIn("boss@example.ro", by_admin.body)
        self.assertIn("support", by_operator.body.lower())
        self.assertNotIn("boss@example.ro", by_operator.body)

    def test_an_unknown_or_inactive_account_gets_nothing(self) -> None:
        user = User.objects.create_user(email="gone@example.ro", password=PASSWORD, is_active=False)
        self.assertFalse(deliver_security_notice(user.pk, "password_changed", "", False)["sent"])
        self.assertFalse(deliver_security_notice(999999, "password_changed", "", False)["sent"])
        self.assertEqual(mail.outbox, [])
