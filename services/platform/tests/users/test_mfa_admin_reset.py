"""An administrator can reset another person's 2FA: the recovery path for a lost device.

`MFAService.disable_totp` had an admin branch that nothing called, so someone who lost both their
authenticator and their backup codes had no way back; the sign-in pages told them to "contact
support", who could do nothing. With staff 2FA required, that would lock a staff member out.

- An administrator resets it from the person's page. The audit event names the administrator as the
  actor, and the person's sessions end, so their next sign-in asks for a new enrolment.
- No one can reset their own 2FA this way: that would get round the rule that staff keep theirs.
- When no administrator can sign in, `manage.py reset_two_factor` does the same from the server.
"""

from __future__ import annotations

from io import StringIO
from typing import Any

from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import Client, TestCase
from django.urls import reverse

from apps.audit.models import AuditEvent
from apps.users.mfa import TOTPService
from apps.users.models import User

PASSWORD = "correct-horse-battery-staple"  # test fixture, not a credential


def enrol(user: User) -> User:
    user.two_factor_secret = TOTPService.generate_secret()
    user.two_factor_enabled = True
    user.save()
    user.generate_backup_codes()
    return user


class AdminResetTests(TestCase):
    def setUp(self) -> None:
        self.admin = enrol(
            User.objects.create_user(email="reset-admin@example.ro", password=PASSWORD, staff_role="admin")
        )
        self.target = enrol(
            User.objects.create_user(email="lost-device@example.ro", password=PASSWORD, staff_role="support")
        )
        self.colleague = User.objects.create_user(email="colleague@example.ro", password=PASSWORD, staff_role="support")

    def reset(self, actor: User, target: User) -> Any:
        self.client.force_login(actor)
        return self.client.post(reverse("users:mfa_admin_reset", kwargs={"pk": target.pk}))

    def test_an_admin_resets_another_persons_2fa_and_is_recorded_as_the_actor(self) -> None:
        response = self.reset(self.admin, self.target)

        self.assertRedirects(
            response, reverse("users:user_detail", kwargs={"pk": self.target.pk}), fetch_redirect_response=False
        )
        target = User.objects.get(pk=self.target.pk)
        self.assertFalse(target.two_factor_enabled)
        self.assertEqual((target.two_factor_secret, target.backup_tokens), ("", []))
        event = AuditEvent.objects.get(action="2fa_admin_reset")
        self.assertEqual(event.user, self.admin)
        self.assertEqual(event.object_id, str(self.target.pk))
        self.assertEqual(event.metadata["reason"], "Admin reset")

    def test_the_persons_sessions_end(self) -> None:
        their_browser = Client()
        their_browser.force_login(self.target)
        self.assertEqual(their_browser.get(reverse("users:user_profile")).status_code, 200)

        self.reset(self.admin, self.target)

        response = their_browser.get(reverse("users:user_profile"))
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse("users:login"), response["Location"])

    def test_only_an_administrator_may_reset(self) -> None:
        self.assertEqual(self.reset(self.colleague, self.target).status_code, 403)

        self.assertTrue(User.objects.get(pk=self.target.pk).two_factor_enabled)
        self.assertFalse(AuditEvent.objects.filter(action="2fa_admin_reset").exists())

    def test_no_one_resets_their_own_2fa_this_way(self) -> None:
        self.reset(self.admin, self.admin)

        self.assertTrue(User.objects.get(pk=self.admin.pk).two_factor_enabled)
        self.assertFalse(AuditEvent.objects.filter(action="2fa_admin_reset").exists())

    def test_the_reset_is_post_only(self) -> None:
        self.client.force_login(self.admin)

        response = self.client.get(reverse("users:mfa_admin_reset", kwargs={"pk": self.target.pk}))

        self.assertEqual(response.status_code, 405)
        self.assertTrue(User.objects.get(pk=self.target.pk).two_factor_enabled)

    def test_the_person_page_offers_the_reset_to_administrators_only(self) -> None:
        reset_url = reverse("users:mfa_admin_reset", kwargs={"pk": self.target.pk})
        detail_url = reverse("users:user_detail", kwargs={"pk": self.target.pk})

        self.client.force_login(self.admin)
        page = self.client.get(detail_url)
        self.assertContains(page, reset_url)
        # A destructive action asks first: ui-actions.js confirms only a confirm-submit button.
        self.assertContains(page, 'data-action="confirm-submit"')
        self.assertContains(page, 'data-confirm="')

        self.client.force_login(self.colleague)
        self.assertNotContains(self.client.get(detail_url), reset_url)

        self.client.force_login(self.admin)
        own_page = self.client.get(reverse("users:user_detail", kwargs={"pk": self.admin.pk}))
        self.assertNotContains(own_page, reverse("users:mfa_admin_reset", kwargs={"pk": self.admin.pk}))

    def test_an_unknown_person_is_not_found(self) -> None:
        self.client.force_login(self.admin)

        self.assertEqual(self.client.get(reverse("users:user_detail", kwargs={"pk": 987654})).status_code, 404)


class OperatorResetCommandTests(TestCase):
    def setUp(self) -> None:
        self.person = enrol(
            User.objects.create_user(email="sole-admin@example.ro", password=PASSWORD, staff_role="admin")
        )

    def test_the_command_resets_2fa_and_audits_the_operator(self) -> None:
        output = StringIO()

        call_command("reset_two_factor", email=self.person.email, reason="Lost phone and codes", stdout=output)

        self.assertFalse(User.objects.get(pk=self.person.pk).two_factor_enabled)
        event = AuditEvent.objects.get(action="2fa_admin_reset")
        self.assertIsNone(event.user)
        self.assertEqual(event.object_id, str(self.person.pk))
        self.assertEqual(event.metadata["reset_by"], "operator_command")
        self.assertIn("Lost phone and codes", event.metadata["reason"])
        self.assertIn(self.person.email, output.getvalue())

    def test_the_command_needs_a_known_enrolled_account_and_a_reason(self) -> None:
        # Each refusal names its reason: an unknown command raises CommandError too.
        with self.assertRaisesMessage(CommandError, "No account with the email nobody@example.ro."):
            call_command("reset_two_factor", email="nobody@example.ro", reason="x", stdout=StringIO())
        with self.assertRaisesMessage(CommandError, "Give a reason"):
            call_command("reset_two_factor", email=self.person.email, reason="  ", stdout=StringIO())
        unenrolled = User.objects.create_user(email="no-2fa@example.ro", password=PASSWORD)
        with self.assertRaisesMessage(CommandError, "has no two-factor authentication to reset"):
            call_command("reset_two_factor", email=unenrolled.email, reason="x", stdout=StringIO())
        self.assertTrue(User.objects.get(pk=self.person.pk).two_factor_enabled)
        self.assertFalse(AuditEvent.objects.filter(action="2fa_admin_reset").exists())
