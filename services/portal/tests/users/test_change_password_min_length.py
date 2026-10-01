"""The portal's change-password form promises what the Platform enforces (#557).

The Platform rejects passwords under 12 characters (AUTH_PASSWORD_VALIDATORS). The
change-password form said 8 and validated 8, so a 9-11 character password passed the
form and then failed at the Platform with a less helpful error.
"""

from django.test import SimpleTestCase
from django.utils import translation

from apps.users.forms import REGISTRATION_PASSWORD_MIN_LENGTH, ChangePasswordForm

CURRENT = "current-password-fixture"  # test fixture, not a credential


class ChangePasswordMinimumLengthTests(SimpleTestCase):
    def form(self, new_password: str) -> ChangePasswordForm:
        return ChangePasswordForm(
            data={"current_password": CURRENT, "new_password": new_password, "confirm_password": new_password}
        )

    def test_eleven_characters_are_refused(self) -> None:
        form = self.form("a" * 11)
        self.assertFalse(form.is_valid())
        self.assertEqual(form.non_field_errors(), ["Password must be at least 12 characters long."])

    def test_twelve_characters_are_accepted(self) -> None:
        self.assertTrue(self.form("a" * 12).is_valid())

    def test_help_text_states_the_enforced_minimum(self) -> None:
        self.assertEqual(REGISTRATION_PASSWORD_MIN_LENGTH, 12)
        help_text = str(ChangePasswordForm().fields["new_password"].help_text)
        self.assertIn(str(REGISTRATION_PASSWORD_MIN_LENGTH), help_text)

    def test_romanian_copy_states_the_same_minimum(self) -> None:
        with translation.override("ro"):
            help_text = str(ChangePasswordForm().fields["new_password"].help_text)
            form = self.form("a" * 11)
            form.is_valid()
            errors = [str(error) for error in form.non_field_errors()]
        self.assertEqual(help_text, "Alegeți o parolă puternică cu cel puțin 12 caractere.")
        self.assertEqual(errors, ["Parola trebuie să conțină cel puțin 12 caractere."])
