"""Romanian local/international phone formats must survive real form cleaning."""

from django.test import SimpleTestCase

from apps.users.forms import CustomerProfileForm, CustomerRegistrationForm


class RomanianPhoneForms(SimpleTestCase):
    def test_supported_phone_formats_are_normalized(self):
        for form_class in (CustomerRegistrationForm, CustomerProfileForm):
            for phone, expected in (("+40.722.123.456", "+40722123456"), ("0722 123 456", "0722123456")):
                with self.subTest(form=form_class.__name__, phone=phone):
                    form = form_class(data={"phone": phone})
                    form.is_valid()
                    self.assertNotIn("phone", form.errors)
                    self.assertEqual(form.cleaned_data["phone"], expected)

    def test_short_long_and_partial_matches_are_rejected(self):
        for form_class in (CustomerRegistrationForm, CustomerProfileForm):
            for phone in ("+4072212345", "+407221234567", "+40722123456junk"):
                form = form_class(data={"phone": phone})
                form.is_valid()
                self.assertIn("phone", form.errors)
