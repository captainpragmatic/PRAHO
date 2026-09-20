"""Romanian local/international phone formats must survive real form cleaning."""

from django.test import SimpleTestCase

from apps.users.forms import CompanyProfileForm, CustomerProfileForm, CustomerRegistrationForm

PHONE_FIELDS = (
    (CustomerRegistrationForm, "phone"),
    (CustomerProfileForm, "phone"),
    (CompanyProfileForm, "primary_phone"),
)


class RomanianPhoneForms(SimpleTestCase):
    def test_supported_phone_formats_are_normalized(self):
        for form_class, field in PHONE_FIELDS:
            for phone, expected in (
                ("+40.722.123.456", "+40722123456"),
                ("0722 123 456", "0722123456"),
                ("+40.21.123.4567", "+40211234567"),
                ("", ""),
            ):
                with self.subTest(form=form_class.__name__, phone=phone):
                    form = form_class(data={field: phone})
                    form.is_valid()
                    self.assertNotIn(field, form.errors)
                    self.assertEqual(form.cleaned_data[field], expected)

    def test_short_long_and_partial_matches_are_rejected(self):
        for form_class, field in PHONE_FIELDS:
            for phone in ("+4072212345", "+407221234567", "+40722123456junk"):
                form = form_class(data={field: phone})
                form.is_valid()
                self.assertIn(field, form.errors)
