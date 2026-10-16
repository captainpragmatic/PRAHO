"""Phone numbers are cleaned to international form; a Romanian national number gains +40."""

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

    def test_a_national_number_is_read_only_where_the_country_is_known(self):
        """Registration knows the customer's country (Romania by default here); a profile does not."""
        registration = CustomerRegistrationForm(data={"phone": "0722 123 456"})
        registration.is_valid()
        self.assertEqual(registration.cleaned_data["phone"], "+40722123456")
        for form_class, field in PHONE_FIELDS[1:]:
            with self.subTest(form=form_class.__name__):
                form = form_class(data={field: "0722 123 456"})
                form.is_valid()
                self.assertIn(field, form.errors)
