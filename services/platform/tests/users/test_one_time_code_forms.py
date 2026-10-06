"""Setup and verification codes retain submitted data without redisplaying it."""

from django.template import Context, Template
from django.test import SimpleTestCase

from apps.users.forms import TwoFactorSetupForm, TwoFactorVerifyForm


class OneTimeCodeFormRenderingTests(SimpleTestCase):
    def test_rejected_codes_are_not_echoed_by_django_widgets(self) -> None:
        for form_class, token in ((TwoFactorSetupForm, "987654"), (TwoFactorVerifyForm, "87654321")):
            with self.subTest(form=form_class.__name__):
                form = form_class({"token": token})
                self.assertTrue(form.is_valid(), form.errors)
                form.add_error(None, "Rejected code")
                rendered = form["token"].as_widget()
                self.assertEqual(form.data["token"], token)
                self.assertEqual(form.cleaned_data["token"], token)
                self.assertIn('type="text"', rendered)
                self.assertNotIn(f'value="{token}"', rendered)

    def test_rejected_codes_are_not_echoed_by_form_field_component(self) -> None:
        template = Template("{% load ui_components %}{% form_field form.token %}")
        for form_class, token in ((TwoFactorSetupForm, "987654"), (TwoFactorVerifyForm, "87654321")):
            with self.subTest(form=form_class.__name__):
                form = form_class({"token": token})
                self.assertTrue(form.is_valid(), form.errors)
                form.add_error(None, "Rejected code")
                rendered = template.render(Context({"form": form}))
                self.assertEqual(form.data["token"], token)
                self.assertEqual(form.cleaned_data["token"], token)
                self.assertIn('type="text"', rendered)
                self.assertNotIn(f'value="{token}"', rendered)
