"""The staff login form is safe when rendered through the component bridge."""

from django.template import Context, Template
from django.test import SimpleTestCase

from apps.users.forms import LoginForm


class StaffLoginPasswordRenderingTests(SimpleTestCase):
    def test_bound_login_password_is_not_redisplayed_by_form_field(self) -> None:
        secret = "SuperSecret123!"
        form = LoginForm({"email": "staff@example.com", "password": secret})
        rendered = Template("{% load ui_components %}{% form_field form.email %}{% form_field form.password %}").render(
            Context({"form": form})
        )

        self.assertIn('name="password"', rendered)
        self.assertIn('type="password"', rendered)
        self.assertIn('value="staff@example.com"', rendered)
        self.assertNotIn(secret, rendered)
        self.assertNotRegex(rendered, r'<input\b[^>]*\bname="password"[^>]*\bvalue\s*=')
