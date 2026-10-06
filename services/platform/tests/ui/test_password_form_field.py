"""Password fields follow Django's explicit render_value policy."""

from __future__ import annotations

from html.parser import HTMLParser

from django import forms
from django.template import Context, Template
from django.test import SimpleTestCase


class _Inputs(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.inputs: dict[str, dict[str, str | None]] = {}

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = dict(attrs)
        name = attributes.get("name")
        if tag == "input" and name is not None:
            self.inputs[name] = attributes


class _PasswordForm(forms.Form):
    email = forms.EmailField()
    password = forms.CharField(widget=forms.PasswordInput)


class PasswordFormFieldTests(SimpleTestCase):
    def test_password_input_respects_render_value(self) -> None:
        secret = "SuperSecret123!"
        template = Template("{% load ui_components %}{% form_field form.email %}{% form_field form.password %}")
        for render_value in (False, True):
            with self.subTest(render_value=render_value):
                form = _PasswordForm({"email": "someone@example.com", "password": secret})
                form.fields["password"].widget = forms.PasswordInput(render_value=render_value)
                rendered = template.render(Context({"form": form}))
                parser = _Inputs()
                parser.feed(rendered)
                parser.close()

                self.assertEqual(set(parser.inputs), {"email", "password"})
                self.assertEqual(parser.inputs["email"].get("value"), "someone@example.com")
                self.assertEqual(parser.inputs["password"].get("type"), "password")
                self.assertEqual(form["password"].value(), secret)
                if render_value:
                    self.assertEqual(parser.inputs["password"].get("value"), secret)
                else:
                    self.assertNotIn("value", parser.inputs["password"])
                    self.assertNotIn(secret, rendered)
