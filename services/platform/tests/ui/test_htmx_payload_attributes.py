"""HTMX payload attributes reach every control branch without weakening argument validation."""

from __future__ import annotations

from django.template import Context, Template, TemplateSyntaxError
from django.test import SimpleTestCase, override_settings
from django.utils.html import escape
from django.utils.safestring import SafeString

from apps.ui.templatetags import ui_components


@override_settings(DEBUG=True, TESTING=True)
class HtmxPayloadAttributeTests(SimpleTestCase):
    def _check_call(self, call: str) -> None:
        values = '{"filter": "<tag>&"}'
        headers = '{"X-Token": "a&b"}'
        cases: tuple[tuple[str, dict[str, object]], ...] = (
            ("hx_vals=values hx_headers=headers", {"values": values, "headers": headers}),
            (
                "hx_vals=values hx_headers=headers",
                {"values": SafeString(values), "headers": SafeString(headers)},
            ),
            (f"hx_vals='{values}' hx_headers='{headers}'", {}),
            (
                "htmx=attributes",
                {"attributes": ui_components.HTMXAttributes(hx_vals=values, hx_headers=headers)},
            ),
        )
        for arguments, context in cases:
            with self.subTest(call=call, arguments=arguments, context=context):
                source = "{% load ui_components %}{% " + call + " " + arguments + " %}"
                rendered = Template(source).render(Context(context))
                self.assertIn(f'hx-vals="{escape(values)}"', rendered)
                self.assertIn(f'hx-headers="{escape(headers)}"', rendered)
                self.assertNotIn('hx-vals="{"', rendered)
                self.assertNotIn('hx-headers="{"', rendered)

        for arguments in ("", "hx_vals=empty hx_headers=empty"):
            with self.subTest(call=call, omitted=arguments):
                source = "{% load ui_components %}{% " + call + " " + arguments + " %}"
                rendered = Template(source).render(Context({"empty": ""}))
                self.assertNotIn("hx-vals=", rendered)
                self.assertNotIn("hx-headers=", rendered)

        for unknown in ("bogus", "onclick", "hx_on"):
            source = (
                "{% load ui_components %}{% "
                + call
                + " hx_vals=values hx_headers=headers "
                + unknown
                + '="unexpected" %}'
            )
            with self.subTest(call=call, unknown=unknown), self.assertRaisesMessage(TemplateSyntaxError, unknown):
                Template(source).render(Context({"values": values, "headers": headers}))

    def test_button_payload_attributes_are_escaped_optional_and_guarded(self) -> None:
        self.assertIn("hx_vals", ui_components.tag_arguments("button"))
        self.assertIn("hx_headers", ui_components.tag_arguments("button"))
        for call in ('button "Save"', 'button "Open" href="/detail/"'):
            self._check_call(call)

    def test_input_payload_attributes_are_escaped_optional_and_guarded(self) -> None:
        self.assertIn("hx_vals", ui_components.tag_arguments("input_field"))
        self.assertIn("hx_headers", ui_components.tag_arguments("input_field"))
        for input_type in ("text", "select", "textarea", "radio"):
            self._check_call(f'input_field "control" input_type="{input_type}" label="Control"')
