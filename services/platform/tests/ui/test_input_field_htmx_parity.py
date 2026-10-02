"""Platform's input_field must pass every hx-* attribute the shared template renders.

components/input.html lives in shared/ui and is rendered by both services' input_field tags.
It renders hx-include, hx-sync and hx-indicator on all three element branches, but Platform's
tag only forwarded hx-get/post/trigger/target/swap, so those three were silently dropped for
every Platform caller (ADR-0035: shared components must stay in parity across services).
"""

from __future__ import annotations

from django.template import Context, Template
from django.test import SimpleTestCase

ELEMENTS = {
    "input": "",
    "textarea": ' input_type="textarea"',
    "select": ' input_type="select"',
}
ATTRIBUTES = {
    "hx_include": ("[name='q']", """hx-include="[name='q']\""""),
    "hx_sync": ("closest form:abort", 'hx-sync="closest form:abort"'),
    "hx_indicator": ("#spinner", 'hx-indicator="#spinner"'),
}


def _render(template_str: str) -> str:
    return Template("{% load ui_components %}" + template_str).render(Context({}))


class InputFieldHtmxParityTests(SimpleTestCase):
    def test_every_shared_hx_attribute_renders_on_every_element(self) -> None:
        for element, type_kwarg in ELEMENTS.items():
            for kwarg, (value, expected) in ATTRIBUTES.items():
                with self.subTest(element=element, attribute=kwarg):
                    rendered = _render(f'{{% input_field "f"{type_kwarg} hx_get="/x/" {kwarg}="{value}" %}}')
                    self.assertIn(expected, rendered)

    def test_absent_attributes_render_nothing(self) -> None:
        rendered = _render('{% input_field "f" hx_get="/x/" %}')
        for attribute in ("hx-include", "hx-sync", "hx-indicator"):
            self.assertNotIn(attribute, rendered)
