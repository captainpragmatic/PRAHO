"""Platform's input_field must hand the shared input template every variable it reads (#593).

components/input.html lives in shared/ui and is rendered by both services' input_field tags
(ADR-0035). Platform's tag stopped at `romanian_validation`, so `min`, `maxlength`, `pattern`,
`autocomplete`, `rows` and the rest were silently dropped - including on forms that pass them
today, such as the TOTP field on the MFA setup page. The guard below reads the variable names
from the template itself, so an attribute added there fails here until the tag passes it.
"""

from __future__ import annotations

from collections.abc import Iterable

from django.template import Context, Template
from django.template.base import FilterExpression, Node, Variable, VariableNode
from django.template.defaulttags import ForNode, IfNode, TemplateLiteral, WithNode
from django.template.loader import get_template
from django.test import SimpleTestCase, TestCase
from django.urls import reverse

from apps.products.models import Product
from apps.ui.templatetags.ui_components import input_field
from tests.factories.core_factories import create_admin_user, create_staff_user

# `{% if x is not None %}` compiles `None` as a variable lookup; these three are literals.
_LITERALS = frozenset({"None", "True", "False"})


def _roots(expression: FilterExpression | None, bound: frozenset[str]) -> set[str]:
    """Context names an expression reads: its variable and any variable filter arguments."""
    if expression is None:
        return set()
    found: set[str] = set()
    variables = [expression.var] + [arg for _f, args in expression.filters for is_var, arg in args if is_var]
    for variable in variables:
        if isinstance(variable, Variable) and variable.lookups and variable.lookups[0] not in bound | _LITERALS:
            found.add(variable.lookups[0])
    return found


def _condition_roots(condition: object, bound: frozenset[str]) -> set[str]:
    if isinstance(condition, TemplateLiteral):
        return _roots(condition.value, bound)
    found: set[str] = set()
    for operand in (getattr(condition, "first", None), getattr(condition, "second", None)):
        if operand is not None:
            found |= _condition_roots(operand, bound)
    return found


def template_variables(nodes: Iterable[Node], bound: frozenset[str] = frozenset()) -> set[str]:
    """Every context name a compiled template reads, minus names a `{% for %}` binds."""
    found: set[str] = set()
    for node in nodes:
        if isinstance(node, VariableNode):
            found |= _roots(node.filter_expression, bound)
        elif isinstance(node, IfNode):
            for condition, nodelist in node.conditions_nodelists:
                if condition is not None:
                    found |= _condition_roots(condition, bound)
                found |= template_variables(nodelist, bound)
        elif isinstance(node, ForNode):
            found |= _roots(node.sequence, bound)
            found |= template_variables(node.nodelist_loop, bound | set(node.loopvars))
            found |= template_variables(node.nodelist_empty, bound)
        elif isinstance(node, WithNode):
            # `{% with alias=source %}` reads `source` and binds `alias` for its body.
            for expression in node.extra_context.values():
                found |= _roots(expression, bound)
            found |= template_variables(node.nodelist, bound | set(node.extra_context))
        else:
            for expression in [*getattr(node, "args", ()), *getattr(node, "kwargs", {}).values()]:
                found |= _roots(expression, bound)
            for attribute in node.child_nodelists:
                found |= template_variables(getattr(node, attribute, None) or (), bound)
    return found


def _render(template_str: str, **context: object) -> str:
    return Template("{% load ui_components %}" + template_str).render(Context(context))


class InputTemplateParityTests(SimpleTestCase):
    def test_the_walker_reads_through_with_aliases(self) -> None:
        nodes = Template("{% with alias=source %}{{ alias }}{% endwith %}{{ plain }}").nodelist
        self.assertEqual(template_variables(nodes), {"source", "plain"})

    def test_the_tag_passes_every_variable_the_template_reads(self) -> None:
        read = template_variables(get_template("components/input.html").template.nodelist)
        # The walker itself must see the template, or the subset check below passes on nothing.
        self.assertTrue({"label", "hx_include", "maxlength", "data_attrs", "checked"} <= read, read)

        self.assertEqual(read - set(input_field("f").keys()), set())
        self.assertIs(input_field("f")["checked"], False)
        self.assertIs(input_field("f", checked=True)["checked"], True)

    def test_help_below_is_announced_with_its_own_id(self) -> None:
        for kind in ("", ' input_type="textarea"', ' input_type="select"'):
            with self.subTest(kind=kind or "input"):
                below_only = _render(f'{{% input_field "f"{kind} help_text_below="Below" %}}')
                self.assertIn('aria-describedby="input-f-help-below"', below_only)
                self.assertIn('id="input-f-help-below"', below_only)
                both = _render(f'{{% input_field "f"{kind} help_text="Above" help_text_below="Below" %}}')
                self.assertIn('aria-describedby="input-f-help input-f-help-below"', both)
                self.assertEqual(both.count('id="input-f-help"'), 1)


class InputAttributesRenderTests(SimpleTestCase):
    def test_each_input_attribute_reaches_the_element(self) -> None:
        cases = {
            "min=0": 'min="0"',
            "max=10": 'max="10"',
            "step=1": 'step="1"',
            "maxlength=6": 'maxlength="6"',
            'pattern="[0-9]{6}"': 'pattern="[0-9]{6}"',
            'autocomplete="one-time-code"': 'autocomplete="one-time-code"',
            "autofocus=True": " autofocus",
            'input_type="file" multiple=True': " multiple",
            'input_type="file" accept="image/png"': 'accept="image/png"',
            'aria_label="Code"': 'aria-label="Code"',
        }
        for kwargs, expected in cases.items():
            with self.subTest(kwargs=kwargs):
                self.assertIn(expected, _render(f'{{% input_field "f" {kwargs} %}}'))

    def test_textarea_rows_and_length_reach_the_element(self) -> None:
        rendered = _render('{% input_field "f" input_type="textarea" rows=5 maxlength=200 %}')
        self.assertIn('rows="5"', rendered)
        self.assertIn('maxlength="200"', rendered)

    def test_a_multiple_select_is_rendered_as_one(self) -> None:
        self.assertIn("<select multiple", _render('{% input_field "f" input_type="select" multiple=True %}'))

    def test_data_attributes_render_and_unsafe_keys_are_dropped(self) -> None:
        rendered = _render('{% input_field "f" data_attrs=attrs %}', attrs={"role": "otp", 'x" onclick="y': "1"})
        self.assertIn('data-role="otp"', rendered)
        self.assertNotIn("onclick", rendered)

    def test_container_class_and_help_below_render(self) -> None:
        rendered = _render('{% input_field "f" container_class="hidden" help_text_below="Below the field" %}')
        self.assertIn('<div class="hidden">', rendered)
        self.assertIn("Below the field", rendered)


class FormsReceiveTheirDeclaredHintsTests(TestCase):
    def test_the_totp_field_keeps_its_pattern_length_and_autocomplete(self) -> None:
        self.client.force_login(create_staff_user())
        response = self.client.get(reverse("users:mfa_setup_totp"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'pattern="[0-9]{6}"')
        self.assertContains(response, 'maxlength="6"')
        self.assertContains(response, 'autocomplete="one-time-code"')

    def test_tld_prices_refuse_negative_and_fractional_cents(self) -> None:
        self.client.force_login(create_admin_user())
        response = self.client.get(reverse("domains:tld_create"))
        self.assertEqual(response.status_code, 200)
        for name in ("registration_price_cents", "renewal_price_cents", "transfer_price_cents"):
            with self.subTest(field=name):
                self.assertRegex(response.content.decode(), rf'name="{name}"[^>]*min="0"[^>]*step="1"')

    def test_price_discounts_accept_the_cents_their_field_stores(self) -> None:
        """Two decimal places on the model; a number input with no step would refuse 12.50."""
        product = Product.objects.create(slug="hints-product", name="Hints", product_type="shared_hosting")
        self.client.force_login(create_admin_user())
        response = self.client.get(reverse("products:product_price_create", kwargs={"slug": product.slug}))
        self.assertEqual(response.status_code, 200)
        for name in ("semiannual_discount_percent", "annual_discount_percent"):
            with self.subTest(field=name):
                self.assertRegex(response.content.decode(), rf'name="{name}"[^>]*min="0"[^>]*max="100"[^>]*step="0.01"')
