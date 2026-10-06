"""The Portal's input_field must hand the shared input template every variable it reads (#593).

components/input.html lives in shared/ui and is rendered by both services' input_field tags
(ADR-0035). The variable names are read from the template itself, so an attribute added there
fails here until this service's tag passes it. Platform runs the same guard; the walker is
copied rather than shared because the Portal may not import Platform code.
"""

from __future__ import annotations

from collections.abc import Iterable

from django.template import Context, Template
from django.template.base import FilterExpression, Node, Variable, VariableNode
from django.template.defaulttags import ForNode, IfNode, TemplateLiteral, WithNode
from django.template.loader import get_template
from django.test import SimpleTestCase

from apps.ui.templatetags.ui_components import input_field

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


def _render(template_str: str) -> str:
    return Template("{% load ui_components %}" + template_str).render(Context({}))


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

    def test_help_below_renders_under_the_field(self) -> None:
        self.assertIn("Below the field", _render('{% input_field "f" help_text_below="Below the field" %}'))

    def test_help_below_is_announced_with_its_own_id(self) -> None:
        for kind in ("", ' input_type="textarea"', ' input_type="select"'):
            with self.subTest(kind=kind or "input"):
                below_only = _render(f'{{% input_field "f"{kind} help_text_below="Below" %}}')
                self.assertIn('aria-describedby="input-f-help-below"', below_only)
                self.assertIn('id="input-f-help-below"', below_only)
                both = _render(f'{{% input_field "f"{kind} help_text="Above" help_text_below="Below" %}}')
                self.assertIn('aria-describedby="input-f-help input-f-help-below"', both)
                self.assertEqual(both.count('id="input-f-help"'), 1)
