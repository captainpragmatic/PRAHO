"""Every template call of a UI tag passes only arguments that tag accepts.

The tags used to apply their keyword arguments with `if hasattr(config, key)`, which skipped
anything else without a word: the styleguide's `{% input_field ... type="email" %}` rendered a
text box, and a button's `href_kwargs=` left its link pointing at a URL name. Each tag now
declares what its keyword arguments may carry and rejects the rest; this scan holds every
template in the service to that, including pages no test renders. Platform runs the same scan.
"""

from __future__ import annotations

import inspect
from collections.abc import Callable, Iterator
from pathlib import Path

from django.template import Context, Template, TemplateSyntaxError, engines
from django.template.library import TagHelperNode
from django.template.utils import get_app_template_dirs
from django.test import SimpleTestCase, override_settings

from apps.ui.templatetags import ui_components


def _template_files() -> Iterator[Path]:
    engine = engines["django"].engine
    roots = {Path(directory) for directory in engine.dirs} | {Path(d) for d in get_app_template_dirs("templates")}
    for root in sorted(roots):
        yield from sorted(root.rglob("*.html"))


def _accepted(tag_function: Callable[..., object]) -> frozenset[str]:
    signature = inspect.signature(tag_function)
    named = {
        name
        for name, parameter in signature.parameters.items()
        if parameter.kind not in (parameter.VAR_KEYWORD, parameter.VAR_POSITIONAL)
    }
    return frozenset(named) | ui_components.tag_arguments(getattr(tag_function, "__name__", ""))


class TagCallSitesTests(SimpleTestCase):
    maxDiff = None

    def test_every_call_site_passes_only_arguments_its_tag_accepts(self) -> None:
        engine = engines["django"].engine
        problems: list[str] = []
        calls = 0
        for path in _template_files():
            try:
                compiled = engine.from_string(path.read_text(encoding="utf-8"))
            except TemplateSyntaxError as exc:
                problems.append(f"{path}: does not compile: {exc}")
                continue
            for node in compiled.nodelist.get_nodes_by_type(TagHelperNode):
                if getattr(node.func, "__module__", "") != ui_components.__name__:
                    continue
                calls += 1
                unknown = sorted(set(node.kwargs) - _accepted(node.func))
                if unknown:
                    problems.append(f"{path}: {{% {node.func.__name__} %}} got {', '.join(unknown)}")
        # The scan must reach the templates, or an empty problem list proves nothing.
        self.assertGreater(calls, 50)
        self.assertEqual(problems, [])


class DeclaredHtmxReachesTheContextTests(SimpleTestCase):
    def test_every_accepted_htmx_argument_is_passed_to_the_template(self) -> None:
        """Accepting an hx_* argument a tag never forwards would drop it as silently as before."""
        contexts = {
            "button": ui_components.button("Go"),
            "input_field": ui_components.input_field("f"),
            "checkbox_field": ui_components.checkbox_field("f"),
        }
        for tag, context in contexts.items():
            with self.subTest(tag=tag):
                accepted = {name for name in ui_components.tag_arguments(tag) if name.startswith("hx_")}
                self.assertTrue(accepted)
                self.assertEqual(accepted - set(context), set())


class BlockTagTests(SimpleTestCase):
    def test_calls_inside_block_tags_are_scanned(self) -> None:
        for block, end in (("page_header", "end_page_header"), ("section_card", "end_section_card")):
            with self.subTest(block=block):
                compiled = Template(
                    f'{{% load ui_components %}}{{% {block} title="T" %}}{{% button "Inner" %}}{{% {end} %}}'
                )
                inner = [n.func.__name__ for n in compiled.nodelist.get_nodes_by_type(TagHelperNode)]
                self.assertEqual(inner, ["button"])

    def test_an_unknown_block_tag_argument_fails_while_testing(self) -> None:
        for block, end in (("page_header", "end_page_header"), ("section_card", "end_section_card")):
            with self.subTest(block=block), self.assertRaisesMessage(TemplateSyntaxError, "unknown argument"):
                Template(f'{{% load ui_components %}}{{% {block} bogus=1 %}}{{% {end} %}}')


def _render(template_str: str) -> str:
    return Template("{% load ui_components %}" + template_str).render(Context({}))


class UnknownArgumentTests(SimpleTestCase):
    def test_an_unknown_argument_fails_while_testing(self) -> None:
        for call in ('{% icon "check" bogus=1 %}', '{% button "Go" bogus=1 %}', '{% input_field "f" type="email" %}'):
            with self.subTest(call=call), self.assertRaisesMessage(TemplateSyntaxError, "unknown argument"):
                _render(call)

    @override_settings(DEBUG=False)
    def test_in_production_it_is_logged_and_the_page_still_renders(self) -> None:
        with self.assertLogs("apps.ui.templatetags.ui_components", level="WARNING") as logs:
            rendered = _render('{% button "Go" bogus=1 %}')
        self.assertIn("Go", rendered)
        self.assertIn("bogus", "".join(logs.output))


class ButtonClassTests(SimpleTestCase):
    def test_css_class_and_class_reach_the_button(self) -> None:
        for call in ('{% button "Add" css_class="add-line-btn" %}', '{% button "Add" class="add-line-btn" %}'):
            with self.subTest(call=call):
                self.assertIn("add-line-btn", _render(call))
