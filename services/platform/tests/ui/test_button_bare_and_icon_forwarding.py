"""`variant="bare"` gives a control its own look, and the icon arguments reach the icon (#821).

Every other variant writes padding, a border, rounding, a display and colours, and a class appended after them can't
reliably win: Tailwind orders its rules by its own sort, not by the order of the class string. A control that doesn't
look like a standard button uses `bare` and its own class string. The icon used to be hard-coded at the small outline
size; `icon_size`, `icon_style` and `svg_class` reach `{% icon %}` instead.
"""

from html.parser import HTMLParser

from django.template import Context, Template, TemplateSyntaxError
from django.test import SimpleTestCase

# What the other variants write and bare must not: layout, size, shape and colour.
STANDARD_LOOK = (
    "inline-flex",
    "items-center",
    "justify-center",
    "font-medium",
    "rounded-lg",
    "border",
    "transition-all",
)
STANDARD_PREFIXES = ("px-", "py-", "bg-", "text-", "border-", "hover:", "rounded-", "focus:ring-4")


class Parser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.elements: list[tuple[str, dict[str, str | None]]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.elements.append((tag, dict(attrs)))


def render(arguments: str) -> Parser:
    html = Template(
        '{% load i18n ui_components %}{% trans "Close" as name %}{% button name ' + arguments + " %}"
    ).render(Context())
    parsed = Parser()
    parsed.feed(html)
    return parsed


def control_classes(parsed: Parser) -> list[str]:
    controls = [attrs for tag, attrs in parsed.elements if tag in ("button", "a")]
    assert len(controls) == 1, parsed.elements
    return (controls[0].get("class") or "").split()


def svg(parsed: Parser) -> dict[str, str | None]:
    found = [
        attrs for tag, attrs in parsed.elements if tag == "svg" and "animate-spin" not in (attrs.get("class") or "")
    ]
    assert len(found) == 1, parsed.elements
    return found[0]


class BareVariantTests(SimpleTestCase):
    def test_bare_writes_only_the_hook_the_focus_ring_the_disabled_styles_and_the_caller_s_classes(self) -> None:
        for extra in ("", ' href="/x/"', " disabled=True"):
            with self.subTest(extra=extra):
                classes = control_classes(render('variant="bare" class="ml-2 text-slate-500 hover:text-white"' + extra))
                self.assertIn("ui-btn", classes)
                self.assertIn("focus-visible:ring-2", classes)
                self.assertIn("disabled:opacity-50", classes)
                own = ["ml-2", "text-slate-500", "hover:text-white"]
                self.assertEqual(classes[-3:], own)
                for name in classes[:-3]:
                    self.assertNotIn(name, STANDARD_LOOK)
                    self.assertFalse(name.startswith(STANDARD_PREFIXES), name)

    def test_bare_ignores_size(self) -> None:
        classes = control_classes(render('variant="bare" size="lg"'))
        self.assertFalse([name for name in classes if name.startswith(("px-", "py-", "text-"))], classes)

    def test_the_other_variants_keep_their_look(self) -> None:
        classes = control_classes(render('variant="ghost"'))
        for name in ("inline-flex", "rounded-lg", "px-4", "py-2", "bg-transparent"):
            self.assertIn(name, classes)


class IconForwardingTests(SimpleTestCase):
    def test_the_default_icon_is_the_small_outline_one(self) -> None:
        icon = svg(render('icon="copy"'))
        self.assertIn("w-4", icon["class"] or "")
        self.assertEqual(icon["viewbox"], "0 0 24 24")

    def test_size_style_and_class_reach_the_svg(self) -> None:
        for extra in ("", ' href="/x/"'):
            with self.subTest(extra=extra):
                icon = svg(
                    render(
                        'icon="x-mark" icon_only=True aria_label=name icon_size="md" icon_style="filled" '
                        'svg_class="chevron-icon"' + extra
                    )
                )
                classes = (icon["class"] or "").split()
                self.assertIn("w-5", classes)
                self.assertIn("chevron-icon", classes)
                self.assertEqual(icon["viewbox"], "0 0 20 20")

    def test_svg_class_sits_beside_the_spacing_of_a_labelled_icon(self) -> None:
        for extra, spacing in (("", "mr-2"), (" icon_right=True", "ml-2")):
            with self.subTest(extra=extra):
                classes = (svg(render('icon="copy" svg_class="chevron-icon"' + extra))["class"] or "").split()
                self.assertIn(spacing, classes)
                self.assertIn("chevron-icon", classes)

    def test_an_icon_only_button_needs_the_icon_in_the_catalog_of_its_style(self) -> None:
        # x-mark exists only filled, copy only outline; either mismatch would render an unnamed blank button.
        for arguments in ('icon="x-mark" icon_style="outline"', 'icon="copy" icon_style="filled"'):
            with self.subTest(arguments=arguments), self.assertRaises(TemplateSyntaxError):
                render(arguments + " icon_only=True aria_label=name")

    def test_an_unknown_size_or_style_is_refused(self) -> None:
        for arguments in ('icon="copy" icon_size="huge"', 'icon="copy" icon_style="duotone"'):
            with self.subTest(arguments=arguments), self.assertRaises(TemplateSyntaxError):
                render(arguments)
