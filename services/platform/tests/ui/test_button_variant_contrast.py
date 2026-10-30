"""The warning and success buttons' labels are readable on their colour (WCAG 2.2 AA, 4.5:1 for normal text).

Warning was white on yellow-500, 1.9:1, so the page's most consequential actions (Suspend, Deactivate) had
the least readable labels; success was white on green-600, 3.3:1. The colours are Tailwind's; the ratio is
computed, not asserted by hand.
"""

from django.template import Context, Template
from django.test import SimpleTestCase

# Tailwind v3/v4 palette values for the classes the warning variant may use.
PALETTE = {
    "white": "#ffffff",
    "slate-900": "#0f172a",
    "yellow-500": "#eab308",
    "yellow-600": "#ca8a04",
    "green-600": "#16a34a",
    "green-700": "#15803d",
    "green-800": "#166534",
}
VARIANTS = ("warning", "success")


def _luminance(hex_colour: str) -> float:
    def channel(value: float) -> float:
        return value / 12.92 if value <= 0.03928 else ((value + 0.055) / 1.055) ** 2.4

    r, g, b = (int(hex_colour[i : i + 2], 16) / 255 for i in (1, 3, 5))
    return 0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b)


def contrast(first: str, second: str) -> float:
    high, low = sorted((_luminance(first), _luminance(second)), reverse=True)
    return (high + 0.05) / (low + 0.05)


class VariantContrastTests(SimpleTestCase):
    def _colours(self, variant: str, extra: str) -> tuple[str, list[str]]:
        html = Template('{% load ui_components %}{% button "Suspend" variant="' + variant + '"' + extra + " %}").render(
            Context()
        )
        classes = html.split('class="ui-btn', 1)[1].split('"', 1)[0].split()
        text = [c.removeprefix("text-") for c in classes if c.removeprefix("text-") in PALETTE]
        backgrounds = [c.split("bg-", 1)[1] for c in classes if "bg-" in c and c.split("bg-", 1)[1] in PALETTE]
        self.assertEqual(len(text), 1, classes)
        self.assertEqual(len(backgrounds), 2, classes)  # resting and hover
        return text[0], backgrounds

    def test_the_label_is_readable_at_rest_and_on_hover_for_links_and_buttons(self) -> None:
        for variant in VARIANTS:
            for extra in ("", ' href="/x/"'):
                text, backgrounds = self._colours(variant, extra)
                for background in backgrounds:
                    with self.subTest(variant=variant, element="link" if extra else "button", background=background):
                        self.assertGreaterEqual(contrast(PALETTE[text], PALETTE[background]), 4.5)
