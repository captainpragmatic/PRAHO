"""Every button variant's label is readable on its colour (WCAG 2.2 AA, 4.5:1 for normal text), at rest and on hover.

Warning was white on yellow-500, 1.9:1, so the page's most consequential actions (Suspend, Deactivate) had
the least readable labels; success was white on green-600, 3.3:1. The colours are Tailwind's; the ratio is
computed, not asserted by hand. Ghost, link and outline buttons have no background of their own and soft ones a
translucent one, so their colour is blended over the dark surfaces buttons sit on (slate-800 cards, the slate-900
page); inverse sits on the customer-view banner's amber.
"""

import re

from django.template import Context, Template
from django.test import SimpleTestCase

# Tailwind palette values for the classes the variants use.
PALETTE = {
    "white": "#ffffff",
    "slate-300": "#cbd5e1",
    "slate-500": "#64748b",
    "slate-600": "#475569",
    "slate-700": "#334155",
    "slate-800": "#1e293b",
    "slate-900": "#0f172a",
    "blue-300": "#93c5fd",
    "blue-400": "#60a5fa",
    "blue-600": "#2563eb",
    "blue-700": "#1d4ed8",
    "red-300": "#fca5a5",
    "red-400": "#f87171",
    "red-500": "#ef4444",
    "red-600": "#dc2626",
    "red-700": "#b91c1c",
    "orange-300": "#fdba74",
    "orange-500": "#f97316",
    "amber-300": "#fcd34d",
    "amber-400": "#fbbf24",
    "yellow-500": "#eab308",
    "yellow-600": "#ca8a04",
    "green-700": "#15803d",
    "green-800": "#166534",
}
DARK_SURFACES = ("slate-800", "slate-900")
SURFACES = {"inverse": ("amber-400",)}  # the customer-view banner
VARIANTS = (
    "primary",
    "secondary",
    "success",
    "danger",
    "warning",
    "info",
    "ghost",
    "link",
    "outline-primary",
    "outline-danger",
    "soft-warning",
    "soft-danger",
    "soft-secondary",
    "inverse",
)
COLOUR = re.compile(r"^(hover:)?(bg|text)-([a-z]+-\d{3}|white|transparent)(?:/(\d+))?$")
RGB = tuple[float, float, float]


def _rgb(name: str) -> RGB:
    value = PALETTE[name]
    return (int(value[1:3], 16) / 255, int(value[3:5], 16) / 255, int(value[5:7], 16) / 255)


def _luminance(rgb: RGB) -> float:
    def channel(value: float) -> float:
        return value / 12.92 if value <= 0.03928 else ((value + 0.055) / 1.055) ** 2.4

    r, g, b = rgb
    return 0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b)


def contrast(first: RGB, second: RGB) -> float:
    high, low = sorted((_luminance(first), _luminance(second)), reverse=True)
    return (high + 0.05) / (low + 0.05)


def blend(background: tuple[str, int], surface: str) -> RGB:
    """The colour a (possibly translucent or transparent) background shows over `surface`."""
    name, alpha = background
    under = _rgb(surface)
    if name == "transparent":
        return under
    over = _rgb(name)
    a = alpha / 100
    return (a * over[0] + (1 - a) * under[0], a * over[1] + (1 - a) * under[1], a * over[2] + (1 - a) * under[2])


class VariantContrastTests(SimpleTestCase):
    def colours(self, variant: str, extra: str) -> dict[str, tuple[str, int]]:
        html = Template('{% load ui_components %}{% button "Suspend" variant="' + variant + '"' + extra + " %}").render(
            Context()
        )
        classes = html.split('class="ui-btn', 1)[1].split('"', 1)[0].split()
        found: dict[str, tuple[str, int]] = {}
        for css in classes:
            match = COLOUR.match(css)
            if match and (match.group(3) in PALETTE or match.group(3) == "transparent"):
                key = ("hover:" if match.group(1) else "") + match.group(2)
                self.assertNotIn(key, found, f"{variant}: two {key} colours in {classes}")
                found[key] = (match.group(3), int(match.group(4) or 100))
        self.assertIn("text", found, f"{variant}: no text colour in {classes}")
        self.assertIn("bg", found, f"{variant}: no background in {classes}")
        return found

    def test_every_variant_is_readable_at_rest_and_on_hover_for_links_and_buttons(self) -> None:
        for variant in VARIANTS:
            for extra in ("", ' href="/x/"'):
                found = self.colours(variant, extra)
                states = {
                    "rest": (found["text"], found["bg"]),
                    "hover": (found.get("hover:text", found["text"]), found.get("hover:bg", found["bg"])),
                }
                for surface in SURFACES.get(variant, DARK_SURFACES):
                    for state, (text, background) in states.items():
                        element = "link" if extra else "button"
                        with self.subTest(variant=variant, element=element, state=state, on=surface):
                            ratio = contrast(_rgb(text[0]), blend(background, surface))
                            self.assertGreaterEqual(ratio, 4.5, f"{text[0]} on {background} over {surface}")

    def test_each_named_variant_has_its_own_look(self) -> None:
        """A misspelt variant falls back to secondary; a variant that silently did the same would pass the test above."""
        looks = {variant: self.colours(variant, "") for variant in VARIANTS}
        secondary = looks.pop("secondary")
        looks.pop("info")  # info is primary's colour by design
        for variant, look in looks.items():
            with self.subTest(variant=variant):
                self.assertNotEqual(look, secondary)
