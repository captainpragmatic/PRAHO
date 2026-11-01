"""The cart's rendered Remove button, for tests that check how it is wired.

The button is the button component (it posts the line's hidden fields with hx-include), so tests read the rendered
markup instead of searching the template source for a hand-written <button hx-post=…>.
"""

from __future__ import annotations

from html.parser import HTMLParser

from django.template.loader import render_to_string
from django.urls import reverse

LINE = {"product_slug": "web-pro", "billing_period": "monthly", "domain_name": "example.ro", "quantity": 1}


class _Buttons(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.buttons: list[dict[str, str]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "button":
            self.buttons.append({name: value or "" for name, value in attrs})


def cart_remove_buttons() -> list[dict[str, str]]:
    html = render_to_string("orders/partials/cart_items.html", {"cart_items": [dict(LINE, product_name="Web Pro")]})
    parser = _Buttons()
    parser.feed(html)
    return [b for b in parser.buttons if b.get("hx-post") == reverse("orders:remove_from_cart")]
