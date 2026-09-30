"""Serialize extra button attributes without changing their browser values.

Both services keep an identical copy because their Python imports are isolated.
Only inert HTML/data attributes and the legacy hx-include selector are accepted.
"""

import re
from collections.abc import Mapping
from html.parser import HTMLParser

from django.utils.html import escape

_ATTRIBUTE_NAME = re.compile(r"(?:data-[a-z0-9_-]+|aria-[a-z0-9_-]+)\Z")
_ALLOWED = frozenset({"name", "value", "title", "tabindex", "role", "form", "hx-include"})


class _AttributeParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.attributes: list[tuple[str, str | None]] = []
        self.seen = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if not self.seen:
            self.seen = True
            if tag == "button":
                self.attributes = attrs


def serialize_button_attributes(raw: object) -> str:
    """Escape values, retain syntax quotes, and discard executable attributes."""
    attributes: list[tuple[str, str | None]]
    if isinstance(raw, Mapping):
        attributes = [(str(key).lower(), str(value)) for key, value in raw.items() if value is not None]
    else:
        parser = _AttributeParser()
        parser.feed("<button " + str(raw or "") + ">")
        attributes = parser.attributes
    accepted: dict[str, str] = {}
    for name, value in attributes:
        if name == "data-action":
            # The explicit data_action argument owns delegated behavior.
            continue
        if value is not None and (name in _ALLOWED or _ATTRIBUTE_NAME.fullmatch(name)):
            accepted.setdefault(name, value)
    return " ".join(f'{name}="{escape(value)}"' for name, value in accepted.items())


_DATA_ATTR_KEY = re.compile(r"[a-z0-9_-]+\Z")


def sanitize_data_attrs(raw: Mapping[str, object] | None) -> dict[str, object]:
    """Drop any data_attrs key that isn't a bare data-* suffix.

    components/input.html renders these as `data-{{ key }}="{{ value }}"` with the KEY
    interpolated unescaped - a key containing a space, `=`, or `>` would close the attribute
    and open a new one (Django auto-escapes the VALUE, but never validated the key). No current
    caller passes anything but a literal dict, but the key is still attacker-shaped if that
    ever changes, so the same class of check serialize_button_attributes already does for
    buttons applies here too.
    """
    if not raw:
        return {}
    return {str(key): value for key, value in raw.items() if _DATA_ATTR_KEY.fullmatch(str(key).lower())}
