"""Small rendered-markup and Node harness helpers for UI unit tests."""

from __future__ import annotations

import json
import shutil
import subprocess
from html.parser import HTMLParser
from typing import cast


class Markup(HTMLParser):
    def __init__(self, markup: str) -> None:
        super().__init__(convert_charrefs=True)
        self.elements: list[tuple[str, dict[str, str]]] = []
        self.scripts: list[str] = []
        self._script: list[str] | None = None
        self.feed(markup)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = {name: value or "" for name, value in attrs}
        self.elements.append((tag, attributes))
        if tag == "script" and "src" not in attributes:
            self._script = []

    def handle_data(self, data: str) -> None:
        if self._script is not None:
            self._script.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag == "script" and self._script is not None:
            self.scripts.append("".join(self._script))
            self._script = None

    def find(self, name: str, value: str) -> dict[str, str]:
        matches = [attrs for _tag, attrs in self.elements if attrs.get(name) == value]
        if len(matches) != 1:
            raise AssertionError(f"Expected one element with {name}={value!r}, got {len(matches)}")
        return matches[0]


def dataset(attributes: dict[str, str]) -> dict[str, str]:
    return {
        parts[0] + "".join(part.title() for part in parts[1:]): value
        for name, value in attributes.items()
        if name.startswith("data-")
        for parts in [name[5:].split("-")]
    }


def run_node(harness: str, payload: dict[str, object]) -> dict[str, object]:
    node = shutil.which("node")
    if node is None:
        raise AssertionError("Node.js is required for the UI unit harness.")
    result = subprocess.run(  # noqa: S603 -- fixed local harness, no shell or remote input
        [node, "-e", harness],
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        check=True,
        timeout=10,
    )
    return cast("dict[str, object]", json.loads(result.stdout))
