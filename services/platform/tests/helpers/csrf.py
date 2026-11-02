"""Read the CSRF token a Platform page gives htmx, the way the browser does.

The token must come from the `<body>` tag's `hx-headers`, not from the first `X-CSRFToken` anywhere on the page
or from the cookie: a control that carries its own header, or the cookie's secret, is accepted by Django whether or
not the page gives htmx a token, so a test built on either passes without the page doing anything.
"""

from __future__ import annotations

import json
from html.parser import HTMLParser

TOKEN_LENGTH = 64  # Django's masked token


class _BodyHeaders(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.headers: str | None = None
        self.meta_token: str | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if tag == "body" and self.headers is None:
            self.headers = values.get("hx-headers") or ""
        if tag == "meta" and values.get("name") == "csrf-token":
            self.meta_token = values.get("content") or ""


def _parse(html: str) -> _BodyHeaders:
    parser = _BodyHeaders()
    parser.feed(html)
    return parser


def body_csrf_token(html: str) -> str:
    """The X-CSRFToken the page's `<body hx-headers>` gives every htmx request; raises if there is none."""
    headers = _parse(html).headers
    if not headers:
        raise AssertionError("the page's <body> carries no hx-headers")
    token = json.loads(headers).get("X-CSRFToken", "")
    if len(token) != TOKEN_LENGTH:
        raise AssertionError(f"the <body> hx-headers carry no usable X-CSRFToken: {headers!r}")
    return str(token)


def meta_csrf_token(html: str) -> str | None:
    """The `<meta name="csrf-token">` content `fetch` callers read, or None if the page has none."""
    return _parse(html).meta_token
