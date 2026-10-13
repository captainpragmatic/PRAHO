"""No page builds a /app/… URL: only the bare /app/ dashboard alias exists, nothing under it.

The order item script, four list paginations, the domain list's actions, the availability check, the
proforma send button and the GDPR downloads all built /app/… URLs by hand, and every one answered
404. Pages build URLs with `{% url %}` or `reverse()`; this scan keeps the prefix from coming back.
"""

import re
from collections.abc import Iterator
from pathlib import Path

from django.test import SimpleTestCase
from django.urls import Resolver404, resolve

ROOT = Path(__file__).resolve().parents[4]
PLATFORM = ROOT / "services" / "platform"
# A quoted literal that starts with the prefix: '/app/…', "/app/…" or `/app/…`.
APP_PREFIX = re.compile(r"""["'`]/app/""")
SCANNED = (
    (PLATFORM / "apps", "*.py"),
    (PLATFORM / "templates", "*.html"),
    (PLATFORM / "static" / "js", "*.js"),
    (ROOT / "shared" / "ui" / "templates", "*.html"),
)


def _sources() -> Iterator[Path]:
    for base, pattern in SCANNED:
        for path in sorted(base.rglob(pattern)):
            if path.name.endswith(".min.js") or {"tests", "migrations"} & set(path.relative_to(base).parts):
                continue
            yield path


class NoAppUrlPrefixTests(SimpleTestCase):
    def test_nothing_is_served_under_the_prefix(self) -> None:
        for path in ("/app/orders/list/", "/app/domains/check-availability/", "/app/audit/logs/list/"):
            with self.subTest(path=path), self.assertRaises(Resolver404):
                resolve(path)

    def test_the_scan_reads_every_tree_and_finds_the_prefix(self) -> None:
        scanned = {path.relative_to(ROOT).as_posix() for path in _sources()}
        for expected in (
            "services/platform/apps/domains/views.py",
            "services/platform/templates/orders/partials/order_list.html",
            "services/platform/static/js/orders-items.js",
            "shared/ui/templates/components/pagination.html",
        ):
            self.assertIn(expected, scanned)
        for literal in ("fetch('/app/x/')", 'href="/app/x/"', "fetch(`/app/x/${id}/`)"):
            self.assertRegex(literal, APP_PREFIX)
        self.assertNotRegex("'/apps/x/'", APP_PREFIX)

    def test_no_page_builds_an_app_prefixed_url(self) -> None:
        hits = [
            f"{path.relative_to(ROOT)}:{number}"
            for path in _sources()
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
            if APP_PREFIX.search(line)
        ]
        self.assertEqual(hits, [])
