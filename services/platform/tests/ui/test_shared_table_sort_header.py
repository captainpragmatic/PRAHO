"""The shared table sends a sort request only for a column that has a sort URL.

The header's `{% if header.sort_url %}` was split across lines. Django reads a tag only on one
line, so the condition reached the page as text: every sortable column got `hx-get`, an empty
one when it had no URL, and the button carried `{%`, `if` and `%}` as junk attributes.
"""

from __future__ import annotations

from django.template.loader import render_to_string
from django.test import SimpleTestCase


class SharedTableSortHeaderTests(SimpleTestCase):
    def render(self, header: dict[str, object]) -> str:
        return render_to_string("components/table.html", {"headers": [header], "rows": []})

    def test_a_sortable_column_without_a_url_sends_no_request(self) -> None:
        html = self.render({"label": "Name", "sortable": True})

        self.assertNotIn("hx-get", html)
        self.assertNotIn("{%", html)

    def test_a_sortable_column_with_a_url_requests_it(self) -> None:
        html = self.render({"label": "Date", "sortable": True, "sort_url": "/orders/?sort=date"})

        self.assertIn('hx-get="/orders/?sort=date"', html)
        self.assertIn('hx-target="#table-container"', html)
        self.assertNotIn("{%", html)
