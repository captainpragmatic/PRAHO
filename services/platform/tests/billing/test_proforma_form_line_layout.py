"""The proforma form's line total fits its column on one line.

The total sat in a one-twelfth column with no `nowrap`, so the amount and the currency broke onto
two lines, while the quantity, a short number, took two twelfths. The row exists three times (a
saved line, the empty first line and the script's template for added lines), and all three must
keep the same layout, under a header whose columns line up with them.
"""

from __future__ import annotations

import re
from pathlib import Path

from django.conf import settings
from django.test import SimpleTestCase

TEMPLATE = Path(settings.BASE_DIR) / "templates" / "billing" / "proforma_form.html"
ROW_START = '<div class="proforma-line grid grid-cols-2 md:grid-cols-12'
# A row's own columns are the only elements with both a mobile and a desktop span.
COLUMN_RE = re.compile(r'<div class="col-span-\d md:col-span-(\d+)')


class ProformaLineLayoutTests(SimpleTestCase):
    def setUp(self) -> None:
        self.source = TEMPLATE.read_text(encoding="utf-8")

    def test_every_copy_of_the_line_total_stays_on_one_line(self) -> None:
        totals = re.findall(r'<div class="line-total ([^"]*)"', self.source)

        self.assertEqual(len(totals), 3)
        for classes in totals:
            self.assertIn("whitespace-nowrap", classes.split())

    def test_every_row_copy_has_the_same_columns_and_fills_the_grid(self) -> None:
        starts = [match.start() for match in re.finditer(re.escape(ROW_START), self.source)]
        ends = [*starts[1:], len(self.source)]
        rows = [COLUMN_RE.findall(self.source[start:end])[:6] for start, end in zip(starts, ends, strict=True)]

        self.assertEqual(len(rows), 3)
        # Description, quantity, unit price, VAT rate, total, remove.
        for columns in rows:
            self.assertEqual([int(span) for span in columns], [4, 1, 2, 2, 2, 1])

    def test_the_header_lines_up_with_the_row(self) -> None:
        header = re.search(r'<div class="hidden md:grid grid-cols-12[^"]*">(.*?)</div>\n\s*\n', self.source, re.S)
        assert header is not None
        spans = [int(span) for span in re.findall(r'<div class="col-span-(\d+)">', header.group(1))]

        self.assertEqual(spans, [4, 1, 2, 2, 2])
