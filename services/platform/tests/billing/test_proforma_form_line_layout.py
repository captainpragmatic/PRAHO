"""The proforma form's line total fits its column, and the header lines up with the rows.

The total first sat in a one-twelfth column with no `nowrap`, so the amount and the currency broke
onto two lines. Two-twelfths with `nowrap` fixed that for small amounts, but a 100,000+ total still
overflowed its cell at md widths (narrowest at about 1024 pixels, where the form sits in a 2/3
column). Now the amount is grouped by Intl.NumberFormat with tabular figures, the currency is named
once in the column header, and the total column has a fixed minimum width in the shared
`proforma-line-grid` template (assets/css/platform.css).

The header and each row are separate grids, so they line up only because they use that same named
template, whose total minimum is fixed rather than sized from each row's own content. The row
exists three times (a saved line, the empty first line and the script's template for added lines),
and all three must keep the same layout. A browser test (tests/e2e/platform/
test_proforma_line_total_layout.py) measures the rendered result.
"""

from __future__ import annotations

import re
from pathlib import Path

from django.conf import settings
from django.test import SimpleTestCase

TEMPLATE = Path(settings.BASE_DIR) / "templates" / "billing" / "proforma_form.html"
PLATFORM_CSS = Path(settings.BASE_DIR).parents[1] / "assets" / "css" / "platform.css"
ROW_START = '<div class="proforma-line grid grid-cols-2 md:proforma-line-grid'
HEADER_RE = re.compile(r'<div class="hidden md:grid md:proforma-line-grid[^"]*">(.*?)</div>\n\s*\n', re.S)
# A row's own cells are the only elements with a mobile column span.
CELL_RE = re.compile(r'<div class="col-span-(\d)( md:col-span-\d)?([^"]*)"')


class ProformaLineLayoutTests(SimpleTestCase):
    def setUp(self) -> None:
        self.source = TEMPLATE.read_text(encoding="utf-8")

    def _rows(self) -> list[str]:
        starts = [match.start() for match in re.finditer(re.escape(ROW_START), self.source)]
        ends = [*starts[1:], len(self.source)]
        return [self.source[start:end] for start, end in zip(starts, ends, strict=True)]

    def test_every_copy_of_the_line_total_stays_on_one_line_in_tabular_figures(self) -> None:
        totals = re.findall(r'<div class="line-total ([^"]*)">([^<]*)</div>', self.source)

        self.assertEqual(len(totals), 3)
        for classes, text in totals:
            for required in ("whitespace-nowrap", "tabular-nums", "min-w-0", "text-sm"):
                self.assertIn(required, classes.split())
            # The amount alone: the currency is in the column header.
            self.assertNotIn("currency", text)

    def test_every_row_copy_has_the_same_cells_on_the_shared_template(self) -> None:
        rows = self._rows()

        self.assertEqual(len(rows), 3)
        for row in rows:
            cells = CELL_RE.findall(row)[:6]
            # Description, quantity, unit price, VAT rate, total, remove: two mobile columns, and on
            # md one track each of the shared template, so no cell spans more than one there.
            self.assertEqual([int(span) for span, _md, _rest in cells], [2, 1, 1, 1, 1, 2])
            self.assertEqual([md for _span, md, _rest in cells], [" md:col-span-1", "", "", "", "", " md:col-span-1"])
            for _span, _md, rest in cells:
                self.assertIn("min-w-0", rest.split())

    def test_the_header_uses_the_same_template_and_names_the_currency(self) -> None:
        header = HEADER_RE.search(self.source)
        assert header is not None
        cells = re.findall(r'<div class="([^"]*)">(.*?)</div>', header.group(1))

        # One header cell per row cell, the last (remove) left empty.
        self.assertEqual(len(cells), 6)
        self.assertEqual(cells[-1][1], "")
        self.assertIn("text-right", cells[4][0].split())
        self.assertIn('<span class="currency-label">{{ selected_currency }}</span>', cells[4][1])

    def test_the_total_track_has_a_fixed_minimum_not_a_content_sized_one(self) -> None:
        css = PLATFORM_CSS.read_text(encoding="utf-8")
        rule = re.search(r"@utility proforma-line-grid \{(.*?)\}", css, re.S)
        assert rule is not None
        tracks = re.findall(r"minmax\(([^,]+),\s*([^)]+)\)", rule.group(1))

        self.assertEqual(len(tracks), 6)
        total_min = tracks[4][0].strip()
        # max-content would size each row's track from its own amount, and the separate header and
        # row grids would drift apart exactly when a long total appears.
        self.assertRegex(total_min, r"^\d+(\.\d+)?rem$")
        self.assertGreaterEqual(float(total_min.removesuffix("rem")), 8.5)

    def test_the_script_formats_amounts_with_grouping_and_no_currency(self) -> None:
        self.assertIn("new Intl.NumberFormat(document.documentElement.lang", self.source)
        self.assertIn("line.querySelector('.line-total').textContent = formatAmount(lineTotal);", self.source)
        self.assertNotIn("toFixed(2)", self.source)
