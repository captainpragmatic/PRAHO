"""Notification table headings use the dark-mode text colour that keeps WCAG AA contrast on slate-700."""

from __future__ import annotations

import re
from pathlib import Path

from django.test import SimpleTestCase

TEMPLATES = Path(__file__).resolve().parents[2] / "templates" / "notifications"


class NotificationHeaderContrastTests(SimpleTestCase):
    def test_table_headings_use_the_aa_dark_text_colour(self) -> None:
        # dark:text-slate-400 on dark:bg-slate-700 measured 3.94:1 for these 12px headings; slate-300 meets 4.5:1.
        for name in ("email_log_list.html", "template_list.html"):
            with self.subTest(template=name):
                headings = re.findall(r"<th\b[^>]*>", (TEMPLATES / name).read_text(encoding="utf-8"))
                self.assertTrue(headings)
                for heading in headings:
                    self.assertNotIn("dark:text-slate-400", heading)
                    self.assertIn("dark:text-slate-300", heading)
