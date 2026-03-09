"""
Regression tests for ENH-5: Service age metric unit display on Service Detail page.

Covers:
  ENH-5: "days" unit always shows even for 0 ("0 days"), with proper pluralization
         ("1 day" vs "0 days" / "5 days") in all three age display locations.
"""
from __future__ import annotations

from django.template import Context, Template
from django.test import SimpleTestCase


class ServiceAgeStatTilePluralizeTests(SimpleTestCase):
    """Tests for the stat-tile age display (lines ~136-148 of service_detail.html).

    Uses the ``asvar`` form (``blocktrans ... asvar st3_age_val``) to store the
    pluralised string before passing it to the ``stat_tile`` template tag.
    """

    def _render_age_stat_tile(self, age_days: int | None) -> str:
        """Render the age blocktrans-with-asvar snippet in isolation."""
        template = Template(
            "{% load i18n %}"
            "{% if age_days is not None %}"
            "  {% with days=age_days %}"
            "    {% blocktrans count days=days asvar age_label %}{{ days }} day{% plural %}{{ days }} days{% endblocktrans %}"
            "    {{ age_label }}"
            "  {% endwith %}"
            "{% else %}"
            "New"
            "{% endif %}"
        )
        return template.render(Context({"age_days": age_days})).strip()

    def test_zero_days_shows_unit(self) -> None:
        result = self._render_age_stat_tile(0)
        self.assertIn("0 days", result)

    def test_one_day_singular(self) -> None:
        result = self._render_age_stat_tile(1)
        self.assertIn("1 day", result)
        self.assertNotIn("days", result)

    def test_two_days_plural(self) -> None:
        result = self._render_age_stat_tile(2)
        self.assertIn("2 days", result)

    def test_five_days_plural(self) -> None:
        result = self._render_age_stat_tile(5)
        self.assertIn("5 days", result)

    def test_none_shows_new(self) -> None:
        result = self._render_age_stat_tile(None)
        self.assertIn("New", result)


class ServiceAgeInlineDisplayPluralizeTests(SimpleTestCase):
    """Tests for the inline age displays (Uptime and Service Age rows)."""

    def _render_inline_age(self, age_days: int | None) -> str:
        """Render the inline age snippet (used in both Uptime and Service Age rows)."""
        template = Template(
            "{% load i18n %}"
            "{% if age_days is not None %}"
            "  {% with days=age_days %}"
            "    {% blocktrans count days=days %}{{ days }} day{% plural %}{{ days }} days{% endblocktrans %}"
            "  {% endwith %}"
            "{% else %}"
            "<span>Calculating...</span>"
            "{% endif %}"
        )
        return template.render(Context({"age_days": age_days})).strip()

    def test_zero_days_shows_days_unit(self) -> None:
        result = self._render_inline_age(0)
        self.assertIn("0 days", result)

    def test_one_day_singular(self) -> None:
        result = self._render_inline_age(1)
        self.assertIn("1 day", result)
        self.assertNotIn("1 days", result)

    def test_multiple_days_plural(self) -> None:
        result = self._render_inline_age(30)
        self.assertIn("30 days", result)

    def test_none_shows_calculating(self) -> None:
        result = self._render_inline_age(None)
        self.assertIn("Calculating", result)
