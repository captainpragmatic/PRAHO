"""ticket_create's category/priority <select>s, swapped from hardcoded <option> tags to
{% input_field type="select" %} (Phase 4 TMPL003) - the historical default selects "normal"
whenever priority is anything other than low/high/critical, including when priority was never
set at all (GET). input_field selects by exact value match, so a regression here would make the
browser default to whichever option renders first in the list, not "normal".
"""

from __future__ import annotations

import time
from datetime import timedelta
from html.parser import HTMLParser
from unittest.mock import patch

from django.test import TestCase
from django.urls import reverse
from django.utils import timezone


class _SelectOptionFinder(HTMLParser):
    """Finds every <option> under the <select> with the given name, recording which is
    selected - a page-wide `assertIn('selected', content)` would pass even if the wrong
    option (or none) carried it, since other selects/tabs on the page use the same word."""

    def __init__(self, select_name: str) -> None:
        super().__init__(convert_charrefs=True)
        self.select_name = select_name
        self.options: list[dict[str, str | bool]] = []
        self._in_target_select = False
        self._depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_dict = dict(attrs)
        if tag == "select":
            self._in_target_select = attr_dict.get("name") == self.select_name
            self._depth = 1 if self._in_target_select else 0
        elif tag == "option" and self._in_target_select:
            self.options.append({"value": attr_dict.get("value", ""), "selected": "selected" in attr_dict})

    def handle_endtag(self, tag: str) -> None:
        if tag == "select" and self._in_target_select:
            self._in_target_select = False


def _selected_value(html: str, select_name: str) -> str | None:
    parser = _SelectOptionFinder(select_name)
    parser.feed(html)
    selected = [opt for opt in parser.options if opt["selected"]]
    assert len(selected) <= 1, f"more than one <option> marked selected in {select_name!r}: {selected}"
    return str(selected[0]["value"]) if selected else None


class TicketCreatePriorityDefaultTests(TestCase):
    def setUp(self) -> None:
        now = timezone.now()
        session = self.client.session
        session.update(
            {
                "user_id": 7,
                "customer_id": 1,
                "selected_customer_id": 1,
                "user_memberships": [{"customer_id": 1, "role": "owner"}],
                "user_memberships_fetched_at": time.time(),
                "session_auth_hash": "test-session",
                "validated_at": now.isoformat(),
                "next_validate_at": (now + timedelta(minutes=10)).isoformat(),
            }
        )
        session.save()

    def test_get_selects_normal_priority_by_default(self) -> None:
        response = self.client.get(reverse("tickets:create"))

        self.assertEqual(response.status_code, 200)
        content = response.content.decode()
        self.assertEqual(_selected_value(content, "priority"), "normal")

    def test_get_selects_the_blank_category_by_default(self) -> None:
        response = self.client.get(reverse("tickets:create"))

        content = response.content.decode()
        self.assertEqual(_selected_value(content, "category"), "")

    def test_validation_error_rerender_keeps_options_and_submitted_selection(self) -> None:
        """An empty title fails validation before the Platform call - the error re-render must
        still carry both select's full option lists and the submitted priority/category, not an
        empty <select> (dead context that nothing populates would do exactly that silently)."""
        response = self.client.post(
            reverse("tickets:create"),
            {"title": "", "description": "Something is broken", "priority": "high", "category": "hosting"},
        )

        self.assertEqual(response.status_code, 200)
        content = response.content.decode()
        self.assertIn('<option value="low"', content)
        self.assertIn('<option value="critical"', content)
        self.assertEqual(_selected_value(content, "priority"), "high")
        self.assertEqual(_selected_value(content, "category"), "hosting")

    def test_validation_error_rerender_preserves_typed_description(self) -> None:
        response = self.client.post(
            reverse("tickets:create"),
            {"title": "", "description": "Something is broken", "priority": "normal", "category": ""},
        )

        self.assertIn("Something is broken", response.content.decode())

    @patch("apps.tickets.views.tickets_api.create_ticket")
    def test_api_error_rerender_keeps_options_and_submitted_selection(self, mock_create) -> None:
        from apps.tickets.services import PlatformAPIError  # noqa: PLC0415

        mock_create.side_effect = PlatformAPIError("boom", status_code=503)

        response = self.client.post(
            reverse("tickets:create"),
            {
                "title": "Still broken",
                "description": "Something is broken",
                "priority": "critical",
                "category": "technical",
            },
        )

        self.assertEqual(response.status_code, 200)
        content = response.content.decode()
        self.assertEqual(_selected_value(content, "priority"), "critical")
        self.assertEqual(_selected_value(content, "category"), "technical")
