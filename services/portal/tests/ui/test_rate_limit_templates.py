from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from django.template import Context, Template
from django.test import SimpleTestCase

REPO_ROOT = Path(__file__).resolve().parents[4]


class RateLimitTemplateTests(SimpleTestCase):
    def _render_partial(self, template_path: str) -> str:
        return Template('{% include "' + template_path + '" %}').render(
            Context(
                {
                    "rate_limited": True,
                    "rate_limit_message": "We are receiving many requests right now.",
                    "rate_limit_retry_url": "/dashboard/",
                    "request": SimpleNamespace(get_full_path=lambda: "/dashboard/"),
                }
            )
        )

    def test_invoices_partial_shows_rate_limit_message(self) -> None:
        rendered = self._render_partial("billing/partials/invoices_table.html")
        self.assertIn("Temporarily rate limited", rendered)
        self.assertIn("Try again", rendered)
        self.assertNotIn("No documents found", rendered)

    def test_tickets_partial_shows_rate_limit_message(self) -> None:
        rendered = self._render_partial("tickets/partials/tickets_table.html")
        self.assertIn("Temporarily rate limited", rendered)
        self.assertIn("Try again", rendered)
        self.assertNotIn("No Support Tickets Yet", rendered)

    def test_services_partial_shows_rate_limit_message(self) -> None:
        rendered = self._render_partial("services/partials/services_table.html")
        self.assertIn("Temporarily rate limited", rendered)
        self.assertIn("Try again", rendered)
        self.assertNotIn("No services found", rendered)

    def test_dashboard_template_contains_rate_limit_states(self) -> None:
        content = (REPO_ROOT / "services" / "portal" / "templates" / "dashboard" / "dashboard.html").read_text(
            encoding="utf-8"
        )
        self.assertIn("{% if rate_limited %}", content)
        self.assertIn("Billing data is temporarily rate limited", content)
        self.assertIn("Ticket data is temporarily rate limited", content)

    def test_base_template_renders_rate_limit_banner_slot(self) -> None:
        content = (REPO_ROOT / "services" / "portal" / "templates" / "base.html").read_text(encoding="utf-8")
        self.assertIn("{% if rate_limit_banner %}", content)
        self.assertIn('include "components/account_status_banner.html" with banner=rate_limit_banner', content)
