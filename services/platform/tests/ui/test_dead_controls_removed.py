"""Dead controls and latent breakage the button audit found stay gone.

- The mobile menu's guest branch linked `{% url 'users:register' %}`, a route that doesn't exist: a plain `{% url %}`
  raises, so the day that branch rendered, every page would answer 500.
- table_enhanced shipped an inline script whose functions nothing calls, and "sortable" headers rendered as buttons
  that sort nothing.
- secure_alert and the trace report emitted inline onclick= handlers, which the CSP blocks.
- server_detail's tab script restyled every `nav button` on the page, including the header's menu triggers.
- The mobile staff menu lacked Promotions, Audit Management and Create Ticket.
"""

from __future__ import annotations

import re
from pathlib import Path

from django.template.loader import render_to_string
from django.test import SimpleTestCase, TestCase
from django.urls import NoReverseMatch, reverse

from apps.users.models import User

PLATFORM = Path(__file__).resolve().parents[2]
URL_NAME = re.compile(r"\{%\s*url\s+['\"]([\w:.-]+)['\"]")
INLINE_HANDLER = re.compile(r"""\son[a-z]+\s*=\s*['"]""")


def _route_exists(name: str) -> bool:
    """False for a missing route or a misspelt namespace; a route that only needs arguments exists."""
    try:
        reverse(name)
    except NoReverseMatch as error:
        message = str(error)
        return (
            "is not a valid view function or pattern name" not in message
            and "is not a registered namespace" not in message
        )
    return True


class TemplateUrlNamesTests(SimpleTestCase):
    def test_the_check_catches_a_missing_route_and_a_misspelt_namespace(self) -> None:
        self.assertFalse(_route_exists("users:register"))
        self.assertFalse(_route_exists("usres:user_profile"))
        self.assertTrue(_route_exists("users:user_profile"))
        self.assertTrue(_route_exists("provisioning:service_detail"))  # needs an argument; still a real route

    def test_every_named_url_in_platform_templates_exists(self) -> None:
        names = set()
        for path in (PLATFORM / "templates").rglob("*.html"):
            if "styleguide" in path.parts:
                continue
            names.update(URL_NAME.findall(path.read_text(encoding="utf-8")))
        self.assertGreater(len(names), 200)  # the scan finds the tags at all
        self.assertIn("audit:management_dashboard", names)  # including the newest (mobile menu)
        unknown = {name for name in names if not _route_exists(name)}
        self.assertEqual(sorted(unknown), [])


class InertMarkupTests(SimpleTestCase):
    def test_the_enhanced_table_has_no_inline_script_or_sort_buttons(self) -> None:
        html = render_to_string(
            "components/table_enhanced.html",
            {"columns": [{"key": "name", "label": "Name", "sortable": True}], "rows": [], "include_js": True},
        )
        self.assertNotIn("<script", html)
        self.assertNotIn("<button", html)
        self.assertIn("Name", html)

    def test_no_python_template_code_emits_an_inline_handler(self) -> None:
        sources = [*(PLATFORM / "apps/ui/templatetags").glob("*.py"), PLATFORM / "apps/common/trace_middleware.py"]
        offenders = [
            str(p.relative_to(PLATFORM)) for p in sources if INLINE_HANDLER.search(p.read_text(encoding="utf-8"))
        ]
        self.assertEqual(offenders, [])

    def test_the_server_page_tab_script_touches_only_its_tabs(self) -> None:
        source = (PLATFORM / "templates/provisioning/virtualmin/server_detail.html").read_text(encoding="utf-8")
        self.assertNotIn("querySelectorAll('nav button')", source)


class MobileStaffMenuTests(TestCase):
    def test_the_mobile_menu_offers_what_the_desktop_menu_does(self) -> None:
        self.client.force_login(User.objects.create_superuser(email="menu-root@example.test", password="pw"))
        html = self.client.get(reverse("dashboard")).content.decode()
        for path in ("/promotions/admin/", "/audit/management/", "/tickets/create/"):
            with self.subTest(path=path):
                self.assertGreaterEqual(html.count(f'href="{path}"'), 2, "desktop and mobile")
