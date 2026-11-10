"""The service page shows a tab only for what the service has (#821)."""

from html.parser import HTMLParser

from django.template.loader import render_to_string
from django.test import SimpleTestCase


class _Tabs(HTMLParser):
    def __init__(self, markup: str) -> None:
        super().__init__()
        self.names: list[str | None] = []
        self.feed(markup)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if dict(attrs).get("role") == "tab":
            self.names.append(dict(attrs)["data-tab"])


class ServiceDetailTabsTests(SimpleTestCase):
    def tabs(self, **context: object) -> list[str | None]:
        return _Tabs(render_to_string("components/service_detail_tabs.html", context)).names

    def test_usage_is_only_for_an_active_service_and_domains_only_when_there_are_some(self) -> None:
        self.assertEqual(self.tabs(service_status="suspended"), ["overview", "billing"])
        self.assertEqual(self.tabs(service_status="active"), ["overview", "usage", "billing"])
        self.assertEqual(
            self.tabs(service_status="active", show_domains=["a.example"]), ["overview", "usage", "billing", "domains"]
        )
