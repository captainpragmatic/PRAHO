"""Real Chromium lays out the Security template with model data and local assets."""

from __future__ import annotations

import mimetypes
from dataclasses import asdict
from datetime import timedelta
from pathlib import Path
from urllib.parse import urlsplit
from uuid import uuid4

import pytest
from django.contrib.staticfiles import finders
from django.core.paginator import Paginator
from django.http import QueryDict
from django.template.loader import render_to_string
from django.test import RequestFactory
from django.utils import timezone
from playwright.sync_api import Browser, Route

from apps.security.addresses import address_bounds
from apps.security.forms import SecurityFilterForm
from apps.security.models import SecurityDecision, SecuritySource
from apps.security.presentation import SourceStatus
from apps.users.models import User


@pytest.mark.parametrize("width", [390, 820, 1280])
def test_security_page_fits_viewport_with_long_ip_and_scenario(browser: Browser, width: int, tmp_path: Path) -> None:
    user = User(email="security-layout@example.test", staff_role="support", is_staff=True)
    source = SecuritySource(
        kind="portal",
        transport="ssh",
        hostname="qualification-portal-with-a-long-hostname.example.test",
        installation_id=uuid4(),
        configuration_digest="a" * 64,
    )
    value = "2001:db8:767:feed:ffff:eeee:dddd:cccc"
    now = timezone.now()
    decision = SecurityDecision(
        source=source,
        remote_id=1,
        source_created_at=now,
        expires_at=now + timedelta(minutes=5),
        scenario="qualification/" + "long-scenario-" * 12,
        type="ban",
        scope="ip",
        value=value,
        origin="crowdsec",
        **asdict(address_bounds("ip", value)),
    )
    request = RequestFactory().get("/security/")
    request.user = user
    filters = SecurityFilterForm(QueryDict("state=active"))
    filters.fields.pop("simulated")
    filters.fields["source"].choices = [("", "All sources"), (str(source.pk), source.hostname)]
    html = render_to_string(
        "security/dashboard.html",
        {
            "user": user,
            "request": request,
            "page_title": "Security",
            "kind": "decisions",
            "filters": filters,
            "security_page": Paginator([decision], 25).get_page(1),
            "query": "",
            "source_statuses": [
                SourceStatus(
                    source,
                    None,
                    "Synchronization disabled",
                    "Reported running",
                    "Simulation; bans cleared",
                    "Unqualified or unknown",
                    "Not current",
                    True,
                )
            ],
            "can_view_security": True,
            "business_items": [],
            "support_items": [{"text": "Security", "url": "/security/", "icon": "shield"}],
        },
    )
    context = browser.new_context(viewport={"width": width, "height": 900})

    def content(route: Route) -> None:
        path = urlsplit(route.request.url).path
        if path == "/security/":
            route.fulfill(status=200, body=html, content_type="text/html")
        elif path.startswith("/static/") and ".." not in path:
            name = path.removeprefix("/static/")
            found = finders.find(name)
            if isinstance(found, str):
                route.fulfill(path=found, content_type=mimetypes.guess_type(found)[0] or "application/octet-stream")
            else:
                route.fulfill(status=404, body="")
        else:
            route.abort()

    try:
        context.route("**/*", content)
        page = context.new_page()
        page.goto("https://security-fixture.invalid/security/", wait_until="networkidle")
        assert page.get_by_role("heading", name="Security", exact=True).is_visible()
        assert page.get_by_role("region", name="Recorded security activity").is_visible()
        assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth + 1")
        headers = page.locator("table thead th")
        assert headers.nth(0).bounding_box()["width"] >= 200
        assert headers.nth(2).bounding_box()["width"] >= 200
        page.screenshot(path=str(tmp_path / f"security-{width}.png"), full_page=True)
        if width < 1024:
            page.get_by_role("button", name="Toggle mobile menu").click()
            assert page.locator('#mobile-menu a[href="/security/"]').is_visible()
        else:
            assert page.get_by_role("button", name="Support", exact=False).is_visible()
    finally:
        context.close()
