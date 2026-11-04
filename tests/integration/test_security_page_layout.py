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

from apps.security.action_forms import ActionHistoryFilter, AllowlistForm, BanForm, CoverageForm, ReasonForm
from apps.security.addresses import address_bounds
from apps.security.forms import SecurityFilterForm
from apps.security.models import SecurityActionRequest, SecurityActionTarget, SecurityDecision, SecuritySource
from apps.security.presentation import SourceStatus
from apps.security.source_forms import SourceEnrollmentForm, SourceReasonForm
from apps.users.models import User


def _render_security_page(surface: str) -> str:
    user = User(email="security-layout@example.test", staff_role="admin", is_staff=True)
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
    data = {
        "user": user,
        "request": request,
        "page_title": "Security",
        "kind": "decisions",
        "filters": filters,
        "security_page": Paginator([decision] * 3, 1).get_page(2),
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
        "can_manage_security": True,
        "can_revoke_security": True,
        "csrf_token": "layout-fixture-token",
        "business_items": [],
        "support_items": [{"text": "Security", "url": "/security/", "icon": "shield"}],
    }
    template = "security/dashboard.html"
    if surface in {"ban", "allowlist", "coverage"}:
        form = {"ban": BanForm, "allowlist": AllowlistForm, "coverage": CoverageForm}[surface]()
        if surface == "ban":
            form.fields["sources"].choices = [(str(source.pk), source.hostname)]
        data.update(
            form=form,
            source=source,
            action_title="Security",
            explanation="A bounded recorded action with verified per-target results.",
            actions_enabled=True,
        )
        if surface == "coverage":
            withdraw = ReasonForm()
            withdraw.fields["reason"].widget.attrs["id"] = "id_withdraw_reason"
            data["withdraw_form"] = withdraw
        template = "security/action_form.html"
    elif surface in {"source", "source_edit"}:
        editing = surface == "source_edit"
        form = SourceEnrollmentForm(source=source if editing else None)
        form.fields["virtualmin_server"].choices = [("", "No node")]
        data.update(form=form, source=source if editing else None, retire_form=SourceReasonForm())
        template = "security/source_form.html"
    elif surface in {"results", "history"}:
        action = SecurityActionRequest(
            kind="ban",
            idempotency_key=uuid4(),
            payload={"payload": {"value": value, "cidrs": ["198.51.100.8/32", "2001:db8:767::/48"]}},
            payload_digest="b" * 64,
            reason="Recorded verification reason " * 30,
            status="unknown",
            created_at=now,
        )
        target = SecurityActionTarget(
            action=action,
            source=source,
            operation="ban_put",
            state="unknown",
            expires_at=now + timedelta(minutes=5),
            evidence={"decision_ids": [11]},
        )
        data.update(
            action=action,
            status_label="Unknown",
            targets=[
                {"target": target, "label": "Unknown", "evidence_label": "A dispatched operation may have applied."}
            ],
        )
        template = "security/action_detail.html"
        if surface == "history":
            data.update(
                filters=ActionHistoryFilter(),
                action_page=Paginator([action] * 3, 1).get_page(2),
                summaries=[{"action": action, "label": "Unknown"}],
            )
            template = "security/action_list.html"
    return render_to_string(template, data)


@pytest.mark.parametrize("width", [390, 820, 1280])
@pytest.mark.parametrize(
    "surface", ["dashboard", "ban", "allowlist", "coverage", "source", "source_edit", "results", "history"]
)
def test_security_page_fits_viewport_with_long_ip_and_scenario(
    browser: Browser, width: int, surface: str, tmp_path: Path
) -> None:
    html = _render_security_page(surface)
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
        assert page.locator("main h1").is_visible()
        assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth + 1")
        control_ids = page.locator("main input[id], main select[id], main textarea[id]").evaluate_all(
            "controls => controls.map(control => control.id)"
        )
        assert len(control_ids) == len(set(control_ids)), control_ids
        violations = page.locator("main").evaluate("""main => {
          const failures = [];
          for (const control of main.querySelectorAll('a[href], button, input:not([type="hidden"]), select, textarea, summary')) {
            const box = control.getBoundingClientRect();
            if (!box.width || !box.height || getComputedStyle(control).visibility === 'hidden') continue;
            const checkbox = control.matches('input[type="checkbox"]');
            const targets = checkbox && control.labels.length ? [...control.labels] : [control];
            if (!targets.some(target => {
              const rect = target.getBoundingClientRect();
              return rect.width >= 44 && rect.height >= 44;
            })) failures.push({control: control.id || control.textContent.trim(), width: box.width, height: box.height, checkbox});
            if (control.matches('input, select, textarea') && parseFloat(getComputedStyle(control).fontSize) < 16)
              failures.push({control: control.id, fontSize: getComputedStyle(control).fontSize});
          }
          return failures;
        }""")
        assert violations == [], violations
        for checkbox in page.locator('main input[type="checkbox"]').all():
            label = page.locator(f'label[for="{checkbox.get_attribute("id")}"]')
            label_box = label.bounding_box()
            assert label_box is not None
            was_checked = checkbox.is_checked()
            label.click(position={"x": label_box["width"] - 8, "y": label_box["height"] / 2})
            assert checkbox.is_checked() != was_checked
        for table in page.locator("main table").all():
            assert table.evaluate("table => getComputedStyle(table.closest('[role=region]')).overflowX") == "auto"
        if surface == "dashboard":
            assert page.get_by_role("region", name="Recorded security activity").is_visible()
            headers = page.locator("table thead th")
            assert headers.nth(0).bounding_box()["width"] >= 200
            assert headers.nth(2).bounding_box()["width"] >= 200
        page.evaluate("window.scrollTo(0, 0)")
        page.screenshot(path=str(tmp_path / f"security-{surface}-{width}.png"), full_page=True)
        if width < 1024:
            page.get_by_role("button", name="Toggle mobile menu").click()
            assert page.locator('#mobile-menu a[href="/security/"]').is_visible()
        else:
            assert page.get_by_role("button", name="Support", exact=False).is_visible()
    finally:
        context.close()
