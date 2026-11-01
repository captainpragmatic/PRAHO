"""Real customer HTTP/HMAC, manual maintenance, scoped queue and production email templates."""

from __future__ import annotations

import json
import os
import re
import time
from collections.abc import Callable
from datetime import timedelta
from pathlib import Path
from urllib.parse import urlencode

import pytest
from django.conf import settings
from django.utils import timezone
from django_q.models import OrmQ
from playwright.sync_api import Browser, Page, expect

from apps.infrastructure.node_maintenance_execution import create_emergency_window
from apps.infrastructure.node_maintenance_models import (
    NodeMaintenanceDelivery,
    NodeMaintenancePolicy,
    NodeMaintenanceWindow,
)
from apps.notifications.models import EmailLog
from apps.users.models import User
from tests.virtualmin_lab.maintenance_fixtures import FixtureLogin, own_window, read_manifest

pytestmark = pytest.mark.virtualmin_maintenance_lab


def eventually(check: Callable[[], bool], description: str, *, seconds: float = 45) -> None:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if check():
            return
        time.sleep(0.2)
    raise AssertionError(description)


def login(page: Page, origin: str, credentials: FixtureLogin, *, path: str = "/auth/login/") -> None:
    page.goto(origin + path)
    page.locator('#login-form input[name="email"]').fill(credentials["email"])
    page.locator('#login-form input[name="password"]').fill(credentials["password"])
    page.locator('#login-form button[type="submit"]').click()
    expect(page).not_to_have_url(re.compile(r"/(?:auth/)?login/"), timeout=30000)


def navigate_read_only(page: Page, url: str) -> None:
    """Respect the real API burst policy; never retry authentication or an operator POST."""
    deadline = time.monotonic() + 90
    for _ in range(3):
        remaining = deadline - time.monotonic()
        assert remaining > 0, "Read-only navigation exceeded its ninety-second retry budget"
        response = page.goto(url, timeout=min(30000, remaining * 1000))
        assert response is not None
        if response.status != 429:
            assert response.status == 200, f"Read-only navigation returned HTTP{response.status}"
            return
        raw = response.headers.get("retry-after", "")
        assert raw.isdigit(), "Actual429 response did not provide a numeric Retry-After"
        delay = int(raw)
        assert 0 < delay <= 60 and time.monotonic() + delay < deadline, (
            f"Actual429 Retry-After={raw!r} exceeds the bounded navigation budget"
        )
        page.wait_for_timeout(delay * 1000)
    raise AssertionError("Read-only navigation remained rate limited after three actual HTTP attempts")


def post(page: Page, origin: str, path: str, data: dict[str, object]) -> None:
    csrf = next(
        cookie["value"] for cookie in page.context.cookies() if cookie["name"] == "maintenance_lab_platform_csrf"
    )
    response = page.request.post(
        origin + path,
        data=urlencode(data, doseq=True),
        max_redirects=0,
        headers={"X-CSRFToken": csrf, "Origin": origin, "Content-Type": "application/x-www-form-urlencoded"},
    )
    assert response.status == 302, response.text()


def configure_policy(page: Page, origin: str, node_id: str) -> None:
    now = timezone.now()
    path = f"/infrastructure/maintenance/servers/{node_id}/policy/"
    page.goto(origin + path)
    post(
        page,
        origin,
        path,
        {
            "revision": "0",
            "timezone": "UTC",
            "weekdays": [str(day) for day in range(7)],
            "starts_time": (now - timedelta(hours=2)).strftime("%H:%M"),
            "ends_time": (now + timedelta(hours=2)).strftime("%H:%M"),
            "max_defer_minutes": "30",
        },
    )
    assert NodeMaintenancePolicy.objects.get(node_id=node_id).timezone == "UTC"


def schedule(page: Page, origin: str, node_id: str, note: str, *, future: bool = False) -> NodeMaintenanceWindow:
    starts = timezone.now() + (timedelta(minutes=10) if future else -timedelta(seconds=2))
    ends = starts + (timedelta(minutes=30) if future else timedelta(seconds=20))
    policy = NodeMaintenancePolicy.objects.get(node_id=node_id)
    post(
        page,
        origin,
        f"/infrastructure/maintenance/servers/{node_id}/create/",
        {
            "policy_revision": str(policy.revision),
            "kind": "panel_update",
            "execution_mode": "manual",
            "starts_at": starts.isoformat(),
            "ends_at": ends.isoformat(),
            "expects_downtime": "on",
            "expected_downtime_minutes": "",
            "customer_note": note,
        },
    )
    window = NodeMaintenanceWindow.objects.get(node_id=node_id, customer_note=note)
    own_window(window.pk)
    return window


def action(page: Page, origin: str, window: NodeMaintenanceWindow, operation: str, **extra: object) -> None:
    window.refresh_from_db()
    post(
        page,
        origin,
        f"/infrastructure/maintenance/windows/{window.pk}/{operation}/",
        {
            "revision": str(window.revision),
            "reason": "Owned acceptance fixture operator decision",
            "confirmation": "on",
            **extra,
        },
    )


def wait_for_mail(window: NodeMaintenanceWindow, kind: str, *, revision: int | None = None) -> None:
    def sent() -> bool:
        deliveries = NodeMaintenanceDelivery.objects.filter(window=window, kind=kind)
        if revision is not None:
            deliveries = deliveries.filter(revision=revision)
        return deliveries.exists() and not deliveries.exclude(email_log__status="sent").exists()

    eventually(sent, f"Actual scoped worker did not send the {kind} production notice")


def switch_company(page: Page, origin: str, customer_id: int) -> None:
    # The existing company selector lives on Account Settings, not the dashboard.
    navigate_read_only(page, origin + "/profile/")
    page.locator("#customerSelectorBtn").click()
    expect(page.locator("#customerSelectorDropdown")).to_be_visible()
    option = page.locator(f'#customerSelectorDropdown button[value="{customer_id}"]')
    option.click()
    # The real CSRF-protected POST verifies current membership on Platform and
    # rerenders this selected state from the Portal session after navigation.
    expect(option).to_have_class(re.compile("bg-blue-900"))


def test_real_portal_manual_emergency_corrections_and_owned_worker(browser: Browser) -> None:  # noqa: PLR0915 -- one real HTTP fixture follows ordered lifecycle, correction and dispatch outcomes
    assert os.environ.get("VIRTUALMIN_MAINTENANCE_LAB") == "1", "Use make test-virtualmin-maintenance-portal"
    manifest = read_manifest()
    platform = os.environ["PLATFORM_BASE_URL"]
    portal = os.environ["PORTAL_BASE_URL"]
    artifacts = Path(os.environ["VIRTUALMIN_MAINTENANCE_ARTIFACTS"])
    staff_context = browser.new_context(locale="en-US", timezone_id="UTC", viewport={"width": 1440, "height": 1000})
    customer_context = browser.new_context(locale="en-US", timezone_id="UTC", viewport={"width": 1440, "height": 1000})
    anonymous = browser.new_context()
    try:
        staff, customer = staff_context.new_page(), customer_context.new_page()
        login(staff, platform, manifest["staff"])
        login(customer, portal, manifest["viewer"], path="/login/")
        consent = customer.locator("#cookie-consent-banner")
        consent.get_by_text("Essential Only", exact=True).click()
        expect(consent).to_be_hidden()
        unsigned = anonymous.request.post(
            platform + "/api/maintenance/summary/", data={"customer_id": manifest["customers"][0]}
        )
        assert unsigned.status in {401, 403}, "Unsigned HTTP must not read customer maintenance"
        region = customer.locator("#account-status-region")
        expect(region).to_have_attribute("hx-trigger", "every 30s")
        expect(region.get_by_role("alert")).to_have_count(0)

        node = manifest["scope"]["node_ids"][0]
        configure_policy(staff, platform, node)
        window = schedule(staff, platform, node, "Ordinary maintenance acceptance")
        wait_for_mail(window, "scheduled")
        action(staff, platform, window, "start")
        detail = customer_context.new_page()
        navigate_read_only(detail, f"{portal}/services/{manifest['services'][0]}/")
        expect(detail.locator("#maintenance-attention")).to_contain_text("Ordinary maintenance acceptance")
        expect(detail.locator("#maintenance-attention")).to_contain_text("Maintenance is in progress")
        expect(detail.locator("#cookie-consent-banner")).to_be_hidden()
        detail.screenshot(path=str(artifacts / "customer-maintenance-running-desktop.png"), full_page=True)
        # This page started empty. Its real HTMX timer must pick up a window and its scoped worker's overrun.
        expect(region).to_contain_text("Maintenance is taking longer than planned", timeout=60000)
        window.refresh_from_db()
        assert window.status == "overran"
        customer.screenshot(path=str(artifacts / "customer-maintenance-overran-desktop.png"), full_page=True)
        action(
            staff,
            platform,
            window,
            "finish",
            outcome="completed",
            public_outcome="Ordinary work completed and service checked.",
            attestation="on",
        )
        wait_for_mail(window, "completed")
        navigate_read_only(detail, detail.url)
        expect(detail.locator("#maintenance-attention")).to_contain_text("Ordinary work completed and service checked.")
        expect(detail.locator("#maintenance-attention")).to_contain_text("Confirmed by an operator")
        detail.set_viewport_size({"width": 393, "height": 852})
        completion_note = (
            detail.locator("#maintenance-attention")
            .get_by_role("status")
            .filter(has_text="Ordinary work completed and service checked.")
        )
        expect(completion_note).to_have_count(1)
        completion_note.scroll_into_view_if_needed()
        expect(completion_note).to_be_visible()
        expect(detail.locator("#cookie-consent-banner")).to_be_hidden()
        detail.screenshot(path=str(artifacts / "customer-maintenance-completed-mobile.png"), full_page=True)
        # This is still the original dashboard page, without navigation or forced refresh.
        # Its next real thirty-second poll must clear the finished window's overrun alert.
        expect(region.get_by_role("alert")).to_have_count(0, timeout=35000)
        expect(region).not_to_contain_text("Maintenance information is temporarily unavailable")
        customer.screenshot(path=str(artifacts / "customer-maintenance-cleared-desktop.png"), full_page=True)

        # Company selection travels through the real Portal session and signed current-company API calls.
        switch_company(customer, portal, manifest["customers"][1])
        for inaccessible_service in (manifest["services"][0], manifest["services"][2]):
            # The existing detail view redirects refused lookups to the scoped list.
            # Inspect the first response so a followed redirect cannot masquerade as access.
            denied = customer.request.get(f"{portal}/services/{inaccessible_service}/", max_redirects=0)
            assert denied.status == 302 and denied.headers["location"] == "/services/"
            assert "Ordinary work completed and service checked." not in denied.text()
            attention = customer.request.get(f"{portal}/services/{inaccessible_service}/maintenance/")
            assert attention.status == 200
            assert "Ordinary work completed and service checked." not in attention.text()
            assert "Ordinary maintenance acceptance" not in attention.text()
        navigate_read_only(customer, f"{portal}/services/{manifest['services'][1]}/")
        expect(customer.locator("#maintenance-attention")).to_contain_text(
            "Ordinary work completed and service checked."
        )
        assert "maintenance-a.lab.invalid" not in customer.content()
        assert "maintenance-2.example.test" not in customer.content()
        # Observe the real thirty-second partial refresh in the newly selected
        # company's session before switching away. This proves ongoing poll scope,
        # while respecting the normal per-user API burst budget across full pages.
        with customer.expect_response(
            lambda response: (
                response.url == f"{portal}/services/{manifest['services'][1]}/maintenance/"
                and response.request.headers.get("hx-request") == "true"
            ),
            timeout=35000,
        ) as scoped_refresh:
            pass
        assert scoped_refresh.value.status == 200
        assert "Ordinary work completed and service checked." in scoped_refresh.value.text()
        expect(customer.locator("#maintenance-attention")).to_contain_text(
            "Ordinary work completed and service checked."
        )
        assert "maintenance-2.example.test" not in customer.content()
        switch_company(customer, portal, manifest["customers"][0])

        # This supported system/manual adapter never calls a provider or native reboot.
        emergency_node = manifest["scope"]["node_ids"][1]
        assert not NodeMaintenancePolicy.objects.filter(node_id=emergency_node).exists()
        emergency = create_emergency_window(
            emergency_node,
            reason="Emergency recovery acceptance",
            timezone_name="UTC",
            actor=User.objects.get(email=manifest["staff"]["email"]),
        )
        own_window(emergency.pk)
        assert emergency.status == "running" and emergency.origin == "system"
        navigate_read_only(detail, f"{portal}/services/{manifest['services'][3]}/")
        expect(detail.locator("#maintenance-attention")).to_contain_text("Emergency maintenance is needed")
        assert "Emergency recovery acceptance" not in detail.content(), "Internal operator reasons stay private"
        wait_for_mail(emergency, "scheduled")
        action(
            staff,
            platform,
            emergency,
            "finish",
            outcome="completed",
            public_outcome="Emergency service recovery confirmed by operator.",
            attestation="on",
        )
        wait_for_mail(emergency, "completed")
        navigate_read_only(detail, detail.url)
        expect(detail.locator("#maintenance-attention")).to_contain_text(
            "Emergency service recovery confirmed by operator."
        )

        announced = schedule(staff, platform, node, "Announced maintenance acceptance", future=True)
        wait_for_mail(announced, "scheduled")
        moved_start = announced.starts_at + timedelta(minutes=15)
        action(
            staff,
            platform,
            announced,
            "move",
            starts_at=moved_start.isoformat(),
            ends_at=(moved_start + timedelta(minutes=30)).isoformat(),
            customer_note="Revised maintenance acceptance",
        )
        announced.refresh_from_db()
        wait_for_mail(announced, "correction", revision=announced.revision)
        action(staff, platform, announced, "cancel")
        announced.refresh_from_db()
        assert announced.status == "cancelled"
        wait_for_mail(announced, "correction", revision=announced.revision)
        staff.goto(platform + f"/infrastructure/maintenance/servers/{node}/policy/")
        staff.screenshot(path=str(artifacts / "staff-maintenance-history-desktop.png"), full_page=True)

        assert set(manifest["protected_queue_ids"]) <= set(OrmQ.objects.values_list("pk", flat=True))
        assert EmailLog.objects.get(pk=manifest["unrelated_email_log_id"]).status == "queued"
        receipts = [
            json.loads(line)
            for line in (Path(os.environ["VIRTUALMIN_MAINTENANCE_MANIFEST"]).parent / "worker.jsonl")
            .read_text()
            .splitlines()
        ]
        assert {row["func"] for row in receipts} == {
            "apps.infrastructure.node_maintenance_tasks.tick_node_maintenance",
            "apps.notifications.tasks.send_email_task",
        }
        assert any(
            row["result"].get("overran") == 1 for row in receipts if row["func"].endswith("tick_node_maintenance")
        )
        assert all(not row["error"] for row in receipts)
        captured_mail = b"\n".join(path.read_bytes() for path in Path(settings.EMAIL_FILE_PATH).glob("*"))
        assert b"maintenance-a@praho.test" in captured_mail and b"Content-Type:" in captured_mail
        (artifacts / "qualification.json").write_text(
            json.dumps(
                {
                    "real_http_hmac": True,
                    "initial_empty_region_polled": True,
                    "scoped_worker_overran": True,
                    "completed_region_cleared_by_poll": True,
                    "company_switched_partial_polled": True,
                    "manual_operator_completion": True,
                    "emergency_without_policy": True,
                    "move_cancel_corrections": True,
                    "unrelated_queue_preserved": True,
                    "provider_reboot_qualified": False,
                },
                indent=2,
            )
        )
    finally:
        anonymous.close()
        customer_context.close()
        staff_context.close()
