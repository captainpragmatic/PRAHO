"""What the load test requests, kept free of Locust so a unit test can check every path.

Each entry is a staff listing page on the Platform. `services/platform/tests/common/
test_load_test_scenarios.py` checks that every path sits behind the staff login and renders for staff,
so a renamed route fails a unit test instead of quietly turning a load run into 404s.
"""

from __future__ import annotations

from urllib.parse import urlparse

LOGIN_PATH = "/auth/login/"

# (name shown in Locust's stats, path, relative weight)
BROWSING: tuple[tuple[str, str, int], ...] = (
    ("dashboard", "/dashboard/", 10),
    ("customers", "/customers/", 8),
    ("invoices", "/billing/invoices/", 7),
    ("orders", "/orders/", 6),
    ("products", "/products/", 5),
    ("tickets", "/tickets/", 4),
    ("proformas", "/billing/proformas/", 3),
    ("provisioned services", "/provisioning/services/", 3),
    ("domains", "/domains/", 2),
    ("audit log", "/audit/logs/", 2),
    ("settings", "/settings/", 1),
)


def page_failure(requested_path: str, status_code: int, final_url: str) -> str | None:
    """Why a browsing response does not count as that page, or None when it does.

    Locust follows redirects, and the page a redirect lands on answers 200. So a 200 alone proves
    nothing: a lost session lands on the login page, and a page the account may not see (a billing
    listing for a support-role account, say) redirects to the dashboard. Either would otherwise be
    timed and reported under the requested page's name.
    """
    landed = urlparse(final_url).path
    if status_code != 200:
        return f"{requested_path} answered {status_code}"
    if landed == LOGIN_PATH:
        return f"{requested_path} redirected to the login page: the session was lost"
    if landed != requested_path:
        return f"{requested_path} redirected to {landed}: the account may lack the role this page needs"
    return None
