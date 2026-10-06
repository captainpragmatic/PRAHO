"""What the load test requests, kept free of Locust so a unit test can check every path.

Each entry is a staff listing page on the Platform. `services/platform/tests/common/
test_load_test_scenarios.py` checks that every path sits behind the staff login and renders for staff,
so a renamed route fails a unit test instead of quietly turning a load run into 404s.
"""

from __future__ import annotations

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
