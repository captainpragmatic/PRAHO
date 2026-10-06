"""Every page the load test requests exists, sits behind the staff login, and renders for staff.

`tests/load/locustfile.py` used to request `/app/<section>/` routes that no longer exist and to log in
with a `username` field the login form does not take, so any run measured only redirects and 404s.
Its requests now live in `tests/load/scenarios.py`, which imports nothing from Locust, so this test can
check each path through the real URLconf and views.
"""

from __future__ import annotations

import sys
from pathlib import Path

from django.test import TestCase

from apps.users.models import User

_LOAD_DIR = str(Path(__file__).resolve().parents[4] / "tests" / "load")
if _LOAD_DIR not in sys.path:
    sys.path.insert(0, _LOAD_DIR)

from scenarios import BROWSING, page_failure  # noqa: E402


class LoadTestScenarioTests(TestCase):
    def test_the_scenario_table_is_substantial(self) -> None:
        self.assertGreaterEqual(len(BROWSING), 6)

    def test_every_page_requires_the_staff_login(self) -> None:
        for name, path, _weight in BROWSING:
            with self.subTest(name=name):
                response = self.client.get(path)
                self.assertEqual(response.status_code, 302, path)
                self.assertTrue(response["Location"].startswith("/auth/login/"), (path, response["Location"]))

    def test_every_page_renders_for_staff(self) -> None:
        staff = User.objects.create_user(
            email="loadtest-staff@example.ro", password="LoadTest123!", is_staff=True, staff_role="admin"
        )
        self.client.force_login(staff)
        for name, path, _weight in BROWSING:
            with self.subTest(name=name):
                response = self.client.get(path)
                self.assertEqual(response.status_code, 200, path)
                self.assertTrue(response.content.strip(), path)


class LoadTestPageVerdictTests(TestCase):
    """A 200 only counts as the requested page if the response did not redirect elsewhere."""

    def test_the_requested_page_counts(self) -> None:
        self.assertIsNone(page_failure("/billing/invoices/", 200, "http://localhost:8700/billing/invoices/?page=1"))

    def test_a_role_redirect_to_the_dashboard_is_a_failure(self) -> None:
        problem = page_failure("/billing/invoices/", 200, "http://localhost:8700/dashboard/")
        self.assertIsNotNone(problem)
        self.assertIn("/dashboard/", problem)

    def test_a_lost_session_is_a_failure(self) -> None:
        problem = page_failure("/customers/", 200, "http://localhost:8700/auth/login/?next=/customers/")
        self.assertIn("session was lost", problem)

    def test_an_error_status_is_a_failure(self) -> None:
        self.assertIn("500", page_failure("/orders/", 500, "http://localhost:8700/orders/"))
