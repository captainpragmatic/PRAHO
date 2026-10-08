# ===============================================================================
# LOAD TESTING CONFIGURATION FOR PRAHO PLATFORM
# ===============================================================================
"""Load test for the PRAHO staff Platform: logged-in staff browsing the listing pages.

Usage (Platform on :8700; see tests/load/README.md):
    LOCUST_EMAIL=... LOCUST_PASSWORD=... uvx locust -f tests/load/locustfile.py --host=http://localhost:8700

Every login and every page is validated, not just its status code. A failed login, or a page that
redirects anywhere else (the login page, or the dashboard when the account lacks the page's role), is
recorded as a Locust failure, because the page a redirect lands on answers 200 and would otherwise
count as success. The account must be staff with no second factor
enrolled; a staff login with 2FA stops at the code page and the user is stopped.

The pages are in `scenarios.py`; a unit test checks each one exists and renders for staff.
"""

from __future__ import annotations

import os
import random
import re
import sys
from pathlib import Path
from urllib.parse import urlparse

from locust import HttpUser, between, task
from locust.exception import StopUser

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scenarios import BROWSING, LOGIN_PATH, page_failure

DASHBOARD_PATH = "/dashboard/"
_CSRF_TOKEN = re.compile(r'name="csrfmiddlewaretoken" value="([^"]+)"')
_NAMES, _PATHS, _WEIGHTS = zip(*BROWSING, strict=True)


class StaffUser(HttpUser):
    """A staff member who logs in once, then browses the listing pages by weight."""

    wait_time = between(1, 5)

    def on_start(self) -> None:
        email = os.environ.get("LOCUST_EMAIL", "loadtest_staff@test.ro")
        password = os.environ.get("LOCUST_PASSWORD", "LoadTest123!")
        form = self.client.get(LOGIN_PATH, name="login form")
        token = _CSRF_TOKEN.search(form.text)
        with self.client.post(
            LOGIN_PATH,
            data={"email": email, "password": password, "csrfmiddlewaretoken": token.group(1) if token else ""},
            headers={"Referer": f"{self.host}{LOGIN_PATH}"},
            name="login",
            catch_response=True,
        ) as response:
            landed = urlparse(response.url).path
            if landed != DASHBOARD_PATH:
                response.failure(
                    f"login as {email} ended at {landed}, not {DASHBOARD_PATH}: wrong credentials, or the account "
                    "has 2FA enrolled (use a staff account without a second factor)"
                )
                raise StopUser()

    @task
    def browse(self) -> None:
        index = random.choices(range(len(_PATHS)), weights=_WEIGHTS)[0]  # noqa: S311  # load mix, not security
        with self.client.get(_PATHS[index], name=_NAMES[index], catch_response=True) as response:
            if problem := page_failure(_PATHS[index], response.status_code, response.url):
                response.failure(problem)
