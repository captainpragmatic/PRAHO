"""Django test runner may create/drop only the isolated full checkout database."""

from copy import deepcopy

from config.settings.ci import *  # noqa: F403 -- Test-only settings extension.

DATABASES = deepcopy(DATABASES)
DATABASES["default"].update(
    NAME="hosting_browser",
    HOST="127.0.0.1",
    USER="praho_hosting_test",
    PASSWORD="praho_hosting_local_fixture",  # noqa: S106 -- Public owned-fixture credentials only.
)
DATABASES["default"]["TEST"]["NAME"] = "test_hosting_browser"
TEST_RUNNER = "tests.browser.full_checkout_runner.CheckoutBrowserRunner"
