"""Ordinary discovery and wrong database names cannot start the opt-in stack."""

import importlib
import os
import unittest
from copy import deepcopy
from unittest.mock import patch

from django.test import SimpleTestCase


class FullCheckoutHarnessSafetyTests(SimpleTestCase):
    def test_imports_do_not_connect_spawn_or_require_opt_in(self):
        with (
            patch.dict(os.environ, {"HOSTING_CHECKOUT_FULL": "0"}),
            patch("psycopg.connect", side_effect=AssertionError("Unexpected database connection")) as connect,
            patch("subprocess.Popen", side_effect=AssertionError("Unexpected process")) as spawn,
        ):
            for name in ("bootstrap_database", "full_checkout_server", "test_plan_change_full_chain"):
                importlib.import_module("tests.browser." + name)
            suite = unittest.defaultTestLoader.loadTestsFromName("tests.browser.test_plan_change_full_chain")
            self.assertEqual(suite.countTestCases(), 0)
            connect.assert_not_called()
            spawn.assert_not_called()

    def test_settings_copy_database_configuration_without_mutating_other_suites(self):
        from config.settings import ci  # noqa: PLC0415 -- Inspect the original configuration object.

        original = deepcopy(ci.DATABASES)
        driver = importlib.import_module("tests.browser.full_checkout_driver_settings")
        server = importlib.import_module("tests.browser.full_checkout_settings")
        self.assertEqual(ci.DATABASES, original)
        self.assertEqual(driver.DATABASES["default"]["NAME"], "hosting_browser")
        self.assertEqual(server.DATABASES["default"]["NAME"], "test_hosting_browser")

    def test_bootstrap_refuses_unowned_database_before_connecting(self):
        from tests.browser import bootstrap_database  # noqa: PLC0415

        with (
            patch.dict(os.environ, {"HOSTING_CHECKOUT_FULL": "1", "DB_NAME": "application"}),
            patch("psycopg.connect", side_effect=AssertionError("Unexpected database connection")) as connect,
        ):
            with self.assertRaises(AssertionError):
                bootstrap_database.main()
            connect.assert_not_called()
