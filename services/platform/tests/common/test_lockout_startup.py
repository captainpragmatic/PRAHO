"""Development lockout overrides must not silently reach a deployed service."""

from django.apps import apps
from django.core.checks import run_checks
from django.core.exceptions import ImproperlyConfigured
from django.test import TestCase, override_settings


class LockoutStartupTests(TestCase):
    @override_settings(DEBUG=False, DISABLE_ACCOUNT_LOCKOUT=True)
    def test_non_debug_startup_refuses_disabled_account_lockout(self) -> None:
        with self.assertRaisesMessage(ImproperlyConfigured, "DISABLE_ACCOUNT_LOCKOUT"):
            apps.get_app_config("common").ready()

    @override_settings(DEBUG=False, DISABLE_ACCOUNT_LOCKOUT=True)
    def test_security_check_reports_disabled_account_lockout(self) -> None:
        errors = run_checks(tags=["security"])
        self.assertTrue(any("DISABLE_ACCOUNT_LOCKOUT" in error.msg for error in errors))

    @override_settings(DEBUG=True, DISABLE_ACCOUNT_LOCKOUT=True)
    def test_explicit_development_override_is_allowed(self) -> None:
        apps.get_app_config("common").ready()
