"""
Cross-Service Parity Tests

Ensures intentionally duplicated modules between Platform and Portal
stay in sync. These files are duplicated because Portal cannot import
from Platform (service isolation), but they must remain identical.
"""

from pathlib import Path
from unittest import TestCase

REPO_ROOT = Path(__file__).resolve().parents[1]
PLATFORM_COMMON = REPO_ROOT / "services" / "platform" / "apps" / "common"
PORTAL_COMMON = REPO_ROOT / "services" / "portal" / "apps" / "common"


class TestRetryAfterParity(TestCase):
    """Ensure retry_after.py is identical across both services (except docstring)."""

    def test_retry_after_implementations_match(self) -> None:
        platform_lines = (PLATFORM_COMMON / "retry_after.py").read_text().splitlines()
        portal_lines = (PORTAL_COMMON / "retry_after.py").read_text().splitlines()

        # Line 2 is the module docstring which intentionally differs ("Platform" vs "Portal")
        platform_body = platform_lines[0:1] + platform_lines[2:]
        portal_body = portal_lines[0:1] + portal_lines[2:]

        self.assertEqual(
            platform_body,
            portal_body,
            "retry_after.py has drifted between Platform and Portal. "
            "Both copies must remain identical (except the module docstring).",
        )

    def test_both_export_coerce_function(self) -> None:
        for service_dir in (PLATFORM_COMMON, PORTAL_COMMON):
            content = (service_dir / "retry_after.py").read_text()
            self.assertIn(
                "def coerce_retry_after_seconds(",
                content,
                f"Missing coerce_retry_after_seconds in {service_dir / 'retry_after.py'}",
            )


class TestLocalisationParity(TestCase):
    """Pure display policy must behave identically across isolated services."""

    def test_localisation_helpers_match(self) -> None:
        for name in ("localisation.py", "localisation_forms.py", "localisation_middleware.py"):
            with self.subTest(name=name):
                self.assertEqual((PLATFORM_COMMON / name).read_text(), (PORTAL_COMMON / name).read_text())


class TestMaintenanceMarkerParity(TestCase):
    """The platform writes a machine-readable maintenance marker; the portal reads it.

    This is a cross-service contract that no type checker or import can enforce, because the portal
    cannot import platform code. It replaced keying on the bare 503 status, which was wrong:
    `apps/api/billing/views.py` answers 503 for arbitrary document-list errors, so a real failure told
    the customer "scheduled maintenance - your data is safe".

    If the marker drifts on either side the portal silently stops recognising a real maintenance window
    and reports every outage as an undeclared one. That degrades quietly, which is exactly the failure
    mode worth a test. Asserted on source text because the two halves cannot be imported into one
    process — the same reason this file exists at all.
    """

    MARKER = "maintenance"
    PLATFORM_MIDDLEWARE = REPO_ROOT / "services" / "platform" / "apps" / "common" / "middleware.py"
    PORTAL_API_CLIENT = REPO_ROOT / "services" / "portal" / "apps" / "api_client" / "services.py"

    def test_the_platform_writes_the_marker(self) -> None:
        source = self.PLATFORM_MIDDLEWARE.read_text()
        self.assertIn(
            f'"error": "{self.MARKER}"',
            source,
            "MaintenanceModeMiddleware must put the marker in its JSON body, or the portal cannot tell "
            "a declared maintenance window from any other 503.",
        )

    def test_the_portal_reads_the_same_marker(self) -> None:
        source = self.PORTAL_API_CLIENT.read_text()
        self.assertIn(
            f'== "{self.MARKER}"',
            source,
            "PlatformAPIError must key is_maintenance on the marker rather than on the 503 status alone.",
        )

    def test_the_portal_does_not_treat_a_bare_503_as_maintenance(self) -> None:
        """Guards the specific regression: `is_maintenance` defaulting from the status code alone."""
        source = self.PORTAL_API_CLIENT.read_text()
        marker_line = next(
            (line for line in source.splitlines() if "SERVICE_UNAVAILABLE" in line and "is_maintenance" in line),
            None,
        )
        self.assertIsNone(
            marker_line,
            "is_maintenance must not be derived from SERVICE_UNAVAILABLE on one line without the marker; "
            f"found: {marker_line}",
        )
