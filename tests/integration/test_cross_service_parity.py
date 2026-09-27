"""
Cross-Service Parity Tests

Ensures intentionally duplicated modules between Platform and Portal
stay in sync. These files are duplicated because Portal cannot import
from Platform (service isolation), but they must remain identical.
"""

from pathlib import Path
from unittest import TestCase

# parents[2], not [1]: this file lives in tests/integration/ so that `make test-integration`
# collects it. At tests/ root nothing collected it - every root pytest target is scoped to
# tests/integration/, tests/e2e/orm/ or a named file - so all three parity guards had been
# running nowhere since the file was added in #74.
REPO_ROOT = Path(__file__).resolve().parents[2]
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

    def test_the_portal_derives_maintenance_from_the_marker_not_the_status(self) -> None:
        """Guards the specific regression: `is_maintenance` defaulting from the status code alone.

        Asserted over the whole assignment expression rather than line by line. The first version of
        this test looked for a single line carrying both `SERVICE_UNAVAILABLE` and `is_maintenance`,
        which is a property of ruff's line breaking and not of the code: collapsing the expression
        onto one line would have failed it while the behaviour was correct, and spreading the bug
        over two lines would have passed it.
        """
        source = self.PORTAL_API_CLIENT.read_text()
        start = source.index("self.is_maintenance = bool(")
        end = depth = 0
        for index, char in enumerate(source[start:], start):
            depth += (char == "(") - (char == ")")
            if depth == 0 and char == ")":
                end = index
                break
        self.assertGreater(end, start, "could not find the end of the is_maintenance assignment")
        assignment = source[start : end + 1]

        self.assertIn(
            f'"{self.MARKER}"',
            assignment,
            "is_maintenance must be derived from the marker the platform writes, not from the 503 "
            f"status alone. `apps/api/billing/views.py` answers 503 for arbitrary document-list "
            f"errors, so a status-only test tells the customer their data is safe during a real "
            f"failure. Found: {assignment}",
        )
