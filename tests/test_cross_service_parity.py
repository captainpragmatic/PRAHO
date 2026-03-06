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
