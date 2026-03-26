"""C1: Verify domain register template does not use innerHTML with API response data."""
import re
from pathlib import Path

from django.test import SimpleTestCase


class DomainRegisterXSSTests(SimpleTestCase):
    """C1: domain_register must not use innerHTML with interpolated API response data."""

    def test_no_innerhtml_with_template_literals(self) -> None:
        """innerHTML must not be used with ${data.*} interpolation."""
        template_path = (
            Path(__file__).resolve().parents[2]
            / "templates/domains/domain_register.html"
        )
        content = template_path.read_text()
        # Find innerHTML assignments with template literal interpolation of data.*
        dangerous_pattern = re.findall(r"innerHTML\s*=\s*`[^`]*\$\{data\.", content)
        self.assertEqual(
            len(dangerous_pattern),
            0,
            f"Found {len(dangerous_pattern)} innerHTML assignments with interpolated API data — XSS risk",
        )

    def test_uses_textcontent_for_text_display(self) -> None:
        """Template should use textContent or createElement for safe DOM insertion."""
        template_path = (
            Path(__file__).resolve().parents[2]
            / "templates/domains/domain_register.html"
        )
        content = template_path.read_text()
        # Should use textContent for displaying API response text
        self.assertIn(
            "textContent",
            content,
            "Expected textContent usage for safe text insertion",
        )
