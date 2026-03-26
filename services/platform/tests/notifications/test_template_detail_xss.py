"""C2: Verify iframe sandbox prevents same-origin access for email template preview."""
from pathlib import Path

from django.test import SimpleTestCase


class TemplateDetailIframeSandboxTests(SimpleTestCase):
    """The email template preview iframe must use an empty sandbox attribute."""

    def test_iframe_sandbox_does_not_allow_same_origin(self):
        """sandbox='allow-same-origin' enables XSS via srcdoc — must be empty."""
        template_path = Path(__file__).resolve().parents[2] / "templates/notifications/template_detail.html"
        content = template_path.read_text()
        self.assertNotIn('sandbox="allow-same-origin"', content)
        # Verify sandbox exists and is empty (most restrictive)
        self.assertIn('sandbox=""', content)
