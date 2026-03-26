"""H4: login template must urlencode next parameter in hidden input."""
from pathlib import Path

from django.test import SimpleTestCase


class LoginNextParamTests(SimpleTestCase):
    """H4: next parameter in hidden input must be urlencoded for defense-in-depth."""

    def test_next_param_uses_urlencode(self):
        template_path = Path(__file__).resolve().parents[2] / "templates/users/login.html"
        content = template_path.read_text()
        # Should NOT have bare {{ request.GET.next }} in value attribute
        self.assertNotIn('value="{{ request.GET.next }}"', content)
        # Should use urlencode
        self.assertIn("request.GET.next|urlencode", content)
