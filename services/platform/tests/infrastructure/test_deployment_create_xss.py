"""H3: deployment_create must use json_script, not |safe in <script>."""
from pathlib import Path

from django.test import SimpleTestCase


class DeploymentCreateJsonEscapingTests(SimpleTestCase):
    """H3: JSON data must be rendered via json_script, not |safe in script context."""

    def test_template_does_not_use_safe_for_json(self) -> None:
        template_path = (
            Path(__file__).resolve().parents[2]
            / "templates/infrastructure/deployment_create.html"
        )
        content = template_path.read_text()
        self.assertNotIn("regions_json|safe", content)
        self.assertNotIn("sizes_json|safe", content)
        self.assertNotIn("providers_json|safe", content)

    def test_template_uses_json_script(self) -> None:
        template_path = (
            Path(__file__).resolve().parents[2]
            / "templates/infrastructure/deployment_create.html"
        )
        content = template_path.read_text()
        self.assertIn("json_script", content)
