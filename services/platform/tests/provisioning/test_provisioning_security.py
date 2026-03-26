"""H6: services_list must escape service_name in onclick handlers."""
import re
from pathlib import Path

from django.test import SimpleTestCase


class ServicesListXSSTests(SimpleTestCase):
    """H6: service_name in onclick must use |escapejs to prevent XSS."""

    def test_all_service_name_in_onclick_use_escapejs(self):
        template_path = Path(__file__).resolve().parents[2] / "templates/provisioning/partials/services_list.html"
        content = template_path.read_text()
        # Find all onclick handlers containing service.service_name
        onclick_matches = re.findall(
            r"onclick=\"[^\"]*\{\{[^}]*service\.service_name[^}]*\}\}[^\"]*\"",
            content,
        )
        self.assertTrue(len(onclick_matches) > 0, "Expected onclick handlers with service_name")
        for match in onclick_matches:
            self.assertIn("escapejs", match, f"Unescaped service_name in: {match}")
