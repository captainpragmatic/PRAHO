"""A maintenance receipt may describe retained mail/DNS rather than website placement."""

from django.template.loader import render_to_string
from django.test import SimpleTestCase
from django.utils.translation import override

from apps.common.localisation import DisplayLocalisation
from apps.services.maintenance import maintenance_presentation, maintenance_receipt
from tests.services.test_maintenance_summary import envelope, window


class RetainedMaintenanceWordingTests(SimpleTestCase):
    def test_rendered_maintenance_describes_hosting_dependencies_in_both_languages(self) -> None:
        descriptions = {
            "en": {
                "reboot": "A restart of a server supporting your hosting services",
                "panel_update": "Updates to a server supporting your hosting services",
                "emergency": "Emergency work on a server supporting your hosting services",
            },
            "ro": {
                "reboot": "Repornirea unui server care susține serviciile dumneavoastră de găzduire",
                "panel_update": "Actualizări pe un server care susține serviciile dumneavoastră de găzduire",
                "emergency": "Lucrări urgente pe un server care susține serviciile dumneavoastră de găzduire",
            },
        }
        for locale, kinds in descriptions.items():
            for kind, description in kinds.items():
                with self.subTest(locale=locale, kind=kind), override(locale):
                    summary = maintenance_receipt(envelope(window(kind=kind, customer_note="Mail & DNS <checked>")))
                    context = maintenance_presentation(summary, DisplayLocalisation(locale, "RO", "UTC", "%Y-%m-%d"))
                    rendered = render_to_string("services/partials/maintenance_attention.html", context)
                    self.assertIn(description, rendered)
                    self.assertIn("Mail &amp; DNS &lt;checked&gt;", rendered)
                    self.assertNotIn("your site runs on", rendered)
                    self.assertNotIn("găzduiește site-ul", rendered)
