"""The portal publishes the Privacy Policy its Terms of Service point to.

The terms ask customers to "review our Privacy Policy" and checkout linked "privacy policy" to the
signed-in privacy dashboard: the policy itself was only on the staff service. The text is shared
with Platform's page (shared/ui/templates/legal/privacy_policy_content.html).
"""

from unittest.mock import patch

from django.core.cache import cache
from django.test import Client, SimpleTestCase, override_settings
from django.urls import reverse
from django.utils import translation

from apps.api_client.services import api_client
from apps.common.localisation import LocalisationDefaults

IDENTITY = {
    "legal_name": "Privacy Test SRL",
    "email_support": "help@privacy.example.test",
    "email_privacy": "privacy@privacy.example.test",
    "email_finance": "",
    "phone": "+40721000000",
}


@override_settings(
    SESSION_ENGINE="django.contrib.sessions.backends.cache",
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
)
class PrivacyPolicyPageTests(SimpleTestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        payload = {"success": True, "localisation": LocalisationDefaults().customer_payload(), "company": IDENTITY}
        identity = patch.object(api_client, "get_localisation_defaults", return_value=payload)
        identity.start()
        self.addCleanup(identity.stop)

    def test_anonymous_visitors_can_read_the_policy(self) -> None:
        response = Client().get("/privacy-policy/")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'id="data-controller"')
        self.assertContains(response, 'id="contact"')

    def test_the_controller_and_privacy_contact_are_named_and_unknown_details_left_out(self) -> None:
        html = Client().get(reverse("privacy_policy")).content.decode()
        self.assertIn("Privacy Test SRL", html)
        self.assertIn("privacy@privacy.example.test", html)
        # The portal knows no registered address and no DPO address: no empty rows.
        self.assertNotIn("Registered Address", html)
        self.assertNotIn("Data Protection Officer (DPO)", html)

    def test_rights_point_to_the_customers_privacy_dashboard(self) -> None:
        html = Client().get("/privacy-policy/").content.decode()
        self.assertIn(f'href="{reverse("users:privacy_dashboard")}"', html)

    def test_the_footer_and_the_terms_link_the_policy(self) -> None:
        link = f'href="{reverse("privacy_policy")}"'
        self.assertIn(link, Client().get("/cookie-policy/").content.decode())
        # The terms' own "View Privacy Policy" button, not the footer link every page has.
        self.assertIn(f'{link} class="inline-block bg-blue-600', Client().get("/terms/").content.decode())

    def test_only_the_page_itself_is_public(self) -> None:
        response = Client().get("/privacy-policy/other/")
        self.assertEqual(response.status_code, 302)

    def test_the_policy_reads_in_romanian(self) -> None:
        with translation.override(None):  # The request activates Romanian; put the language back after.
            response = Client(headers={"Accept-Language": "ro"}).get("/privacy-policy/")
        text = " ".join(response.content.decode().split())
        self.assertIn("Solicitări privind confidențialitatea", text)
        self.assertIn("Mergeți la panoul de confidențialitate", text)
