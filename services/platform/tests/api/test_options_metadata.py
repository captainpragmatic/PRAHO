"""OPTIONS must not publish view docstrings (#567).

DRF's SimpleMetadata answers every OPTIONS request with the view docstring under
"description". Public endpoints answer OPTIONS without authentication, and
``obtain_token``'s docstring is its full request and response contract. Docstrings are
written for maintainers, so the API no longer serves them.
"""

from __future__ import annotations

from django.conf import settings
from django.test import Client, TestCase, override_settings


class OptionsMetadataTests(TestCase):
    def test_unauthenticated_options_omits_the_view_docstring(self) -> None:
        response = Client().options("/api/users/token/")

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["name"], "Obtain Token")  # metadata is still served
        self.assertNotIn("description", body)
        self.assertNotIn("raw token shown once", response.content.decode())

    @override_settings(MIDDLEWARE=[*settings.MIDDLEWARE, "apps.common.middleware.PortalServiceHMACMiddleware"])
    def test_through_the_hmac_middleware_too(self) -> None:
        # config/settings/test.py strips this middleware; production does not.
        response = Client().options("/api/users/token/")

        self.assertEqual(response.status_code, 200)
        self.assertNotIn("description", response.json())
