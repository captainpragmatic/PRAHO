"""A refused CSRF token tells the page to reload, in a way scripts can recognise.

A tab whose token went stale (the secret rotates when anyone signs in again in another tab) is refused with 403. A
403 can also mean "not allowed", so the CSRF refusal carries `X-CSRF-Failure: reload`: the htmx error handler and
`platformFetch` show reload guidance for it and never replay the request.
"""

from __future__ import annotations

from django.conf import settings
from django.test import Client, TestCase
from django.urls import reverse
from django.utils.crypto import get_random_string

from tests.factories.core_factories import create_admin_user
from tests.helpers.csrf import body_csrf_token


class CsrfFailureViewTests(TestCase):
    def setUp(self) -> None:
        self.client = Client(enforce_csrf_checks=True)
        self.client.force_login(create_admin_user("csrf-failure"))
        self.url = reverse("users:logout")

    def stale_token(self) -> str:
        """The token a page carried before the secret rotated, as when another tab signs in again."""
        token = body_csrf_token(self.client.get(reverse("dashboard")).content.decode())
        self.assertNotEqual(
            self.client.post(reverse("dashboard"), HTTP_X_CSRFTOKEN=token).status_code, 403
        )  # valid now
        self.client.cookies[settings.CSRF_COOKIE_NAME] = get_random_string(32)
        return token

    def test_a_stale_token_on_a_script_request_is_marked_for_reload(self) -> None:
        for headers in ({"HTTP_HX_REQUEST": "true"}, {"HTTP_ACCEPT": "application/json"}):
            with self.subTest(headers=headers):
                response = self.client.post(self.url, HTTP_X_CSRFTOKEN=self.stale_token(), **headers)
                self.assertEqual(response.status_code, 403)
                self.assertEqual(response["X-CSRF-Failure"], "reload")
                self.assertContains(response, "reload the page", status_code=403)

    def test_a_plain_form_post_gets_a_page_that_says_to_reload(self) -> None:
        response = self.client.post(self.url)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response["X-CSRF-Failure"], "reload")
        self.assertContains(response, "reload the page", status_code=403)
        self.assertContains(response, "<html", status_code=403)

    def test_the_reload_link_returns_to_the_form_page_never_the_refused_url_or_another_site(self) -> None:
        settings_page = "http://testserver" + reverse("products:product_list")
        for referer, expected in (
            (settings_page, settings_page),
            ("https://evil.example/phish", reverse("dashboard")),
            ("", reverse("dashboard")),
        ):
            with self.subTest(referer=referer):
                response = self.client.post(self.url, HTTP_REFERER=referer)
                self.assertEqual(response.context["back_url"], expected)
                self.assertNotEqual(response.context["back_url"], self.url)
