"""Every Platform page gives htmx and fetch() one CSRF token, and keeps htmx's eval path off.

The CSRF cookie is HttpOnly, so scripts can't read it; the page carries the token instead, in `<body hx-headers>` for
htmx and `<meta name="csrf-token">` for fetch(). `htmx.config.allowEval = false` used to be set only inside the
flash-messages block, so pages without a message left htmx evaluating `js:` values.
"""

from __future__ import annotations

from django.test import Client, TestCase
from django.urls import reverse

from tests.factories.core_factories import create_admin_user
from tests.helpers.csrf import body_csrf_token, meta_csrf_token


class BaseTemplateCsrfTests(TestCase):
    def setUp(self) -> None:
        self.client = Client(enforce_csrf_checks=True)
        self.client.force_login(create_admin_user("base-csrf"))

    def test_the_page_gives_htmx_and_fetch_the_same_working_token(self) -> None:
        html = self.client.get(reverse("dashboard")).content.decode()
        token = body_csrf_token(html)
        self.assertEqual(meta_csrf_token(html), token)

    def test_htmx_eval_is_off_on_a_page_with_no_flash_messages(self) -> None:
        response = self.client.get(reverse("dashboard"))
        self.assertFalse(list(response.context["messages"]))
        self.assertContains(response, "htmx.config.allowEval = false")
