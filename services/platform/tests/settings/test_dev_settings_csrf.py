"""Local development checks CSRF the way staging does, without taking the Portal's cookie.

Dev used to remove CsrfViewMiddleware, so a button that sent no token worked locally and was refused on staging
(the Platform's service Suspend/Activate and mobile product toggles). With the check on, both services run on
localhost, where cookies ignore the port: the Platform's HttpOnly cookie needs its own name, or it overwrites the
`csrftoken` cookie the Portal's scripts read.
"""

from __future__ import annotations

from django.test import SimpleTestCase

from tests.settings.test_media_storage import _settings_module

CSRF_MIDDLEWARE = "django.middleware.csrf.CsrfViewMiddleware"


class DevSettingsCsrfTests(SimpleTestCase):
    def test_every_local_profile_checks_csrf_under_the_platforms_own_cookie(self) -> None:
        # lab.py (the Virtualmin lab) is `from .dev import *` and never touches MIDDLEWARE or the cookie; it can't
        # be imported here because it needs the lab's generated env file.
        for name in ("config.settings.dev", "config.settings.e2e"):
            with self.subTest(settings=name):
                module = _settings_module(name, {})
                self.assertIn(CSRF_MIDDLEWARE, module.MIDDLEWARE)
                self.assertLess(
                    module.MIDDLEWARE.index("django.contrib.sessions.middleware.SessionMiddleware"),
                    module.MIDDLEWARE.index(CSRF_MIDDLEWARE),
                )
                self.assertEqual(module.CSRF_COOKIE_NAME, "platform_csrftoken")

    def test_staging_and_production_keep_the_default_name(self) -> None:
        """They run on their own hosts; renaming there would void every open tab's token at deploy."""
        base = _settings_module("config.settings.base", {})
        self.assertEqual(getattr(base, "CSRF_COOKIE_NAME", "csrftoken"), "csrftoken")
