"""The registration page shows each message once (#689).

The page listed every message inside its form, and the base template shows the same messages
as toasts, so a refusal such as "Too many registration attempts" appeared twice.
"""

from __future__ import annotations

from django.contrib import messages
from django.contrib.messages.storage.fallback import FallbackStorage
from django.contrib.sessions.backends.cache import SessionStore
from django.test import RequestFactory, SimpleTestCase, override_settings

from apps.users.views import register_view

REFUSAL = "Too many registration attempts. Please try again later."


@override_settings(
    SESSION_ENGINE="django.contrib.sessions.backends.cache",
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache", "LOCATION": "register-once"}},
)
class RegisterMessagesOnceTests(SimpleTestCase):
    def test_a_refusal_is_shown_once(self) -> None:
        request = RequestFactory().get("/register/")
        request.session = SessionStore()
        request._messages = FallbackStorage(request)  # type: ignore[attr-defined]  # what MessageMiddleware sets
        messages.error(request, REFUSAL)

        response = register_view(request)

        self.assertEqual(response.content.decode().count(REFUSAL), 1)
