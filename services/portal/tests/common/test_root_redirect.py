"""The portal root uses the same session identity as authentication middleware."""

from datetime import timedelta

from django.test import SimpleTestCase, override_settings
from django.urls import reverse
from django.utils import timezone


@override_settings(
    ROOT_URLCONF="config.urls",
    MIDDLEWARE=[
        "django.contrib.sessions.middleware.SessionMiddleware",
        "apps.users.middleware.PortalAuthenticationMiddleware",
    ],
    SESSION_ENGINE="django.contrib.sessions.backends.cache",
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
)
class RootRedirectTests(SimpleTestCase):
    def test_authenticated_root_redirects_directly_to_dashboard(self) -> None:
        # Both current and legacy identities are accepted by the auth middleware.
        for identity_key in ("user_id", "customer_id"):
            with self.subTest(identity_key=identity_key):
                self.client.cookies.clear()
                now = timezone.now()
                session = self.client.session
                session[identity_key] = 7
                session["active_customer_id"] = 42
                session["authenticated_at"] = now.isoformat()
                session["validated_at"] = now.isoformat()
                session["next_validate_at"] = (now + timedelta(minutes=10)).isoformat()
                session["session_auth_hash"] = "cached-session-binding"
                session.save()

                response = self.client.get(reverse("root"))

                self.assertRedirects(response, "/dashboard/", fetch_redirect_response=False)

    def test_anonymous_root_redirects_to_login(self) -> None:
        response = self.client.get(reverse("root"))

        self.assertRedirects(response, "/login/", fetch_redirect_response=False)
