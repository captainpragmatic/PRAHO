"""Loading the session user reads the credential version in the same query (#553).

`User._get_session_auth_hash` binds sessions to `UserCredentialVersion`, and Django calls
it on every authenticated request. With the stock `ModelBackend` that was a second
SELECT per request. The backend now joins it into the user lookup.

Counted as whole queries, not by table name: the joined query still names
`users_usercredentialversion`, so a substring count could not tell the two apart.
"""

from __future__ import annotations

from asgiref.sync import async_to_sync
from django.conf import settings
from django.contrib.auth import aget_user, get_user, login
from django.contrib.auth.models import AnonymousUser
from django.contrib.sessions.middleware import SessionMiddleware
from django.db import connection
from django.http import HttpRequest, HttpResponse
from django.test import RequestFactory, TestCase
from django.test.utils import CaptureQueriesContext

from apps.users.models import User, UserCredentialVersion


class CredentialVersionBackendTests(TestCase):
    def setUp(self) -> None:
        self.factory = RequestFactory()
        self.middleware = SessionMiddleware(lambda request: HttpResponse())

    def _request(self, key: str | None = None) -> HttpRequest:
        request = self.factory.get("/")
        request.user = AnonymousUser()
        if key is not None:
            request.COOKIES[settings.SESSION_COOKIE_NAME] = key
        self.middleware.process_request(request)
        return request

    def _logged_in_request(self, user: User) -> HttpRequest:
        request = self._request()
        login(request, user, backend=settings.AUTHENTICATION_BACKENDS[0])
        self.middleware.process_response(request, HttpResponse())
        key = request.session.session_key
        assert key is not None
        follow_up = self._request(key)
        follow_up.session.load()  # the session read is not what is being counted
        follow_up.session._session_cache = follow_up.session.load()
        return follow_up

    def _assert_one_query_loads(self, user: User) -> None:
        request = self._logged_in_request(user)

        with CaptureQueriesContext(connection) as captured:
            loaded = get_user(request)

        self.assertEqual(loaded.pk, user.pk)
        self.assertEqual(len(captured.captured_queries), 1, [q["sql"] for q in captured.captured_queries])

    def test_user_without_a_version_row_loads_in_one_query(self) -> None:
        """FAILS on master: the missing version row costs a second SELECT."""
        self._assert_one_query_loads(User.objects.create_user(email="no-version@example.com", password="Version-pass123!"))

    def test_user_with_a_version_row_loads_in_one_query(self) -> None:
        """FAILS on master: the version row is read by a second SELECT."""
        user = User.objects.create_user(email="versioned@example.com", password="Version-pass123!")
        UserCredentialVersion.objects.create(user=user, version=3)

        self._assert_one_query_loads(User.objects.get(pk=user.pk))

    def test_async_load_uses_one_query(self) -> None:
        """FAILS on master with SynchronousOnlyOperation, not just a second query.

        Django's ModelBackend has its own aget_user. It returned the user without the
        version, so get_session_auth_hash read it lazily, a synchronous query from an
        async context, and loading any async session user crashed.
        """
        user = User.objects.create_user(email="async-version@example.com", password="Version-pass123!")
        request = self._logged_in_request(user)

        with CaptureQueriesContext(connection) as captured:
            loaded = async_to_sync(aget_user)(request)

        self.assertEqual(loaded.pk, user.pk)
        self.assertEqual(len(captured.captured_queries), 1, [q["sql"] for q in captured.captured_queries])

    def test_a_version_bumped_after_login_rejects_the_session(self) -> None:
        """Guard: the joined version is the one the hash is checked against."""
        user = User.objects.create_user(email="bumped@example.com", password="Version-pass123!")
        request = self._logged_in_request(user)
        UserCredentialVersion.objects.create(user=user, version=1)

        self.assertIsInstance(get_user(request), AnonymousUser)

    def test_an_inactive_user_is_not_loaded(self) -> None:
        """Guard: the override keeps ModelBackend's user_can_authenticate check."""
        user = User.objects.create_user(email="inactive-version@example.com", password="Version-pass123!")
        request = self._logged_in_request(user)
        User.objects.filter(pk=user.pk).update(is_active=False)

        self.assertIsInstance(get_user(request), AnonymousUser)
