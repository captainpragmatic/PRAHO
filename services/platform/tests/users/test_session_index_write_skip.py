"""Avoid redundant session index writes while preserving authentication changes."""

from datetime import timedelta

from asgiref.sync import async_to_sync
from django.conf import settings
from django.contrib.auth import get_user, login, logout
from django.contrib.auth.models import AnonymousUser
from django.contrib.sessions.backends.base import UpdateError
from django.contrib.sessions.middleware import SessionMiddleware
from django.contrib.sessions.models import Session
from django.db import connection
from django.http import HttpRequest, HttpResponse
from django.test import RequestFactory, TestCase, override_settings
from django.test.utils import CaptureQueriesContext

from apps.users.models import User, UserSession
from apps.users.session_backend import SessionStore


@override_settings(SESSION_SAVE_EVERY_REQUEST=True, DEBUG=False)
class SessionIndexWriteSkipTests(TestCase):
    def setUp(self) -> None:
        super().setUp()
        self.user = User.objects.create_user(email="index-skip@example.com", password="Index-password123!")
        self.factory = RequestFactory()
        self.middleware = SessionMiddleware(lambda request: HttpResponse())

    def request(self, key: str | None = None) -> HttpRequest:
        request = self.factory.get("/")
        request.user = AnonymousUser()
        if key is not None:
            request.COOKIES[settings.SESSION_COOKIE_NAME] = key
        self.middleware.process_request(request)
        return request

    def persist(self, request: HttpRequest) -> str:
        self.middleware.process_response(request, HttpResponse())
        key = request.session.session_key
        self.assertIsNotNone(key)
        assert key is not None
        return key

    def authenticated_key(self) -> str:
        request = self.request()
        login(request, self.user, backend="django.contrib.auth.backends.ModelBackend")
        return self.persist(request)

    def index_query_count(self, captured: CaptureQueriesContext) -> int:
        return sum("users_usersession" in query["sql"].lower() for query in captured.captured_queries)

    def assert_only_index(self, key: str) -> None:
        self.assertEqual(list(UserSession.objects.values_list("session_key", flat=True)), [key])
        self.assertEqual(UserSession.objects.get(session_key=key).user_id, self.user.pk)
        self.assertTrue(Session.objects.filter(session_key=key).exists())

    def test_second_authenticated_request_saves_session_without_index_queries(self) -> None:
        """FAILS on current master: an unchanged authenticated request writes the index."""
        key = self.authenticated_key()
        self.assert_only_index(key)
        previous_expiry = Session.objects.get(pk=key).expire_date - timedelta(minutes=1)
        Session.objects.filter(pk=key).update(expire_date=previous_expiry)
        request = self.request(key)

        with CaptureQueriesContext(connection) as captured:
            request.user = get_user(request)
            self.assertEqual(request.user.pk, self.user.pk)
            self.assertFalse(request.session.modified)
            self.assertEqual(self.persist(request), key)

        self.assertEqual(self.index_query_count(captured), 0)
        self.assertGreater(Session.objects.get(pk=key).expire_date, previous_expiry)
        self.assert_only_index(key)

    def test_login_indexes_only_the_final_key_after_an_anonymous_request(self) -> None:
        """Control: anonymous-to-authenticated persistence must keep passing."""
        request = self.request()
        request.session["before_login"] = True
        old_key = self.persist(request)
        self.assertFalse(UserSession.objects.filter(session_key=old_key).exists())
        request = self.request(old_key)

        login(request, self.user, backend="django.contrib.auth.backends.ModelBackend")
        with CaptureQueriesContext(connection) as captured:
            key = self.persist(request)

        self.assertEqual(self.index_query_count(captured), 1)
        self.assertNotEqual(key, old_key)
        self.assertFalse(UserSession.objects.filter(session_key=old_key).exists())
        self.assert_only_index(key)

    def test_logout_removes_the_index_before_response_persistence(self) -> None:
        """Control: logout and response persistence must keep removing the index."""
        key = self.authenticated_key()
        request = self.request(key)
        request.user = get_user(request)

        logout(request)
        self.middleware.process_response(request, HttpResponse())

        self.assertIsNone(request.session.session_key)
        self.assertFalse(Session.objects.filter(session_key=key).exists())
        self.assertFalse(UserSession.objects.filter(session_key=key).exists())

    def test_restoring_authentication_on_the_same_store_recreates_the_index(self) -> None:
        """Control: removing and restoring the same user ID must keep passing."""
        key = self.authenticated_key()
        store = SessionStore(key)
        user_id = store.pop("_auth_user_id")

        store.save()

        self.assertFalse(UserSession.objects.filter(session_key=key).exists())
        self.assertNotIn("_auth_user_id", Session.objects.get(pk=key).get_decoded())
        store["_auth_user_id"] = user_id
        store.save()

        self.assertEqual(Session.objects.get(pk=key).get_decoded()["_auth_user_id"], user_id)
        self.assert_only_index(key)

    def test_rotated_session_skips_index_queries_on_the_following_save(self) -> None:
        """FAILS on current master: saving after rotation writes the new index again."""
        old_key = self.authenticated_key()
        store = SessionStore(old_key)
        self.assertEqual(store["_auth_user_id"], str(self.user.pk))

        store.cycle_key()

        key = store.session_key
        assert key is not None
        self.assertNotEqual(key, old_key)
        self.assertFalse(Session.objects.filter(session_key=old_key).exists())
        self.assertFalse(UserSession.objects.filter(session_key=old_key).exists())
        self.assert_only_index(key)
        with CaptureQueriesContext(connection) as captured:
            store.save()

        self.assertEqual(self.index_query_count(captured), 0)
        self.assert_only_index(key)

    def test_async_loaded_session_skips_index_queries_on_save(self) -> None:
        """FAILS on current master: saving an asynchronously loaded session writes the index."""
        key = self.authenticated_key()
        store = SessionStore(key)
        # Match Django's cache population so a later sync load cannot hide a missing aload baseline.
        store._session_cache = async_to_sync(store.aload)()
        self.assertEqual(store["_auth_user_id"], str(self.user.pk))

        with CaptureQueriesContext(connection) as captured:
            store.save()

        self.assertEqual(self.index_query_count(captured), 0)
        self.assert_only_index(key)

    def test_deleted_session_raises_update_error_without_resurrecting_its_index(self) -> None:
        """Control: a session deleted after loading must keep raising UpdateError."""
        key = self.authenticated_key()
        store = SessionStore(key)
        self.assertEqual(store["_auth_user_id"], str(self.user.pk))
        Session.objects.filter(session_key=key).delete()
        UserSession.objects.filter(session_key=key).delete()

        with CaptureQueriesContext(connection) as captured, self.assertRaises(UpdateError):
            store.save()

        self.assertEqual(self.index_query_count(captured), 0)
        self.assertFalse(Session.objects.filter(session_key=key).exists())
        self.assertFalse(UserSession.objects.filter(session_key=key).exists())
