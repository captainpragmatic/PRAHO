"""Session persistence, rotation, reconciliation, and indexed revocation."""

from datetime import timedelta
from io import StringIO
from unittest.mock import patch

from asgiref.sync import async_to_sync
from django.conf import settings
from django.contrib.auth import get_user, login, update_session_auth_hash
from django.contrib.auth.models import AnonymousUser
from django.contrib.sessions.backends.db import SessionStore as LegacySessionStore
from django.contrib.sessions.middleware import SessionMiddleware
from django.contrib.sessions.models import Session
from django.core.management import call_command
from django.db.models.signals import post_delete
from django.http import HttpRequest, HttpResponse
from django.test import RequestFactory, TestCase, override_settings
from django.utils import timezone

from apps.users.models import User, UserSession
from apps.users.services import SessionSecurityService
from apps.users.session_backend import SessionStore
from apps.users.tasks import cleanup_expired_2fa_sessions, cleanup_expired_password_reset_tokens


class SessionIndexTests(TestCase):
    def setUp(self) -> None:
        super().setUp()
        self.enterContext(override_settings(DEBUG=False))
        self.user = User.objects.create_user(email="index@example.com", password="Index-password123!")
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

    def authenticated_request(self) -> HttpRequest:
        request = self.request()
        login(request, self.user, backend="django.contrib.auth.backends.ModelBackend")
        self.persist(request)
        return request

    def assert_only_index(self, key: str) -> None:
        self.assertEqual(list(UserSession.objects.filter(user=self.user).values_list("session_key", flat=True)), [key])
        self.assertTrue(Session.objects.filter(session_key=key).exists())

    def test_new_anonymous_store_creates_a_session_without_an_index(self) -> None:
        self.assertEqual(settings.SESSION_ENGINE, "apps.users.session_backend")
        session = SessionStore()
        session.create()
        self.assertIsNotNone(session.session_key)
        self.assertTrue(Session.objects.filter(session_key=session.session_key).exists())
        self.assertFalse(UserSession.objects.exists())

    def test_two_logins_are_indexed_and_all_are_revoked(self) -> None:
        first, second = self.authenticated_request(), self.authenticated_request()
        keys = {first.session.session_key, second.session.session_key}
        self.assertEqual(UserSession.objects.filter(user=self.user).count(), 2)

        SessionSecurityService.invalidate_all_sessions_for_user(self.user.pk)

        self.assertFalse(Session.objects.filter(session_key__in=keys).exists())
        self.assertFalse(UserSession.objects.filter(user=self.user).exists())

    def test_password_change_keeps_exactly_the_current_session(self) -> None:
        current, other = self.authenticated_request(), self.authenticated_request()
        old_keys = {current.session.session_key, other.session.session_key}

        SessionSecurityService.rotate_session_on_password_change(current)

        key = current.session.session_key
        assert key is not None
        self.assertNotIn(key, old_keys)
        self.assertFalse(Session.objects.filter(session_key__in=old_keys).exists())
        self.assert_only_index(key)

    def test_login_flush_branch_is_indexed_when_response_saves_session(self) -> None:
        stale = self.authenticated_request().session.session_key
        self.user.set_password("Changed-password123!")
        self.user.save(update_fields=["password"])
        request = self.request(stale)

        login(request, self.user, backend="django.contrib.auth.backends.ModelBackend")

        self.assertIsNone(request.session.session_key)
        key = self.persist(request)
        self.assertNotEqual(key, stale)
        self.assertFalse(Session.objects.filter(session_key=stale).exists())
        self.assert_only_index(key)

    def test_cycle_key_keeps_exactly_the_new_index_row(self) -> None:
        request = self.authenticated_request()
        old_key = request.session.session_key

        request.session.cycle_key()

        key = request.session.session_key
        assert key is not None
        self.assertNotEqual(key, old_key)
        self.assertFalse(Session.objects.filter(session_key=old_key).exists())
        self.assert_only_index(key)

    def test_update_session_auth_hash_repoints_the_index(self) -> None:
        request = self.authenticated_request()
        old_key = request.session.session_key
        self.user.set_password("Replacement-password123!")
        self.user.save(update_fields=["password"])

        update_session_auth_hash(request, self.user)
        key = self.persist(request)

        self.assertNotEqual(key, old_key)
        self.assertFalse(Session.objects.filter(session_key=old_key).exists())
        self.assert_only_index(key)
        self.assertEqual(
            Session.objects.get(pk=key).get_decoded()["_auth_user_hash"], self.user.get_session_auth_hash()
        )

    def test_fallback_secret_authentication_repoints_the_index(self) -> None:
        with override_settings(SECRET_KEY="old-session-signing-key"):
            old_key = self.authenticated_request().session.session_key
        with override_settings(SECRET_KEY="new-session-signing-key", SECRET_KEY_FALLBACKS=["old-session-signing-key"]):
            request = self.request(old_key)
            self.assertEqual(get_user(request).pk, self.user.pk)
            key = self.persist(request)
            self.assertNotEqual(key, old_key)
            self.assertFalse(Session.objects.filter(session_key=old_key).exists())
            self.assert_only_index(key)

    def test_removing_authentication_removes_the_index_on_save(self) -> None:
        request = self.authenticated_request()
        key = request.session.session_key
        del request.session["_auth_user_id"]

        request.session.save()

        self.assertTrue(Session.objects.filter(session_key=key).exists())
        self.assertFalse(UserSession.objects.exists())

    def test_clear_expired_removes_index_rows_with_their_sessions(self) -> None:
        expired_key = self.authenticated_request().session.session_key
        Session.objects.filter(session_key=expired_key).update(expire_date=timezone.now() - timedelta(days=1))
        live_key = self.authenticated_request().session.session_key

        SessionStore.clear_expired()

        self.assertFalse(Session.objects.filter(session_key=expired_key).exists())
        self.assertFalse(UserSession.objects.filter(session_key=expired_key).exists())
        assert live_key is not None
        self.assert_only_index(live_key)

    def test_flush_removes_both_rows(self) -> None:
        request = self.authenticated_request()
        key = request.session.session_key

        request.session.flush()

        self.assertIsNone(request.session.session_key)
        self.assertFalse(Session.objects.filter(session_key=key).exists())
        self.assertFalse(UserSession.objects.exists())

    def test_async_rotation_and_flush_use_the_same_index(self) -> None:
        request = self.authenticated_request()
        old_key = request.session.session_key

        async_to_sync(request.session.acycle_key)()

        key = request.session.session_key
        assert key is not None
        self.assertNotEqual(key, old_key)
        self.assertFalse(Session.objects.filter(session_key=old_key).exists())
        self.assert_only_index(key)
        async_to_sync(request.session.aflush)()
        self.assertFalse(Session.objects.filter(session_key=key).exists())
        self.assertFalse(UserSession.objects.exists())

    def test_failed_index_write_rolls_back_the_session_insert(self) -> None:
        session = SessionStore()
        session["_auth_user_id"] = str(self.user.pk)

        with (
            patch.object(UserSession.objects, "bulk_create", side_effect=RuntimeError("Index write failed")),
            self.assertRaisesMessage(RuntimeError, "Index write failed"),
        ):
            session.save()

        self.assertFalse(Session.objects.filter(session_key=session.session_key).exists())
        self.assertFalse(UserSession.objects.exists())

    def test_a_deleted_users_session_still_saves(self) -> None:
        """Django anonymises the request of a deleted user but keeps the session row.

        Every later request re-saves that session, so an index write that could fail on the
        missing user would turn the login redirect into a server error for that browser.
        """
        request = self.authenticated_request()
        key = request.session.session_key
        User.objects.filter(pk=self.user.pk).delete()
        self.assertFalse(UserSession.objects.exists())

        request.session["touched"] = True
        request.session.save()

        self.assertTrue(Session.objects.filter(session_key=key).exists())
        self.assertEqual(get_user(request), AnonymousUser())

    def test_user_without_index_does_not_decode_any_sessions(self) -> None:
        legacy = LegacySessionStore()
        legacy["_auth_user_id"] = str(self.user.pk)
        legacy.save()

        with patch.object(Session, "get_decoded", side_effect=AssertionError("Revocation decoded a session")) as decode:
            SessionSecurityService.invalidate_all_sessions_for_user(self.user.pk)
            decode.assert_not_called()

        self.assertTrue(Session.objects.filter(session_key=legacy.session_key).exists())
        self.assertFalse(UserSession.objects.exists())

    @override_settings(SESSION_ENGINE="django.contrib.sessions.backends.db")
    def test_active_unindexed_user_emits_security_error(self) -> None:
        self.middleware = SessionMiddleware(lambda request: HttpResponse())
        request = self.authenticated_request()

        with self.assertLogs("apps.users.services", level="ERROR") as captured:
            SessionSecurityService.rotate_session_on_2fa_change(request)

        self.assertTrue(
            any("🚨 [SessionSecurity] session index empty for an active user" in line for line in captured.output)
        )
        self.assertTrue(Session.objects.filter(session_key=request.session.session_key).exists())
        self.assertFalse(UserSession.objects.exists())

    def test_revocation_preserves_a_session_inserted_after_key_capture(self) -> None:
        request = self.authenticated_request()
        old_key = request.session.session_key
        new_keys: list[str] = []

        def save_new_login(sender: type[Session], instance: Session, **kwargs: object) -> None:
            if instance.session_key == old_key:
                session = SessionStore()
                session["_auth_user_id"] = str(self.user.pk)
                session.save()
                assert session.session_key is not None
                new_keys.append(session.session_key)

        post_delete.connect(save_new_login, sender=Session)
        try:
            SessionSecurityService.invalidate_all_sessions_for_user(self.user.pk)
        finally:
            post_delete.disconnect(save_new_login, sender=Session)

        self.assertEqual(len(new_keys), 1)
        self.assertFalse(Session.objects.filter(session_key=old_key).exists())
        self.assert_only_index(new_keys[0])

    def test_reconcile_command_indexes_only_missing_keys_then_revokes_them(self) -> None:
        current = self.authenticated_request().session.session_key
        legacy = LegacySessionStore()
        legacy["_auth_user_id"] = str(self.user.pk)
        legacy.save()
        UserSession.objects.create(user=self.user, session_key="orphan")
        original_decode = Session.get_decoded

        def decode_missing(session: Session) -> dict[str, object]:
            if session.session_key == current:
                raise AssertionError("Reconciliation decoded an indexed session")
            return original_decode(session)

        with patch.object(Session, "get_decoded", decode_missing):
            call_command("reconcile_session_index", stdout=StringIO())
        self.assertEqual(
            set(UserSession.objects.values_list("session_key", flat=True)),
            {current, legacy.session_key},
        )
        with patch.object(
            Session, "get_decoded", side_effect=AssertionError("Repeated reconciliation decoded a session")
        ):
            call_command("reconcile_session_index", stdout=StringIO())

        SessionSecurityService.invalidate_all_sessions_for_user(self.user.pk)
        self.assertFalse(Session.objects.filter(session_key__in=[current, legacy.session_key]).exists())
        self.assertFalse(UserSession.objects.exists())

    def test_scheduled_cleanups_prune_orphans_and_reconcile_old_worker_sessions(self) -> None:
        for task, marker in (
            (cleanup_expired_2fa_sessions, "2fa_challenge"),
            (cleanup_expired_password_reset_tokens, "password_reset_token"),
        ):
            with self.subTest(task=task.__name__):
                expired = SessionStore()
                expired["_auth_user_id"] = str(self.user.pk)
                expired[marker] = True
                expired.set_expiry(-7200)
                expired.save()
                legacy = LegacySessionStore()
                legacy["_auth_user_id"] = str(self.user.pk)
                legacy.save()

                result = task()

                self.assertIs(result["success"], True, result)
                self.assertFalse(Session.objects.filter(session_key=expired.session_key).exists())
                self.assertFalse(UserSession.objects.filter(session_key=expired.session_key).exists())
                self.assertTrue(UserSession.objects.filter(user=self.user, session_key=legacy.session_key).exists())
