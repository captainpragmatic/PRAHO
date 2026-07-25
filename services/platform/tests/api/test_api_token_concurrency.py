"""PostgreSQL concurrency guarantees for custom API tokens (issue #248)."""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

from django.db import close_old_connections, connection
from django.test import TransactionTestCase, override_settings
from rest_framework.response import Response
from rest_framework.test import APIClient, APIRequestFactory

from apps.api.users.authentication import HashedTokenAuthentication
from apps.users.models import APIToken, User


class APITokenPostgresConcurrencyTests(TransactionTestCase):
    """Exercise token issuance and usage tracking over independent connections."""

    reset_sequences = True

    def setUp(self) -> None:
        if connection.vendor != "postgresql":
            self.skipTest("API token concurrency guarantees require PostgreSQL")
        self.password = "StrongPass123!"
        self.user = User.objects.create_user(email="api-token-race@example.test", password=self.password)

    def _obtain_token(self) -> Response:
        close_old_connections()
        try:
            client = APIClient()
            return client.post(
                "/api/users/token/",
                {"email": self.user.email, "password": self.password, "name": "concurrent"},
                format="json",
            )
        finally:
            connection.close()

    @override_settings(API_TOKEN_MAX_ACTIVE_PER_USER=1)
    def test_concurrent_obtain_token_calls_never_exceed_cap(self) -> None:
        first_reached_create = threading.Event()
        second_reached_create = threading.Event()
        release_first_create = threading.Event()
        call_lock = threading.Lock()
        create_call_count = 0
        original_create = APIToken.objects.create

        def coordinated_create(**kwargs: object) -> APIToken:
            nonlocal create_call_count
            with call_lock:
                create_call_count += 1
                call_number = create_call_count
            if call_number == 1:
                first_reached_create.set()
                if not release_first_create.wait(timeout=10):
                    raise AssertionError("Timed out releasing first token creation")
            else:
                second_reached_create.set()
            return original_create(**kwargs)

        with (
            patch.object(APIToken.objects, "create", side_effect=coordinated_create),
            ThreadPoolExecutor(max_workers=2) as executor,
        ):
            first = executor.submit(self._obtain_token)
            self.assertTrue(first_reached_create.wait(timeout=5), "First request never reached token creation")
            second = executor.submit(self._obtain_token)
            try:
                self.assertFalse(
                    second_reached_create.wait(timeout=1),
                    "Second request crossed the per-user row lock before the first committed",
                )
            finally:
                release_first_create.set()
            responses = [first.result(timeout=10), second.result(timeout=10)]

        self.assertEqual(sorted(response.status_code for response in responses), [200, 400])
        self.assertEqual(APIToken.objects.filter(user=self.user).count(), 1)

    def test_concurrent_authentications_write_last_used_once_per_interval(self) -> None:
        raw_key = APIToken.generate_key()
        token = APIToken.objects.create(
            user=self.user,
            key_hash=APIToken.hash_key(raw_key),
            key_prefix=raw_key[:8],
            name="concurrent-auth",
        )
        update_barrier = threading.Barrier(2)
        original_update = HashedTokenAuthentication._update_last_used

        def synchronized_update(stale_token: APIToken) -> None:
            update_barrier.wait(timeout=10)
            original_update(stale_token)

        def authenticate() -> bool:
            close_old_connections()
            try:
                request = APIRequestFactory().get(
                    "/api/users/token/me/",
                    HTTP_AUTHORIZATION=f"Bearer {raw_key}",
                )
                result = HashedTokenAuthentication().authenticate(request)
                if result is None:
                    raise AssertionError("Token authentication unexpectedly declined")
                return result[1].last_used_at is not None
            finally:
                connection.close()

        with (
            patch.object(
                HashedTokenAuthentication,
                "_update_last_used",
                new=staticmethod(synchronized_update),
            ),
            ThreadPoolExecutor(max_workers=2) as executor,
        ):
            updates = list(executor.map(lambda _: authenticate(), range(2)))

        self.assertEqual(updates.count(True), 1)
        token.refresh_from_db()
        self.assertIsNotNone(token.last_used_at)
