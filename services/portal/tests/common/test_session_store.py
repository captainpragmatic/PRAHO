"""Concurrent requests on one session no longer undo each other's writes (ADR-0055).

Two store instances on one key stand for two requests of one customer: each loads, changes what
it changes, and saves, in a chosen order. The threaded case runs real threads on a file-backed
SQLite database in a subprocess, because the test database is in memory.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import textwrap
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

from django.conf import settings
from django.contrib.sessions.backends import db as stock_db
from django.contrib.sessions.backends.base import UpdateError
from django.contrib.sessions.exceptions import SessionInterrupted
from django.contrib.sessions.models import Session
from django.test import TestCase
from django.utils import timezone

from apps.common.session_store import SessionSaveContended, SessionStore

PORTAL_ROOT = Path(__file__).resolve().parents[2]


def _stored(key: str) -> dict[str, object]:
    return SessionStore().decode(Session.objects.get(session_key=key).session_data)


class MergingSessionStoreTests(TestCase):
    def _session(self, **data: object) -> str:
        store = SessionStore()
        store.update(data)
        store.save()
        assert store.session_key is not None
        return store.session_key

    def _load(self, key: str) -> SessionStore:
        store = SessionStore(session_key=key)
        store._get_session()  # load now, as a request does when it first reads its session
        return store

    def test_the_configured_engine_is_this_store(self) -> None:
        self.assertEqual(settings.SESSION_ENGINE, "apps.common.session_store")
        self.assertTrue(issubclass(SessionStore, stock_db.SessionStore))

    def test_a_stale_request_does_not_undo_a_company_switch(self) -> None:
        key = self._session(user_id=7, selected_customer_id=1, selected_customer_name="Acme", selected_customer_role="owner")
        stale, switch = self._load(key), self._load(key)
        switch.update({"selected_customer_id": 2, "selected_customer_name": "Beta", "selected_customer_role": "viewer"})
        switch.save()
        stale["last_activity"] = 123.0
        stale.save()

        stored = _stored(key)
        self.assertEqual(
            (stored["selected_customer_id"], stored["selected_customer_name"], stored["selected_customer_role"]),
            (2, "Beta", "viewer"),
        )
        self.assertEqual(stored["last_activity"], 123.0)

    def test_a_company_group_is_stored_whole_never_mixed(self) -> None:
        key = self._session(user_id=7, selected_customer_id=1, selected_customer_name="Acme", selected_customer_role="owner")
        first, second = self._load(key), self._load(key)
        second.update({"selected_customer_id": 3, "selected_customer_name": "Gamma", "selected_customer_role": "viewer"})
        second.save()
        # The role this request picks equals its baseline, so only the id and name differ.
        first.update({"selected_customer_id": 2, "selected_customer_name": "Beta", "selected_customer_role": "owner"})
        first.save()

        stored = _stored(key)
        self.assertEqual(
            (stored["selected_customer_id"], stored["selected_customer_name"], stored["selected_customer_role"]),
            (2, "Beta", "owner"),
        )

    def test_a_key_another_request_deleted_stays_deleted(self) -> None:
        key = self._session(user_id=7, new_mfa_backup_codes=["a"], cart={"items": []})
        stale, deleter = self._load(key), self._load(key)
        del deleter["new_mfa_backup_codes"]
        deleter.save()
        stale["last_activity"] = 1.0
        stale.save()
        self.assertNotIn("new_mfa_backup_codes", _stored(key))

    def test_a_nested_change_made_in_place_is_saved(self) -> None:
        key = self._session(user_id=7, security_fingerprint={"ip_hash": "a", "created_at": 1.0})
        store = self._load(key)
        store["security_fingerprint"]["ip_hash"] = "b"  # mutated in place, as code does
        store.modified = True
        store.save()
        self.assertEqual(_stored(key)["security_fingerprint"], {"ip_hash": "b", "created_at": 1.0})

    def test_two_tabs_keep_both_purchases_in_progress(self) -> None:
        key = self._session(user_id=7, order_checkout_attempts={})
        tab_a, tab_b = self._load(key), self._load(key)
        tab_a["order_checkout_attempts"] = {"cart-a": {"key": "idem-a"}}
        tab_a.save()
        tab_b["order_checkout_attempts"] = {"cart-b": {"key": "idem-b"}}
        tab_b.save()
        self.assertEqual(
            _stored(key)["order_checkout_attempts"], {"cart-a": {"key": "idem-a"}, "cart-b": {"key": "idem-b"}}
        )

    def test_two_tabs_creating_the_first_purchase_both_keep_theirs(self) -> None:
        key = self._session(user_id=7)  # no record map yet
        tab_a, tab_b = self._load(key), self._load(key)
        tab_a["gift_purchase_forms"] = {"form-a": {"amount": 50}}
        tab_a.save()
        tab_b["gift_purchase_forms"] = {"form-b": {"amount": 70}}
        tab_b.save()
        self.assertEqual(
            _stored(key)["gift_purchase_forms"], {"form-a": {"amount": 50}, "form-b": {"amount": 70}}
        )

    def test_removing_ones_last_record_keeps_anothers(self) -> None:
        key = self._session(user_id=7, order_checkout_attempts={"cart-a": {"key": "idem-a"}})
        finishing, starting = self._load(key), self._load(key)
        starting["order_checkout_attempts"] = {"cart-a": {"key": "idem-a"}, "cart-b": {"key": "idem-b"}}
        starting.save()
        del finishing["order_checkout_attempts"]  # done with its only purchase
        finishing.save()
        self.assertEqual(_stored(key)["order_checkout_attempts"], {"cart-b": {"key": "idem-b"}})

    def test_a_change_of_json_type_is_saved(self) -> None:
        key = self._session(user_id=7, flag=1)
        store = self._load(key)
        store["flag"] = True  # equal to 1 in Python, different as stored
        store.save()
        self.assertIs(_stored(key)["flag"], True)

    def test_a_previously_saved_key_is_not_written_again_by_a_later_save(self) -> None:
        key = self._session(user_id=7, step=0)
        store, other = self._load(key), self._load(key)
        store["step"] = 1
        store.save()  # published as this request's new baseline
        other["step"] = 5  # another request changes it afterwards
        other.save()
        store["unrelated"] = True
        store.save()  # must not write step=1 again
        stored = _stored(key)
        self.assertEqual((stored["step"], stored["unrelated"]), (5, True))

    def test_rotating_an_unloaded_session_cannot_outlive_a_logout_after_its_load(self) -> None:
        key = self._session(user_id=7)
        unloaded = SessionStore(session_key=key)  # rotation is its first touch of the session
        load = SessionStore.load

        def load_then_logout(store: SessionStore) -> dict[str, object]:
            data = load(store)
            Session.objects.filter(session_key=key).delete()  # a logout lands right after the load
            return data

        with patch.object(SessionStore, "load", load_then_logout), self.assertRaises(SessionInterrupted):
            unloaded.cycle_key()
        self.assertEqual(Session.objects.count(), 0)  # no new authenticated session was minted

    def test_a_rotation_that_gives_up_fails_closed(self) -> None:
        # A password change rotates the key; if the rotation fails, the new session_auth_hash must
        # never be saved under the old key, which the old cookie could keep using.
        key = self._session(user_id=7, session_auth_hash="old")
        password_change, other = self._load(key), self._load(key)
        other["unrelated"] = 1
        other.save()  # the row changes under the rotation, which then cannot delete what it read
        password_change["session_auth_hash"] = "new"
        with (
            patch("apps.common.session_store.MAX_MERGE_ATTEMPTS", 1),
            self.assertRaises(SessionSaveContended),
        ):
            password_change.cycle_key()
        self.assertFalse(Session.objects.filter(session_key=key).exists())
        self.assertIsNone(password_change.session_key)
        self.assertEqual(dict(password_change.items()), {})

    def test_a_rotation_interrupted_by_logout_leaves_nothing_to_save(self) -> None:
        key = self._session(user_id=7, session_auth_hash="old")
        stale = self._load(key)
        Session.objects.filter(session_key=key).delete()
        stale["session_auth_hash"] = "new"
        with self.assertRaises(SessionInterrupted):
            stale.cycle_key()
        self.assertIsNone(stale.session_key)
        self.assertEqual(dict(stale.items()), {})

    def test_a_contended_save_is_answered_as_a_temporary_outage(self) -> None:
        from django.http import HttpResponse  # noqa: PLC0415
        from django.test import RequestFactory  # noqa: PLC0415

        from apps.common.session_store import SessionMiddleware  # noqa: PLC0415

        key = self._session(user_id=7)
        request = RequestFactory().post("/cart/", HTTP_ACCEPT="application/json")
        request.COOKIES[settings.SESSION_COOKIE_NAME] = key
        middleware = SessionMiddleware(lambda request: HttpResponse("ok"))
        middleware.process_request(request)
        request.session["cart"] = {"items": [1]}
        with (
            patch("django.db.models.query.QuerySet.update", return_value=0),
            patch("apps.common.session_store._back_off"),
        ):
            response = middleware.process_response(request, HttpResponse("ok"))
        self.assertEqual(response.status_code, 503)
        self.assertIn("Retry-After", response)

    def test_endless_contention_is_not_reported_as_a_deleted_session(self) -> None:
        key = self._session(user_id=7)
        store = self._load(key)
        store["x"] = 1
        with (
            patch("django.db.models.query.QuerySet.update", return_value=0),
            patch("apps.common.session_store._back_off"),
            self.assertRaises(SessionSaveContended),
        ):
            store.save()
        self.assertTrue(Session.objects.filter(session_key=key).exists())

    def test_repeated_saves_in_one_request_apply_cumulatively(self) -> None:
        key = self._session(user_id=7)
        store, other = self._load(key), self._load(key)
        store["step"] = 1
        store.save()  # a save in the middle of a request
        other["other"] = "kept"
        other.save()
        store["step"] = 2
        store.save()  # the response's save must not re-apply step 1 over the other request
        stored = _stored(key)
        self.assertEqual((stored["step"], stored["other"]), (2, "kept"))

    def test_a_save_after_the_row_was_deleted_never_recreates_it(self) -> None:
        key = self._session(user_id=7)
        stale = self._load(key)
        Session.objects.filter(session_key=key).delete()  # a concurrent logout
        stale["last_activity"] = 1.0
        with self.assertRaises(UpdateError):
            stale.save()
        self.assertFalse(Session.objects.filter(session_key=key).exists())

    def test_rotation_after_a_concurrent_logout_creates_no_session(self) -> None:
        key = self._session(user_id=7, session_auth_hash="old")
        stale = self._load(key)
        Session.objects.filter(session_key=key).delete()  # logout elsewhere
        stale["session_auth_hash"] = "new"
        with self.assertRaises(SessionInterrupted):
            stale.cycle_key()
        self.assertEqual(Session.objects.count(), 0)

    def test_rotation_keeps_a_concurrent_company_switch(self) -> None:
        key = self._session(user_id=7, selected_customer_id=1, selected_customer_name="Acme", selected_customer_role="owner")
        password_change, switch = self._load(key), self._load(key)
        switch.update({"selected_customer_id": 2, "selected_customer_name": "Beta", "selected_customer_role": "viewer"})
        switch.save()
        password_change["session_auth_hash"] = "new"
        password_change.cycle_key()

        self.assertFalse(Session.objects.filter(session_key=key).exists())
        assert password_change.session_key is not None
        stored = _stored(password_change.session_key)
        self.assertEqual((stored["selected_customer_id"], stored["session_auth_hash"]), (2, "new"))

    def test_a_pre_login_session_rotates_as_before(self) -> None:
        key = self._session(_language="ro")
        store = self._load(key)
        store.cycle_key()
        store["user_id"] = 7
        store.save()
        assert store.session_key is not None
        self.assertNotEqual(store.session_key, key)
        self.assertEqual(_stored(store.session_key)["user_id"], 7)

    def test_a_merged_expiry_sets_the_stored_expiry(self) -> None:
        key = self._session(user_id=7)
        store, other = self._load(key), self._load(key)
        other["unrelated"] = 1
        other.save()  # forces the expiring save onto a merged row
        store.set_expiry(60)
        before = timezone.now()
        store.save()
        expire_date = Session.objects.get(session_key=key).expire_date
        self.assertLessEqual(abs((expire_date - (before + timedelta(seconds=60))).total_seconds()), 5)

    def test_sessions_written_by_the_stock_store_still_decode_and_the_reverse(self) -> None:
        stock = stock_db.SessionStore()
        stock["user_id"] = 7
        stock.save()
        assert stock.session_key is not None
        self.assertEqual(SessionStore(session_key=stock.session_key)["user_id"], 7)
        ours = SessionStore()
        ours["user_id"] = 8
        ours.save()
        self.assertEqual(stock_db.SessionStore(session_key=ours.session_key)["user_id"], 8)


THREADED_HARNESS = textwrap.dedent(
    """
    import json, sys, threading
    import django
    django.setup()
    from django.core.management import call_command
    from django.contrib.sessions.backends.base import UpdateError
    from apps.common.session_store import SessionStore

    call_command("migrate", "sessions", verbosity=0)
    seed = SessionStore()
    seed["user_id"] = 7
    seed.save()
    key = seed.session_key
    errors = []

    def worker(thread):
        for step in range(25):
            store = SessionStore(session_key=key)
            store[f"t{thread}_{step}"] = step
            try:
                store.save()
            except Exception as error:  # every failure is reported, none is retried
                errors.append(repr(error))

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    stored = SessionStore(session_key=key)
    written = sorted(k for k in stored.keys() if k.startswith("t"))
    print(json.dumps({"written": len(written), "errors": errors}))
    """
)


class ThreadedMergeTests(TestCase):
    def test_eight_threads_on_one_session_keep_every_write(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            environment = {
                **os.environ,
                "DJANGO_SETTINGS_MODULE": "config.settings.dev",
                "SESSION_DB_PATH": str(Path(directory) / "sessions.sqlite3"),
                "PYTHONPATH": "",
            }
            completed = subprocess.run(  # noqa: S603 -- fixed interpreter and a test-owned script
                [sys.executable, "-c", THREADED_HARNESS],
                cwd=PORTAL_ROOT,
                env=environment,
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )
        self.assertEqual(completed.returncode, 0, completed.stderr[-2000:])
        result = json.loads(completed.stdout.strip().splitlines()[-1])
        self.assertEqual(result, {"written": 8 * 25, "errors": []})
