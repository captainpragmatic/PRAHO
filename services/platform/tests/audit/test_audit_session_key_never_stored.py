"""No audit row, export or SIEM entry holds a usable session key.

Django cycles the session key before user_logged_in fires, so a key recorded at login is the live
one; an export holding it would let its reader resume that session. Audit rows keep a keyed digest:
equal for the same session, so search and same-session correlation keep working.
"""

from __future__ import annotations

import dataclasses
import json
import random
from typing import Any

from django.contrib.auth import get_user_model
from django.contrib.sessions.backends.db import SessionStore
from django.test import Client, RequestFactory, TestCase, override_settings
from django.urls import reverse

from apps.audit.models import AuditChainHead, AuditChainLink, AuditEvent, AuditImmutabilityError
from apps.audit.services import AuditContext, AuditEventData, AuditIntegrityService, AuditSearchService, AuditService
from apps.audit.session_digest import SESSION_DIGEST_PREFIX, session_key_digest
from apps.audit.siem import SIEMService
from apps.users.mfa import MFAService
from apps.users.services import SessionSecurityService

User = get_user_model()


def _all_text(event: AuditEvent) -> str:
    """Every stored value of the row, as one string."""
    values: list[Any] = [
        event.session_key,
        event.description,
        event.request_id,
        event.object_id,
        json.dumps(event.metadata, default=str),
        json.dumps(event.old_values, default=str),
        json.dumps(event.new_values, default=str),
    ]
    return "\n".join(str(value) for value in values)


class SessionKeysNeverStoredTests(TestCase):
    def setUp(self) -> None:
        self.admin = User.objects.create_user(
            email="admin@example.com", password="x-pass-123", is_staff=True, staff_role="admin"
        )
        self.member = User.objects.create_user(email="member@example.com", password="x-pass-123")
        self.seen_keys: set[str] = set()

    def _session_request(self, user: Any) -> Any:
        request = RequestFactory().get("/")
        request.user = user
        request.session = SessionStore()
        request.session.create()
        self.seen_keys.add(request.session.session_key)
        return request

    def _assert_no_raw_key_anywhere(self) -> None:
        self.assertTrue(self.seen_keys)
        events = list(AuditEvent.objects.all())
        self.assertTrue(events)
        for event in events:
            text = _all_text(event)
            for raw in self.seen_keys:
                self.assertNotIn(raw, text, f"{event.action} holds a live session key")
            if event.session_key:
                self.assertTrue(event.session_key.startswith(SESSION_DIGEST_PREFIX), event.action)

        siem = SIEMService()
        for event in events:
            entry = json.dumps(dataclasses.asdict(siem._create_log_entry(event)), default=str)
            for raw in self.seen_keys:
                self.assertNotIn(raw, entry, f"the SIEM entry for {event.action} holds a session key")

        client = Client()
        client.force_login(self.admin)
        for export_format in ("csv", "json"):
            response = client.get(reverse("audit:export_logs"), {"format": export_format})
            self.assertEqual(response.status_code, 200)
            body = b"".join(response.streaming_content) if response.streaming else response.content
            for raw in self.seen_keys:
                self.assertNotIn(raw.encode(), body, f"the {export_format} export holds a session key")

    def test_no_audit_row_or_export_holds_a_live_session_key(self) -> None:
        # Login and logout through Django's own login(), which cycles the key first.
        client = Client()
        client.force_login(self.member)
        self.seen_keys.add(client.session.session_key)
        client.post(reverse("users:logout"))

        # 2FA enrolment records the session as metadata["session_id"].
        MFAService.enable_totp(self.member, self._session_request(self.member))

        # A password-change rotation stores only short, unusable prefixes: they stay prefixes.
        request = self._session_request(self.member)
        SessionSecurityService.rotate_session_on_password_change(request, self.member)
        self.seen_keys.add(request.session.session_key)
        rotation = AuditEvent.objects.filter(action="session_rotated_password_change").first()
        if rotation is not None:
            prefix = rotation.metadata.get("old_session_key") or ""
            self.assertTrue(prefix == "" or prefix.endswith("..."), prefix)

        self._assert_no_raw_key_anywhere()

    def test_session_search_finds_the_event_by_raw_or_digested_key(self) -> None:
        raw = self._session_request(self.member).session.session_key
        event = AuditService.log_event(
            AuditEventData(event_type="login_success", description="signed in"),
            AuditContext(user=self.member, session_key=raw),
        )
        self.assertEqual(event.session_key, session_key_digest(raw))

        for search_value in (raw, session_key_digest(raw)):
            queryset, _info = AuditSearchService.build_advanced_query({"session_keys": search_value}, self.admin)
            self.assertEqual(list(queryset), [event], search_value)
        empty, _info = AuditSearchService.build_advanced_query({"session_keys": ""}, self.admin)
        self.assertIn(event, list(empty), "an empty filter is no filter, never the digest of nothing")


@override_settings(AUDIT_CHAIN_ENABLED=True)
class BulkCreateIsAuditedLikeSaveTests(TestCase):
    def setUp(self) -> None:
        self.user = User.objects.create_user(email="bulk@example.com", password="x-pass-123")
        AuditChainHead.objects.get_or_create(pk=1)
        AuditChainHead.objects.filter(pk=1).update(backfill_complete=True)

    def _unsaved(self, raw_key: str) -> AuditEvent:
        return AuditEvent(
            user=self.user,
            action="login_success",
            category="authentication",
            severity="low",
            description=f"signed in with session {raw_key}",
            session_key=raw_key,
            metadata={"session_info": {"session_key": raw_key}},
        )

    def test_bulk_create_stamps_chains_and_refuses_conflict_modes(self) -> None:
        raw_keys = [f"{index:02d}" + "k" * 30 for index in range(3)]
        created = AuditEvent.objects.bulk_create([self._unsaved(raw) for raw in raw_keys])

        for event, raw in zip(created, raw_keys, strict=True):
            stored = AuditEvent.objects.get(pk=event.pk)
            self.assertEqual(stored.session_key, session_key_digest(raw))
            self.assertNotIn(raw, _all_text(stored))
            expected = AuditIntegrityService.integrity_stamp_marker(stored)["integrity_hash"]
            self.assertEqual(stored.metadata.get("integrity_hash"), expected, "stamped like save()")
            self.assertTrue(AuditChainLink.objects.filter(event_id_str=str(stored.pk)).exists(), "chained")

        for conflict_mode in ({"ignore_conflicts": True}, {"update_conflicts": True}):
            with self.assertRaises(AuditImmutabilityError):
                AuditEvent.objects.bulk_create([self._unsaved("x" * 32)], **conflict_mode)


class SessionInfoKeepsItsOtherFieldsTests(TestCase):
    def test_session_times_survive_beside_the_digested_key(self) -> None:
        user = User.objects.create_user(email="times@example.com", password="x-pass-123")
        raw = "r" * 32
        created_at = "2026-10-17T10:00:00.123456+00:00"
        event = AuditService.log_event(
            AuditEventData(event_type="logout_manual", description="signed out"),
            AuditContext(
                user=user,
                session_key=raw,
                metadata={
                    "session_info": {
                        "session_key": raw,
                        "session_created": created_at,
                        "duration_human": "0:42:07.000001",
                    }
                },
            ),
        )
        info = event.metadata["session_info"]
        self.assertEqual(info["session_key"], session_key_digest(raw))
        self.assertEqual(info["session_created"], created_at, "a timestamp is not a session key")
        self.assertEqual(info["duration_human"], "0:42:07.000001")


class DirectInsertsAreScrubbedTests(TestCase):
    def test_a_direct_create_digests_every_session_identifier_and_still_verifies(self) -> None:
        raw = "d" * 32
        event = AuditEvent.objects.create(
            action="login_success",
            category="authentication",
            severity="low",
            description=f"signed in with session {raw}",
            session_key=raw,
            metadata={"session_id": raw, "nested": {"old_session_key": raw}},
            new_values={"session_key": raw},
        )
        stored = AuditEvent.objects.get(pk=event.pk)
        self.assertNotIn(raw, _all_text(stored))
        self.assertEqual(stored.metadata["session_id"], session_key_digest(raw))
        expected = AuditIntegrityService.integrity_stamp_marker(stored)["integrity_hash"]
        self.assertEqual(stored.metadata.get("integrity_hash"), expected, "the MAC covers the digests")


class LabelledKeysInTextAreScrubbedTests(TestCase):
    def test_a_key_named_only_in_free_text_is_digested(self) -> None:
        raw = "k1" + "a" * 30
        event = AuditEvent.objects.create(
            action="login_success",
            category="authentication",
            severity="low",
            description=f"resumed session_key={raw} after a timeout",
            metadata={"note": f"Session ID: {raw}"},
        )
        stored = AuditEvent.objects.get(pk=event.pk)
        self.assertNotIn(raw, _all_text(stored))
        self.assertIn(session_key_digest(raw), stored.description)
        self.assertIn(session_key_digest(raw), stored.metadata["note"])


class SessionNamedCollectionsAreScrubbedTests(TestCase):
    def test_every_string_under_a_session_named_key_is_digested(self) -> None:
        live, rotated = "c1" + "b" * 30, "c2" + "d" * 30
        event = AuditEvent.objects.create(
            action="session_rotation",
            category="authentication",
            severity="low",
            description="rotated the session",
            metadata={
                "session_id": [live],
                "rotation": {"previous_session_keys": [rotated]},
                "elsewhere": f"seen {live} earlier",
            },
        )
        stored = AuditEvent.objects.get(pk=event.pk)
        self.assertNotIn(live, _all_text(stored))
        self.assertNotIn(rotated, _all_text(stored))
        self.assertEqual(stored.metadata["session_id"], [session_key_digest(live)])
        self.assertEqual(stored.metadata["rotation"]["previous_session_keys"], [session_key_digest(rotated)])
        self.assertIn(session_key_digest(live), stored.metadata["elsewhere"])

    def test_a_tuple_of_session_keys_is_digested_like_a_list(self) -> None:
        live = "t1" + "e" * 30
        event = AuditEvent.objects.create(
            action="session_rotation",
            category="authentication",
            severity="low",
            description="rotated the session",
            metadata={"session_ids": (live,)},
        )
        stored = AuditEvent.objects.get(pk=event.pk)
        self.assertNotIn(live, _all_text(stored))
        self.assertEqual(stored.metadata["session_ids"], [session_key_digest(live)])


class SessionKeyInvariantTests(SessionKeysNeverStoredTests):
    """A live key hidden in any supported shape never survives into a row, the SIEM or an export.

    Shapes are drawn with fixed seeds, so a failure reproduces exactly: a value or list item under a
    session-named key (singular or plural), a tuple, a mapping keyed by the live key, a labelled key
    in free text, and a key that is known from the event's own session_key and reused as a mapping
    key elsewhere. Each is wrapped in random neutral dicts and lists to vary the depth.
    """

    _ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"

    def _shape(self, rng: Any, live: str) -> dict[str, Any]:
        kind = rng.randrange(7)
        if kind == 0:
            payload: Any = {"session_ids": [live]}
        elif kind == 1:
            payload = {"session_ids": (live,)}
        elif kind == 2:
            payload = {"session_ids": {live: True}}
        elif kind == 3:
            payload = {"previous_session_keys": [{"note": live}]}
        elif kind == 4:
            payload = {"note": f"resumed session_key={live}"}
        elif kind == 5:
            return {"description": f"Session ID: {live}", "metadata": {}}
        else:
            return {"session_key": live, "metadata": {"by_session": {live: {"seen": 1}}}}
        for _ in range(rng.randrange(4)):
            payload = {rng.choice(["outer", "ctx", "data"]): payload} if rng.random() < 0.5 else {"items": [payload]}
        return {"metadata": payload}

    def test_a_live_key_in_any_supported_shape_never_survives(self) -> None:
        for seed in range(42):
            rng = random.Random(seed)  # noqa: S311  # seeded shapes for a reproducible test, not secrets
            live = "".join(rng.choice(self._ALPHABET) for _ in range(32))
            self.seen_keys.add(live)
            fields = self._shape(rng, live)
            AuditEvent.objects.create(
                action="session_rotation",
                category="authentication",
                severity="low",
                description=fields.pop("description", "a session event"),
                **fields,
            )
        self._assert_no_raw_key_anywhere()
