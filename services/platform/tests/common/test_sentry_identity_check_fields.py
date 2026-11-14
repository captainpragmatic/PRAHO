"""An error report never carries what an identity check or a portal session sends.

The re-check endpoint receives a second-factor code as ``mfa_code``, and every signed portal body
names its Platform session as ``session_id``. Neither name is in Sentry's own denylist, so an error
raised while handling them would have sent both to the error tracker, nested or not. Sentry scrubs an
event, then serialises it (anything nested past its depth limit becomes text), then calls
``before_send``: the scrub must catch everything before serialisation, and leave the ``_meta``
annotations serialisation writes intact.
"""

from __future__ import annotations

import json
from typing import Any

from django.test import SimpleTestCase
from sentry_sdk import Client
from sentry_sdk.transport import Transport

from config.settings.sentry import sentry_options

CODE = "482913"
SESSION = "6f1c2a0e-8a5b-4d0c-9a77-0d4b3c2e1f00"


class _Captured(Transport):
    def __init__(self) -> None:
        super().__init__()
        self.envelopes: list[Any] = []

    def capture_envelope(self, envelope: Any) -> None:
        self.envelopes.append(envelope)


def _send(event: dict[str, Any]) -> bytes:
    """What the configured client would send for this event, through Sentry's whole pipeline."""
    transport = _Captured()
    client = Client(**sentry_options("https://key@sentry.example.test/1", release="1.0"), transport=transport)
    client.capture_event(event)
    return b"".join(item.get_bytes() for envelope in transport.envelopes for item in envelope.items)


class IdentityCheckFieldsTests(SimpleTestCase):
    def test_codes_and_session_ids_are_scrubbed_at_any_depth(self) -> None:
        scrubber = sentry_options("https://key@sentry.example.test/1", release="1.0")["event_scrubber"]
        event = {
            "request": {
                "data": {
                    "user_id": 42,
                    "mfa_code": CODE,
                    "session_id": SESSION,
                    "nested": {"portal_session_id": SESSION, "inner": {"mfa_code": CODE}},
                }
            },
            "extra": {"body": {"session_id": SESSION}},
        }
        scrubber.scrub_event(event)
        report = repr(event)
        self.assertNotIn(CODE, report)
        self.assertNotIn(SESSION, report)
        self.assertEqual(event["request"]["data"]["user_id"], 42)  # an ordinary field is kept

    def test_fields_inside_a_tuple_never_reach_the_sent_report(self) -> None:
        sent = _send({"message": "boom", "extra": {"payload": ({"mfa_code": CODE, "cnp": "1800101221144"},)}})
        self.assertIn(b"boom", sent)  # the report itself was sent
        self.assertNotIn(CODE.encode(), sent)
        self.assertNotIn(b"1800101221144", sent)

    def test_nothing_deeply_nested_in_a_tuple_reaches_the_sent_report(self) -> None:
        nested = {"a": {"b": {"c": {"mfa_code": CODE, "session_id": SESSION}}}}
        sent = _send({"message": "boom", "extra": {"payload": (nested,)}})
        self.assertIn(b"boom", sent)
        self.assertNotIn(CODE.encode(), sent)
        self.assertNotIn(SESSION.encode(), sent)

    def test_a_cycle_through_a_tuple_does_not_stop_the_scrubbing_after_it(self) -> None:
        holder: dict[str, Any] = {}
        loop = (holder,)
        holder["back"] = loop  # tuple -> dict -> the same tuple
        deep = ({"a": {"b": {"c": {"mfa_code": CODE, "session_id": SESSION}}}},)
        sent = _send({"message": "boom", "extra": {"a_cycle": loop, "z_payload": deep}})
        self.assertIn(b"boom", sent)
        self.assertNotIn(CODE.encode(), sent)
        self.assertNotIn(SESSION.encode(), sent)

    def test_sections_sentry_s_own_scrub_skips_are_scrubbed_too(self) -> None:
        sections = {
            "contexts": {"identity": {"mfa_code": CODE}},
            "tags": {"session_id": SESSION},
            "logentry": {"message": "check %s", "params": ({"cnp": "1800101221144"},)},
            "exception": {"values": [{"type": "E", "value": "x", "mechanism": {"data": {"mfa_code": CODE}}}]},
        }
        for section, content in sections.items():
            with self.subTest(section=section):
                sent = _send({"message": "boom", "tags": {"kept": "yes"}, section: content})
                self.assertIn(b"boom", sent)
                self.assertNotIn(CODE.encode(), sent)
                self.assertNotIn(SESSION.encode(), sent)
                self.assertNotIn(b"1800101221144", sent)
        self.assertIn(b'"kept":"yes"', _send({"message": "boom", "tags": {"kept": "yes"}}))  # ordinary tags stay

    def test_the_scrub_keeps_sentry_s_own_annotations_intact(self) -> None:
        sent = _send({"message": "boom", "request": {"data": {"password": "hunter2", "note": "kept"}}})
        self.assertNotIn(b"hunter2", sent)
        self.assertIn(b'"_meta"', sent)
        self.assertIn(b"!config", sent)  # the removal's annotation, not "[Filtered]" in its place

    def test_an_extra_sentry_scrubbed_keeps_its_annotation(self) -> None:
        sent = _send({"message": "boom", "extra": {"password": "hunter2", "note": "password=extra-secret"}})
        self.assertNotIn(b"hunter2", sent)
        self.assertNotIn(b"extra-secret", sent)  # free text in an extra is still redacted
        self.assertIn(b'"password":"[Filtered]"', sent)  # Sentry's own substitute, matching its annotation
        self.assertIn(b"!config", sent)

    def test_free_text_in_request_data_is_redacted(self) -> None:
        sent = _send({"message": "boom", "request": {"data": {"note": "password=request-secret"}}})
        self.assertIn(b"boom", sent)
        self.assertNotIn(b"request-secret", sent)

    def test_content_sentry_trims_is_still_redacted(self) -> None:
        extra = {"a_note": "password=trim-secret", **{f"field_{index:02}": index for index in range(12)}}
        sent = _send({"message": "boom", "extra": extra})
        self.assertIn(b'"len"', sent)  # Sentry trimmed the extras and annotated it
        self.assertNotIn(b"trim-secret", sent)

    def test_a_sensitive_parent_is_redacted_whole_though_sentry_annotated_its_child(self) -> None:
        sent = _send({"message": "boom", "extra": {"new_password1": {"password": "inner", "value": "outer-secret"}}})
        self.assertNotIn(b"outer-secret", sent)
        self.assertNotIn(b"inner", sent)

    def test_colliding_redacted_keys_are_all_kept(self) -> None:
        sent = _send({"message": "boom", "extra": {"password": "p", "password=one": 1, "password=two": 2}})
        event = json.loads(sent)
        self.assertEqual(len(event["extra"]), 3, event["extra"])
        self.assertNotIn(b"one", sent)
        self.assertNotIn(b"two", sent)

    def test_a_secret_in_a_key_never_returns_through_the_annotations(self) -> None:
        sent = _send({"message": "boom", "extra": {"password=key-secret": {"password": "hunter2"}}})
        self.assertIn(b'"_meta"', sent)
        self.assertNotIn(b"key-secret", sent)
        self.assertNotIn(b"hunter2", sent)
