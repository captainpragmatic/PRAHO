"""An error report never carries what an identity check or a portal session sends.

The re-check endpoint receives a second-factor code as ``mfa_code``, and every signed portal body
names its Platform session as ``session_id``. Neither name is in Sentry's own denylist, so an error
raised while handling them would have sent both to the error tracker, nested or not. Sentry scrubs an
event, then serialises it (anything nested past its depth limit becomes text), then calls
``before_send``: the scrub must catch everything before serialisation, and leave the ``_meta``
annotations serialisation writes intact.
"""

from __future__ import annotations

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

    def test_the_scrub_keeps_sentry_s_own_annotations_intact(self) -> None:
        sent = _send({"message": "boom", "request": {"data": {"password": "hunter2", "note": "kept"}}})
        self.assertNotIn(b"hunter2", sent)
        self.assertIn(b'"_meta"', sent)
        self.assertIn(b"!config", sent)  # the removal's annotation, not "[Filtered]" in its place
