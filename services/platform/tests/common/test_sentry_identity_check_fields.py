"""An error report never carries what an identity check or a portal session sends.

The re-check endpoint receives a second-factor code as ``mfa_code``, and every signed portal body
names its Platform session as ``session_id``. Neither name is in Sentry's own denylist, so an error
raised while handling them would have sent both to the error tracker, nested or not.
"""

from __future__ import annotations

from typing import Any

from django.test import SimpleTestCase

from config.settings.sentry import sentry_options

CODE = "482913"
SESSION = "6f1c2a0e-8a5b-4d0c-9a77-0d4b3c2e1f00"


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

    def test_fields_inside_tuples_are_scrubbed_before_sending(self) -> None:
        # Sentry's own scrubber walks dicts and lists, not tuples; the before_send callbacks cover them.
        options = sentry_options("https://key@sentry.example.test/1", release="1.0")
        for name in ("before_send", "before_send_transaction"):
            with self.subTest(callback=name):
                event = {"extra": {"payload": ({"mfa_code": CODE, "session_id": SESSION, "cnp": "1800101221144"},)}}
                sent = options[name](event, {})
                self.assertNotIn(CODE, repr(sent))
                self.assertNotIn(SESSION, repr(sent))
                self.assertNotIn("1800101221144", repr(sent))
                self.assertIsInstance(sent["extra"]["payload"], tuple)  # tuples stay tuples
                self.assertEqual(event["extra"]["payload"][0]["mfa_code"], CODE)  # the input is not changed

    def test_nothing_deeply_nested_in_a_tuple_reaches_the_sent_report(self) -> None:
        # The whole pipeline: Sentry scrubs, then serialises (deep values become text), then calls before_send.
        from sentry_sdk import Client  # noqa: PLC0415
        from sentry_sdk.transport import Transport  # noqa: PLC0415

        class Captured(Transport):
            def __init__(self) -> None:
                super().__init__()
                self.envelopes: list[Any] = []

            def capture_envelope(self, envelope: Any) -> None:
                self.envelopes.append(envelope)

        transport = Captured()
        client = Client(**sentry_options("https://key@sentry.example.test/1", release="1.0"), transport=transport)
        nested = {"a": {"b": {"c": {"mfa_code": CODE, "session_id": SESSION}}}}
        client.capture_event({"message": "boom", "extra": {"payload": (nested,)}})
        sent = b"".join(item.get_bytes() for envelope in transport.envelopes for item in envelope.items)
        self.assertIn(b"boom", sent)  # the report itself was sent
        self.assertNotIn(CODE.encode(), sent)
        self.assertNotIn(SESSION.encode(), sent)

    def test_a_cycle_through_a_tuple_does_not_stop_the_scrubbing_after_it(self) -> None:
        from sentry_sdk import Client  # noqa: PLC0415
        from sentry_sdk.transport import Transport  # noqa: PLC0415

        class Captured(Transport):
            def __init__(self) -> None:
                super().__init__()
                self.envelopes: list[Any] = []

            def capture_envelope(self, envelope: Any) -> None:
                self.envelopes.append(envelope)

        transport = Captured()
        client = Client(**sentry_options("https://key@sentry.example.test/1", release="1.0"), transport=transport)
        holder: dict[str, Any] = {}
        loop = (holder,)
        holder["back"] = loop  # tuple -> dict -> the same tuple
        deep = ({"a": {"b": {"c": {"mfa_code": CODE, "session_id": SESSION}}}},)
        client.capture_event({"message": "boom", "extra": {"a_cycle": loop, "z_payload": deep}})
        sent = b"".join(item.get_bytes() for envelope in transport.envelopes for item in envelope.items)
        self.assertIn(b"boom", sent)
        self.assertNotIn(CODE.encode(), sent)
        self.assertNotIn(SESSION.encode(), sent)
