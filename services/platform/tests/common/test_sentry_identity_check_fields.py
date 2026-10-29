"""An error report never carries what an identity check or a portal session sends.

The re-check endpoint receives a second-factor code as ``mfa_code``, and every signed portal body
names its Platform session as ``session_id``. Neither name is in Sentry's own denylist, so an error
raised while handling them would have sent both to the error tracker, nested or not.
"""

from __future__ import annotations

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
