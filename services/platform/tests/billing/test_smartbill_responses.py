"""What a SmartBill reply proves — the classification money-safety depends on.

Fixture provenance: shapes are taken from the published OpenAPI spec, EXCEPT
`test_the_real_authentication_failure_body`, which is a verbatim capture from the
live API using a deliberately invalid token. That capture is why this module does
not trust the spec: it carries four fields the schema never mentions.
"""

from __future__ import annotations

import json

from django.test import SimpleTestCase

from apps.billing.issuers.smartbill.responses import (
    RawReply,
    SmartBillResponse,
    Verdict,
    classify,
    first_sentence,
)


def _classify(
    status: int | None,
    body: str,
    *,
    retry_after: int | None = None,
    transport_failed: bool = False,
    is_write: bool = False,
) -> SmartBillResponse:
    try:
        parsed = json.loads(body) if body else None
    except json.JSONDecodeError:
        parsed = None
    if not isinstance(parsed, dict):
        parsed = None
    return classify(
        RawReply(
            status=status,
            body=body,
            parsed=parsed,
            retry_after=retry_after,
            transport_failed=transport_failed,
            is_write=is_write,
        )
    )


class VerdictTests(SimpleTestCase):
    def test_a_clean_issuance_is_success(self) -> None:
        body = json.dumps({"errorText": "", "number": "3593", "series": "FCT"})
        self.assertIs(_classify(200, body, is_write=True).verdict, Verdict.SUCCESS)

    def test_http_200_with_error_text_is_a_failure(self) -> None:
        """The rule that catches naive `if response.ok` code."""
        body = json.dumps({"errorText": "Seria nu a fost gasita!", "number": "", "documentId": -1})
        result = _classify(200, body)

        self.assertIs(result.verdict, Verdict.REJECTED)
        self.assertIn("Seria nu a fost gasita", result.error_text)

    def test_html_inside_error_text_is_cut_at_the_first_tag(self) -> None:
        """SmartBill appends markup aimed at its own UI; only the lead is the cause."""
        body = json.dumps(
            {
                "errorText": (
                    "Cantitate stoc insuficienta la <b>FCT 3593</b>."
                    '<div id="moreErrorDetails" style="display:none"><p>help</p></div>'
                )
            }
        )
        result = _classify(200, body)

        self.assertEqual(result.error_text, "Cantitate stoc insuficienta la")
        self.assertNotIn("<", result.error_text)

    def test_the_v3_error_envelope_yields_codes_and_params(self) -> None:
        body = json.dumps(
            {
                "status": 400,
                "type": "invalid_request_error",
                "errors": [{"code": "json_mapping_error", "message": "Unrecognized property: zzz.", "param": "zzz"}],
            }
        )
        result = _classify(400, body)

        self.assertIs(result.verdict, Verdict.REJECTED)
        self.assertIn("json_mapping_error", result.error_codes)
        self.assertIn("zzz", result.error_text)

    def test_a_rate_limit_is_rejected_not_ambiguous(self) -> None:
        """Refused before processing, so nothing was created and a retry is safe."""
        result = _classify(429, json.dumps({"errors": [{"code": "rate_limit_exceeded"}]}), retry_after=10)

        self.assertIs(result.verdict, Verdict.REJECTED)
        self.assertEqual(result.retry_after_seconds, 10)

    def test_an_html_500_is_ambiguous_even_though_the_spec_says_it_is_a_field_typo(self) -> None:
        """THE deliberate asymmetry.

        The spec says a misspelled field name returns 500 with an HTML body, which
        provably creates nothing. But that is indistinguishable from a genuine
        server error AFTER the document was written, and the two demand opposite
        handling. A wrong AMBIGUOUS costs a human a reconciliation; a wrong
        REJECTED costs a duplicate fiscal invoice that can never be deleted.
        """
        result = _classify(500, "<html><body>Internal Server Error</body></html>")

        self.assertIs(result.verdict, Verdict.AMBIGUOUS)

    def test_no_reply_at_all_is_ambiguous(self) -> None:
        result = _classify(None, "", transport_failed=True)
        self.assertIs(result.verdict, Verdict.AMBIGUOUS)

    def test_a_timeout_is_never_reported_as_rejected(self) -> None:
        """The single most expensive misclassification: it invites an automatic retry."""
        result = _classify(None, "", transport_failed=True)
        self.assertIsNot(result.verdict, Verdict.REJECTED)

    def test_the_real_authentication_failure_body(self) -> None:
        """Verbatim from the live API. Note the four fields the spec omits.

        `successfully`, `errorCode`, `key` and `documentNumber` appear in no schema
        in the published 9,132-line spec. This is the evidence for treating recorded
        responses as the contract.
        """
        body = json.dumps(
            {
                "key": "!.oresp@&",
                "successfully": False,
                "errorText": "Autentificare esuata. Va rugam verificati datele si incercati din nou.",
                "errorCode": "0",
                "message": "",
                "id": "",
                "documentNumber": "",
            }
        )
        result = _classify(401, body)

        self.assertIs(result.verdict, Verdict.REJECTED)
        self.assertIn("Autentificare esuata", result.error_text)

    def test_the_undocumented_success_flag_can_deny(self) -> None:
        """`successfully: false` with no errorText must still not read as success."""
        result = _classify(200, json.dumps({"errorText": "", "successfully": False, "message": "nope"}))
        self.assertIs(result.verdict, Verdict.REJECTED)

    def test_an_unknown_extra_field_does_not_break_a_success(self) -> None:
        """The spec is incomplete, so unknown fields must be tolerated, not fatal."""
        body = json.dumps({"errorText": "", "number": "1", "brandNewFieldSmartBillAddedTomorrow": {"a": 1}})
        self.assertIs(_classify(200, body).verdict, Verdict.SUCCESS)


class FirstSentenceTests(SimpleTestCase):
    def test_plain_text_is_unchanged(self) -> None:
        self.assertEqual(first_sentence("Seria nu a fost gasita!"), "Seria nu a fost gasita!")

    def test_empty_stays_empty(self) -> None:
        self.assertEqual(first_sentence(""), "")


class WriteSafetyTests(SimpleTestCase):
    """On a write, REJECTED is a licence to send the same POST again.

    SmartBill has no idempotency key, so a wrong REJECTED creates a second legally
    numbered invoice that can never be deleted — only reversed — and may already be
    in SPV. These cases each looked like a refusal but prove nothing about whether
    a document was created.
    """

    def test_an_unparseable_body_is_ambiguous_for_a_write(self) -> None:
        """A truncated or intermediary-mangled reply can hide a completed write."""
        result = _classify(200, "<html>gateway error</html>", is_write=True)
        self.assertIs(result.verdict, Verdict.AMBIGUOUS)

    def test_the_same_body_may_be_rejected_for_a_read(self) -> None:
        """Reads carry no duplication hazard, so they need not pay for the caution."""
        result = _classify(200, "<html>gateway error</html>", is_write=False)
        self.assertIs(result.verdict, Verdict.REJECTED)

    def test_a_200_with_no_number_is_not_a_success(self) -> None:
        """SUCCESS means "the document exists and we know its number"."""
        self.assertIs(_classify(200, json.dumps({}), is_write=True).verdict, Verdict.AMBIGUOUS)
        self.assertIs(
            _classify(200, json.dumps({"errorText": "", "number": ""}), is_write=True).verdict,
            Verdict.AMBIGUOUS,
        )

    def test_a_failure_shaped_but_unrecognised_envelope_is_ambiguous(self) -> None:
        """A bare list of strings is not the documented refusal envelope."""
        body = json.dumps({"errors": ["something went wrong"]})
        self.assertIs(_classify(200, body, is_write=True).verdict, Verdict.AMBIGUOUS)

    def test_a_contradictory_reply_never_authorises_a_replay(self) -> None:
        """errorText AND a document number: we cannot tell what happened."""
        body = json.dumps({"errorText": "Ceva nu a mers", "number": "3593"})
        result = _classify(200, body, is_write=True)

        self.assertIs(result.verdict, Verdict.AMBIGUOUS)
        self.assertIn("Contradictory", result.error_text)

    def test_the_undocumented_success_flag_denies_without_granting_retry(self) -> None:
        """`successfully: false` proves the call did not succeed.

        It does NOT prove nothing was created — it has only ever been observed on an
        authentication failure. Denying SUCCESS is not the same as proving REJECTED.
        """
        body = json.dumps({"errorText": "", "successfully": False, "message": "nope"})
        self.assertIs(_classify(200, body, is_write=True).verdict, Verdict.AMBIGUOUS)
        self.assertIs(_classify(200, body, is_write=False).verdict, Verdict.REJECTED)

    def test_a_recognised_business_refusal_is_still_retriable(self) -> None:
        """Caution must not swallow the ordinary case, or every typo needs a human."""
        body = json.dumps({"errorText": "Seria nu a fost gasita!", "number": ""})
        self.assertIs(_classify(200, body, is_write=True).verdict, Verdict.REJECTED)
