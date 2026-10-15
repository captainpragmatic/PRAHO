"""The recorded Virtualmin answers replay through the production gateway and classify as the node did.

The contract suite recorded, for every case, what `has_explicit_success`, `explicit_rejection` and the
retriability classification said on the real answer. Replaying the answer through today's production code
must say the same: a change to the parser or the classifiers that would read a real answer differently fails
here, without a lab.
"""

from __future__ import annotations

from typing import Any

from django.test import TestCase

from apps.common.types import Retriability
from apps.provisioning.virtualmin_gateway import (
    classify_virtualmin_application_error,
    explicit_rejection,
    has_explicit_success,
    is_absent_domain_rejection,
)
from apps.provisioning.virtualmin_validators import VIRTUALMIN_ALLOWED_PROGRAMS, is_virtualmin_read_only_program
from tests.helpers.recorded_virtualmin import (
    FIXTURE_ROOT,
    RECORDED_ABSENT_DOMAIN,
    RecordedVirtualminGateway,
    latest_version,
    load_cases,
    recorded_response,
)


class RecordedReplayTests(TestCase):
    def test_every_allowlisted_program_has_a_recording(self) -> None:
        recorded = {path.stem for path in (FIXTURE_ROOT / latest_version()).glob("*.json")}
        self.assertEqual(recorded, set(VIRTUALMIN_ALLOWED_PROGRAMS))

    def test_every_recorded_case_classifies_today_as_it_did_on_the_node(self) -> None:
        checked = 0
        for program in sorted(VIRTUALMIN_ALLOWED_PROGRAMS):
            for case, recorded in load_cases(program).items():
                with self.subTest(program=program, case=case):
                    expected: dict[str, Any] = recorded["classification"]
                    response = recorded_response(program, case)
                    self.assertEqual(response.success, expected["success"])
                    self.assertEqual(has_explicit_success(response), expected["explicit_success"])
                    self.assertEqual(explicit_rejection(response.raw_response), expected["explicit_rejection"])
                    self.assertEqual(is_virtualmin_read_only_program(program), expected["read_only"])
                    if not expected["success"]:
                        self.assertEqual(classify_virtualmin_application_error(response).value, expected["retriability"])
                    checked += 1
        self.assertGreaterEqual(checked, len(VIRTUALMIN_ALLOWED_PROGRAMS))

    def test_a_refusal_is_a_200_failure_envelope_and_never_a_success(self) -> None:
        refusal = recorded_response("modify-domain", "unknown_parameter")
        self.assertEqual(refusal.http_status, 200)
        self.assertFalse(refusal.success)
        self.assertFalse(has_explicit_success(refusal))
        self.assertEqual(explicit_rejection(refusal.raw_response), "Unknown parameter --bandwidth")
        self.assertIs(classify_virtualmin_application_error(refusal), Retriability.UNKNOWN)

    def test_the_absent_domain_answer_is_the_one_that_proves_absence(self) -> None:
        absent = recorded_response("list-domains", "absent_domain")
        self.assertTrue(is_absent_domain_rejection(absent, RECORDED_ABSENT_DOMAIN))
        self.assertFalse(is_absent_domain_rejection(absent, "another.example.test"))


class RecordedGatewayTests(TestCase):
    def test_a_call_gets_the_recorded_case_through_the_production_call_path(self) -> None:
        gateway = RecordedVirtualminGateway({"list-domains": "name_only"})
        result = gateway.call("list-domains", {"name-only": ""})
        self.assertTrue(result.is_ok())
        self.assertEqual([row["name"] for row in result.unwrap().data["data"]], ["contract.praho.test"])
        self.assertEqual(gateway.sent, [("list-domains", {"name-only": ""})])

    def test_cases_are_used_in_order_and_the_last_repeats(self) -> None:
        gateway = RecordedVirtualminGateway({"disable-domain": ["success", "already_disabled"]})
        outcomes = [has_explicit_success(gateway.call("disable-domain", {"domain": "x.test"}).unwrap()) for _ in range(3)]
        self.assertEqual(outcomes, [True, False, False])

    def test_a_parameter_the_node_never_accepted_fails_the_test(self) -> None:
        gateway = RecordedVirtualminGateway()
        with self.assertRaisesRegex(AssertionError, r"never accepted \['format'\]"):
            gateway.call("list-domains", {"format": "json"})
        with self.assertRaisesRegex(AssertionError, r"never accepted \['bandwidth'\]"):
            gateway.call("modify-domain", {"domain": "x.test", "bandwidth": "0"})

    def test_the_parameters_production_sends_are_ones_the_node_accepted(self) -> None:
        gateway = RecordedVirtualminGateway({"list-domains": "one_domain"})
        self.assertTrue(gateway.call("modify-domain", {"domain": "x.test", "quota": "1", "bw": "0"}).is_ok())
        self.assertTrue(gateway.call("list-domains", {"domain": "x.test", "multiline": ""}).is_ok())
