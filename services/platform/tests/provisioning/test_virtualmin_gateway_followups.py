"""Regression tests for Virtualmin response honesty and retry policy."""

from __future__ import annotations

from unittest.mock import MagicMock

from django.test import SimpleTestCase

from apps.common.types import Err, Ok, Retriability
from apps.provisioning.virtualmin_gateway import (
    VirtualminGateway,
    VirtualminResponse,
    classify_virtualmin_application_error,
)
from apps.provisioning.virtualmin_validators import (
    VIRTUALMIN_ALLOWED_PROGRAMS,
    VIRTUALMIN_READ_ONLY_PROGRAMS,
    is_virtualmin_read_only_program,
)


def _response(data: dict, *, success: bool = False) -> VirtualminResponse:
    return VirtualminResponse(
        success=success,
        data=data,
        raw_response="",
        http_status=200,
        execution_time=0.01,
        program="list-templates",
        server_hostname="vm.example.com",
    )


class VirtualminApplicationFailurePolicyTests(SimpleTestCase):
    def test_rate_limit_rejection_is_retriable(self) -> None:
        response = _response({"error": "Rate limit exceeded, try again later"})

        self.assertEqual(classify_virtualmin_application_error(response), Retriability.RETRIABLE)

    def test_proven_validation_rejection_is_terminal(self) -> None:
        response = _response({"error": "Invalid domain name specified"})

        self.assertEqual(classify_virtualmin_application_error(response), Retriability.NOT_RETRIABLE)

    def test_unknown_application_failure_stays_unknown(self) -> None:
        response = _response({"error": "Operation failed"})

        self.assertEqual(classify_virtualmin_application_error(response), Retriability.UNKNOWN)


class VirtualminReadOnlyPolicyTests(SimpleTestCase):
    def test_known_query_is_read_only(self) -> None:
        self.assertTrue(is_virtualmin_read_only_program("list-domains"))

    def test_prefix_alone_never_makes_program_read_only(self) -> None:
        self.assertFalse(is_virtualmin_read_only_program("list-and-clean-cache"))

    def test_every_read_only_program_is_an_allowed_program(self) -> None:
        self.assertLessEqual(VIRTUALMIN_READ_ONLY_PROGRAMS, VIRTUALMIN_ALLOWED_PROGRAMS)


class VirtualminTemplateParsingTests(SimpleTestCase):
    def _gateway_with(self, result):
        gateway = MagicMock(spec=VirtualminGateway)
        gateway.call.return_value = result
        return gateway

    def test_name_only_table_preserves_multi_word_template_name(self) -> None:
        gateway = self._gateway_with(Ok(_response({"data": [{"name": "Premium Hosting"}]}, success=True)))

        result = VirtualminGateway.list_templates(gateway)

        self.assertTrue(result.is_ok())
        self.assertEqual(result.unwrap(), ["Premium Hosting"])

    def test_unrecognized_response_shape_is_error(self) -> None:
        gateway = self._gateway_with(Ok(_response({}, success=True)))

        result = VirtualminGateway.list_templates(gateway)

        self.assertTrue(result.is_err())
        self.assertIn("unrecognized", str(result.unwrap_err()).lower())

    def test_explicit_empty_template_collection_is_valid(self) -> None:
        gateway = self._gateway_with(Ok(_response({"templates": []}, success=True)))

        result = VirtualminGateway.list_templates(gateway)

        self.assertTrue(result.is_ok())
        self.assertEqual(result.unwrap(), [])

    def test_template_object_without_name_is_an_error(self) -> None:
        gateway = self._gateway_with(Ok(_response({"templates": [{"id": 7}]}, success=True)))

        result = VirtualminGateway.list_templates(gateway)

        self.assertTrue(result.is_err())
        self.assertIn("unrecognized", str(result.unwrap_err()).lower())

    def test_transport_retriability_is_preserved(self) -> None:
        gateway = self._gateway_with(Err("temporarily unavailable", retriability=Retriability.RETRIABLE))

        result = VirtualminGateway.list_templates(gateway)

        self.assertTrue(result.is_err())
        self.assertEqual(result.retriability, Retriability.RETRIABLE)
