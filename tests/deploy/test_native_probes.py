"""Probe requests must satisfy the application's actual non-business request contract."""

import io
import json
from unittest.mock import patch

import pytest
from django.test import RequestFactory

from apps.api.secure_auth import validate_portal_service_request
from deploy.scripts import native_probe
from tests.native_role_helpers import failed_ansible_task


@pytest.mark.parametrize("failure", ["fatal: [platform]: FAILED!", "failed: [portal] (item=portal.native.test) =>"])
def test_failure_phase_parser_handles_real_ansible_loop_failures(failure: str) -> None:
    output = f"TASK [Verify trusted TLS] ********\n{failure} {{}}\nTASK [Reassert durable holds] ******\nok: [portal]\n"
    assert failed_ansible_task(output) == "Verify trusted TLS"


def test_non_json_maintenance_response_retains_its_status_without_logging_the_body() -> None:
    response = io.BytesIO(b"private-unexpected-response")
    response.status = 503
    with patch("deploy.scripts.native_probe.http.client.HTTPSConnection") as connection:
        connection.return_value.getresponse.return_value = response
        status, payload = native_probe.request("https://portal.example.test/order/payment/webhook/", {})
    assert status == 503 and payload is None


def test_api_probe_sends_the_timestamp_required_by_the_service_validator() -> None:
    requests = []

    class Connection:
        def __init__(self, *args: object, **kwargs: object) -> None:
            pass

        def request(self, method: str, path: str, *, body: bytes, headers: dict[str, str]) -> None:
            request = RequestFactory().generic(method, path, body, content_type="application/json")
            request._portal_authenticated = headers["X-Signature"] != "0" * 64
            requests.append(request)

        def getresponse(self):
            _, error = validate_portal_service_request(requests[-1])
            response = io.BytesIO(b'{"success":true}')
            response.status = error.status_code if error is not None else 200
            return response

        def close(self) -> None:
            pass

    with patch.dict(native_probe.os.environ, {"PLATFORM_API_BASE_URL": "https://staff.example.test/api",
                                             "PLATFORM_API_SECRET": "fixture", "NATIVE_PROBE_LOOPBACK": "false"}), patch(
        "deploy.scripts.native_probe.http.client.HTTPSConnection", Connection
    ):
        native_probe.probe_api()
    assert len(requests) == 2
    assert all(isinstance(json.loads(request.body)["timestamp"], int) for request in requests)
