"""Exercise the installed provider SDK HTTP pipelines without opening network connections."""

import json
from io import BytesIO
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

import requests
from django.test import SimpleTestCase
from urllib3.response import HTTPResponse

from apps.infrastructure.digitalocean_service import DigitalOceanService
from apps.infrastructure.hcloud_service import HcloudService
from apps.infrastructure.vultr_service import VultrService


def reply(status, payload):
    response = requests.Response()
    response.status_code = status
    response._content = json.dumps(payload).encode() if payload is not None else b""
    response.raw = HTTPResponse(body=BytesIO(response._content), status=status, preload_content=False)
    response.headers["Content-Type"] = "application/json"
    response.url = "https://provider.example.test/resource"
    return response


class SDKResourceTransportTests(SimpleTestCase):
    @patch("requests.Session.request")
    def test_hcloud_locked_primary_ip_delete_keeps_sdk_error_code(self, http):
        http.side_effect = [
            reply(423, {"error": {"code": "locked", "message": "Primary IP is locked", "details": {}}}),
            reply(
                200,
                {
                    "primary_ip": {
                        "id": 7,
                        "type": "ipv4",
                        "ip": "192.0.2.7",
                        "assignee_type": "server",
                        "assignee_id": None,
                        "auto_delete": True,
                    }
                },
            ),
        ]
        result = HcloudService(token="fixture-token").resource_client().delete_exact("primary_ip", "7")
        self.assertTrue(result.is_err(), result)
        self.assertIn("APIException (locked)", result.unwrap_err())
        self.assertEqual(
            [(call.kwargs["method"], urlsplit(call.kwargs["url"]).path) for call in http.call_args_list],
            [("DELETE", "/v1/primary_ips/7"), ("GET", "/v1/primary_ips/7")],
        )

    @patch("requests.Session.request")
    def test_hcloud_uses_its_authenticated_sdk_and_native_structured_absence(self, http):
        http.side_effect = [
            reply(200, {"image": {"id": 123, "type": "snapshot", "status": "available"}}),
            reply(404, {"error": {"code": "not_found", "message": "gone"}}),
        ]
        client = HcloudService(token="fixture-token").resource_client()
        self.assertEqual(client.read_exact("snapshot", "123")["type"], "snapshot")
        first = http.call_args.kwargs
        self.assertEqual(first["url"], "https://api.hetzner.cloud/v1/images/123")
        self.assertEqual(
            {key.lower(): value for key, value in first["headers"].items()}["authorization"], "Bearer fixture-token"
        )
        self.assertIsNone(client.read_exact("snapshot", "123"))
        self.assertEqual(http.call_count, 2)

    @patch("requests.Session.request")
    def test_pydo_raw_request_preserves_authentication_and_pagination_parameters(self, http):
        http.return_value = reply(
            200,
            {
                "snapshots": [{"id": "91", "resource_type": "droplet", "resource_id": "43"}],
                "links": {},
                "meta": {"total": 1},
            },
        )
        resources = DigitalOceanService(token="fixture-token").resource_client().list_collection("snapshots")
        self.assertEqual(resources[0].source_ids, ("43",))
        call = http.call_args
        url = urlsplit(call.kwargs.get("url") or call.args[1])
        self.assertEqual((url.netloc, url.path), ("api.digitalocean.com", "/v2/snapshots"))
        self.assertEqual(parse_qs(url.query), {"per_page": ["100"], "page": ["1"]})
        self.assertEqual(
            {key.lower(): value for key, value in call.kwargs["headers"].items()}["authorization"], "Bearer fixture-token"
        )

    @patch("requests.Session.request")
    def test_pydo_delete_receipt_is_followed_by_exact_snapshot_absence(self, http):
        http.side_effect = [reply(204, None), reply(404, {"id": "not_found", "message": "gone"})]
        result = DigitalOceanService(token="fixture-token").resource_client().delete_exact("snapshot", "91")
        self.assertTrue(result.is_ok(), result)
        self.assertEqual([call.kwargs.get("method") or call.args[0] for call in http.call_args_list], ["DELETE", "GET"])
        self.assertTrue(all(urlsplit(call.kwargs.get("url") or call.args[1]).path == "/v2/snapshots/91" for call in http.call_args_list))

    @patch("apps.infrastructure.vultr_service.safe_request")
    def test_vultr_preserves_native_status_and_supports_bare_volume_snapshot_objects(self, http):
        http.side_effect = [
            reply(200, {"id": "vs", "block_id": "volume", "state": "COMPLETE"}),
            reply(403, {"error": "not found: request 404"}),
        ]
        client = VultrService(token="fixture-token").resource_client()
        self.assertEqual(client.read_exact("volume_snapshot", "vs")["state"], "COMPLETE")
        self.assertEqual(http.call_args.args[:2], ("GET", "https://api.vultr.com/v2/blocks/snapshots/vs"))
        self.assertEqual(http.call_args.kwargs["headers"]["Authorization"], "Bearer fixture-token")
        with self.assertRaises(requests.HTTPError):
            client.read_exact("volume_snapshot", "vs")
