"""Hetzner server types are usable only where a location lists them without a deprecation."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any
from unittest.mock import patch

from django.test import SimpleTestCase

from apps.infrastructure.hcloud_service import HcloudService
from tests.helpers.recorded_hcloud import CPX11, CPX22, CX11, CX23, RecordedHcloudTransport


class _HcloudTestCase(SimpleTestCase):
    def service(self, transport: Callable[..., dict[str, Any]]) -> HcloudService:
        """The real SDK client, with only its HTTP request method answered from recordings."""
        service = HcloudService(token="fixture-token")
        patcher = patch.object(service.client._client, "request", transport)
        patcher.start()
        self.addCleanup(patcher.stop)
        return service


class ServerTypeCatalogueTests(_HcloudTestCase):
    def test_type_retired_in_every_listed_location_is_not_available(self) -> None:
        transport = RecordedHcloudTransport([CX11])
        result = self.service(transport).get_server_types()
        self.assertTrue(result.is_ok(), result)
        (info,) = result.unwrap()
        self.assertEqual(info.name, "cx11")
        self.assertFalse(info.available)

    def test_reports_only_locations_without_a_deprecation(self) -> None:
        transport = RecordedHcloudTransport([CPX11, CX23, CPX22])
        result = self.service(transport).get_server_types()
        self.assertTrue(result.is_ok(), result)
        catalogue = {info.name: info for info in result.unwrap()}
        self.assertEqual(catalogue["cpx11"].locations, ("ash", "hil"))
        self.assertTrue(catalogue["cpx11"].available)
        self.assertEqual(catalogue["cx23"].locations, ("fsn1", "nbg1", "hel1"))
        self.assertEqual(catalogue["cpx22"].locations, ("fsn1", "nbg1", "hel1", "sin"))
        # Location names come from the listing itself; no location is fetched one by one.
        self.assertEqual([url for url, _ in transport.requests], ["/server_types"])

    def test_retired_everywhere_reports_no_locations(self) -> None:
        transport = RecordedHcloudTransport([CX11])
        (info,) = self.service(transport).get_server_types().unwrap()
        self.assertEqual(info.locations, ())


class ServerTypeOrderableTests(_HcloudTestCase):
    def test_type_retired_in_location_is_not_orderable(self) -> None:
        transport = RecordedHcloudTransport([CPX11])
        result = self.service(transport).server_type_orderable("cpx11", "hel1")
        self.assertEqual(result.unwrap(), False)
        self.assertEqual(transport.requests, [("/server_types", {"name": "cpx11"})])

    def test_type_sold_in_location_is_orderable(self) -> None:
        transport = RecordedHcloudTransport([CPX11, CX23])
        service = self.service(transport)
        self.assertEqual(service.server_type_orderable("cpx11", "ash").unwrap(), True)
        self.assertEqual(service.server_type_orderable("cx23", "hel1").unwrap(), True)

    def test_unlisted_location_and_unknown_type_are_not_orderable(self) -> None:
        transport = RecordedHcloudTransport([CX23])
        service = self.service(transport)
        self.assertEqual(service.server_type_orderable("cx23", "ash").unwrap(), False)
        self.assertEqual(service.server_type_orderable("cx99", "hel1").unwrap(), False)

    def test_api_failure_is_an_error_not_a_verdict(self) -> None:
        def failing(url: str, method: str, **kwargs: object) -> dict[str, Any]:
            raise ConnectionError("timed out")

        result = self.service(failing).server_type_orderable("cx23", "hel1")
        self.assertTrue(result.is_err())
        self.assertIn("timed out", result.unwrap_err())
