"""A registered node carries its public addresses, which account names point at (ADR-0061 P1.2).

Registration copies the deployment's IPv4 and IPv6 onto the server, normalised. An address that
is not public (a lab or private network) is left empty rather than failing the registration: DNS
for account names is never published to it. The staff form validates the same way.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from django.test import TestCase

from apps.common.types import Ok
from apps.infrastructure.registration_service import NodeRegistrationService
from apps.provisioning.virtualmin_forms import VirtualminServerForm


def _deployment(ipv4: str, ipv6: str) -> MagicMock:
    deployment = MagicMock()
    deployment.status = "registering"
    deployment.ipv4_address = ipv4
    deployment.ipv6_address = ipv6
    deployment.virtualmin_server = None
    deployment.hostname = "prd-sha-tst-de-tst1-001"
    deployment.fqdn = "prd-sha-tst-de-tst1-001.example.com"
    deployment.id = 1
    deployment.node_size.max_domains = 50
    deployment.node_size.max_bandwidth_gb = 1000
    return deployment


@patch("apps.provisioning.virtualmin_models.VirtualminServer")
@patch("apps.infrastructure.validation_service.get_validation_service")
class RegistrationAddressTests(TestCase):
    def _register(self, validation: MagicMock, model: MagicMock, ipv4: str, ipv6: str) -> dict[str, object]:
        validation.return_value.get_webmin_certificate_fingerprint.return_value = Ok("ab" * 32)
        model.objects.filter.return_value.exists.return_value = False
        model.objects.create.return_value = MagicMock(id=7)
        result = NodeRegistrationService().register_node(_deployment(ipv4, ipv6))
        self.assertTrue(result.is_ok(), result.unwrap_err() if result.is_err() else "")
        return dict(model.objects.create.call_args.kwargs)

    def test_public_addresses_are_stored_normalised(self, validation: MagicMock, model: MagicMock) -> None:
        created = self._register(validation, model, "95.217.0.10", "2a01:04F8:0000::0001")
        self.assertEqual((created["ipv4_address"], created["ipv6_address"]), ("95.217.0.10", "2a01:4f8::1"))

    def test_a_private_address_is_left_empty_and_registration_goes_on(
        self, validation: MagicMock, model: MagicMock
    ) -> None:
        created = self._register(validation, model, "10.20.0.5", "")
        self.assertEqual((created["ipv4_address"], created["ipv6_address"]), (None, None))


class ServerFormAddressTests(TestCase):
    def _form(self, **addresses: str) -> VirtualminServerForm:
        data = {
            "name": "Primary",
            "hostname": "node1.example.com",
            "api_port": "10000",
            "api_username": "praho",
            "use_ssl": "on",
            "status": "active",
            "max_domains": "100",
            "max_disk_gb": "1000",
            "max_bandwidth_gb": "5000",
            **addresses,
        }
        return VirtualminServerForm(data=data)

    def test_the_form_accepts_and_normalises_public_addresses(self) -> None:
        form = self._form(ipv4_address="95.217.0.20", ipv6_address="2A01:4F8::0001")
        form.is_valid()
        self.assertNotIn("ipv4_address", form.errors)
        self.assertNotIn("ipv6_address", form.errors)
        self.assertEqual(form.cleaned_data["ipv6_address"], "2a01:4f8::1")

    def test_the_form_refuses_a_private_or_wrong_family_address(self) -> None:
        for field, value in (
            ("ipv4_address", "192.168.1.10"),
            ("ipv4_address", "127.0.0.1"),
            ("ipv6_address", "fd00::1"),
            ("ipv6_address", "95.217.0.20"),
        ):
            with self.subTest(field=field, value=value):
                form = self._form(**{field: value})
                form.is_valid()
                self.assertIn(field, form.errors)

    def test_the_addresses_are_optional(self) -> None:
        form = self._form()
        form.is_valid()
        self.assertNotIn("ipv4_address", form.errors)
        self.assertNotIn("ipv6_address", form.errors)
