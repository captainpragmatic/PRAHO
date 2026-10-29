"""Provider catalog sync preserves operator-owned identity and encrypted credentials."""

from unittest import mock

from django.test import TestCase

from apps.common.credential_vault import EncryptedCredential
from apps.common.types import Err, Ok
from apps.infrastructure.cloud_gateway import LocationInfo, ServerTypeInfo
from apps.infrastructure.models import CloudProvider
from apps.infrastructure.provider_config import get_provider_token, store_provider_token
from apps.infrastructure.provider_sync import (
    sync_aws_provider,
    sync_digitalocean_provider,
    sync_hetzner_provider,
    sync_vultr_provider,
)


class ProviderCredentialPreservationTests(TestCase):
    """Catalog refreshes never replace operator-owned provider identity or secrets."""

    providers = (
        ("hetzner", "HET", sync_hetzner_provider, "apps.infrastructure.hcloud_service.get_hcloud_service"),
        ("digitalocean", "DGO", sync_digitalocean_provider, "apps.infrastructure.digitalocean_service.get_digitalocean_service"),
        ("vultr", "VUL", sync_vultr_provider, "apps.infrastructure.vultr_service.get_vultr_service"),
        ("aws", "AWS", sync_aws_provider, "apps.infrastructure.aws_service.get_aws_service"),
    )

    @staticmethod
    def _service(kind: str = "") -> mock.Mock:
        service = mock.Mock()
        service.get_locations.return_value = Ok([])
        service.get_server_types.return_value = Ok([])
        if kind == "hetzner":
            # A Hetzner catalogue with nothing orderable is refused, so offer one type in one location.
            service.get_locations.return_value = Ok([LocationInfo(name="fsn1")])
            service.get_server_types.return_value = Ok([ServerTypeInfo(name="cx23", locations=("fsn1",))])
        service.client.sizes.list.return_value = {"sizes": []}
        service._request.return_value.json.return_value = {"plans": []}
        return service

    def test_repeated_sync_preserves_encrypted_token_and_operator_identity(self) -> None:
        for kind, code, synchronize, factory in self.providers:
            with self.subTest(provider=kind):
                provider = CloudProvider.objects.create(
                    provider_type=kind, code=code, name=f"Operator {kind}",
                    is_active=False, config={"operator_option": "keep"},
                )
                fixture_token = f"fixture-{kind}-token"
                provider.credential_identifier = store_provider_token(provider, fixture_token).unwrap()
                provider.save(update_fields=["credential_identifier"])
                provider_id = provider.pk
                credential_count = EncryptedCredential.objects.count()
                credential = EncryptedCredential.objects.get(service_identifier=provider.credential_identifier)
                encrypted_before = bytes(credential.encrypted_password)
                self.assertTrue(encrypted_before.startswith(b"vault:v2:"))
                with mock.patch(factory, return_value=self._service(kind)):
                    self.assertTrue(synchronize(token=fixture_token).is_ok())
                    self.assertTrue(synchronize(token=fixture_token).is_ok())
                provider.refresh_from_db()
                credential.refresh_from_db()
                retrieved = get_provider_token(provider)
                self.assertTrue(retrieved.is_ok(), retrieved.unwrap_err() if retrieved.is_err() else "")
                self.assertEqual(retrieved.unwrap(), fixture_token)
                self.assertEqual(provider.credential_identifier, credential.service_identifier)
                self.assertEqual(CloudProvider.objects.get(provider_type=kind).pk, provider_id)
                self.assertEqual(CloudProvider.objects.filter(provider_type=kind).count(), 1)
                self.assertEqual(EncryptedCredential.objects.count(), credential_count)
                self.assertEqual(bytes(credential.encrypted_password), encrypted_before)
                self.assertEqual(provider.code, code)
                self.assertEqual(provider.name, f"Operator {kind}")
                self.assertFalse(provider.is_active)
                self.assertEqual(provider.config, {"operator_option": "keep"})

    def test_failed_catalog_request_preserves_the_stored_credential_link(self) -> None:
        for kind, code, synchronize, factory in self.providers:
            with self.subTest(provider=kind):
                provider = CloudProvider.objects.create(provider_type=kind, code=code, name=f"Operator {kind}")
                fixture_token = f"fixture-{kind}-token"
                provider.credential_identifier = store_provider_token(provider, fixture_token).unwrap()
                provider.save(update_fields=["credential_identifier"])
                service = self._service(kind)
                service.get_locations.return_value = Err("catalog unavailable")
                with mock.patch(factory, return_value=service):
                    result = synchronize(token=fixture_token)
                self.assertTrue(result.is_err())
                provider.refresh_from_db()
                retrieved = get_provider_token(provider)
                self.assertTrue(retrieved.is_ok(), retrieved.unwrap_err() if retrieved.is_err() else "")
                self.assertEqual(retrieved.unwrap(), fixture_token)
                self.assertEqual(provider.code, code)

    def test_existing_blank_reference_is_not_replaced_by_a_bootstrap_alias(self) -> None:
        for kind, code, synchronize, factory in self.providers:
            with self.subTest(provider=kind):
                provider = CloudProvider.objects.create(provider_type=kind, code=code, name=f"Operator {kind}")
                with mock.patch(factory, return_value=self._service(kind)):
                    self.assertTrue(synchronize(token="fixture-bootstrap-token").is_ok())
                provider.refresh_from_db()
                self.assertEqual(provider.credential_identifier, "")
        self.assertEqual(EncryptedCredential.objects.count(), 0)
