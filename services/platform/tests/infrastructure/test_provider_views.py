"""
Tests for provider create and edit views.

Verifies that provider management views correctly handle form submission,
token storage in the credential vault, and permission checks.
"""

from __future__ import annotations

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

import apps.common.credential_vault as vault_module
from apps.common.credential_vault import EncryptedCredential
from apps.infrastructure.models import CloudProvider

User = get_user_model()


class TestProviderCreateView(TestCase):
    """Tests for the provider_create view."""

    def setUp(self) -> None:
        # Reset vault singleton so it reinitializes with test settings key
        vault_module._vault_instance = None
        self.url = reverse("infrastructure:provider_create")
        self.superuser = User.objects.create_superuser(
            email="admin@test.com",
            password="testpass123",
        )

    def test_get_renders_form(self) -> None:
        """GET returns 200 with the provider form."""
        self.client.force_login(self.superuser)
        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 200)
        self.assertIn("form", response.context)

    def test_post_creates_provider_without_token(self) -> None:
        """POST without api_token creates provider, no vault entry."""
        self.client.force_login(self.superuser)
        data = {
            "name": "New Provider",
            "provider_type": "hetzner",
            "code": "NEW",
            "is_active": True,
            "config": "{}",
        }
        response = self.client.post(self.url, data)

        self.assertEqual(response.status_code, 302)
        self.assertTrue(CloudProvider.objects.filter(name="New Provider").exists())
        self.assertEqual(EncryptedCredential.objects.count(), 0)

    def test_post_creates_provider_with_token_stores_in_vault(self) -> None:
        """POST with api_token creates provider and stores token in vault."""
        self.client.force_login(self.superuser)
        data = {
            "name": "Vault Provider",
            "provider_type": "hetzner",
            "code": "VLT",
            "is_active": True,
            "config": "{}",
            "api_token": "secret-api-token",
        }
        response = self.client.post(self.url, data)

        self.assertEqual(response.status_code, 302)
        provider = CloudProvider.objects.get(name="Vault Provider")
        self.assertTrue(provider.credential_identifier)
        self.assertTrue(
            EncryptedCredential.objects.filter(
                service_type="cloud_provider",
                service_identifier=provider.credential_identifier,
            ).exists()
        )

    def test_requires_login(self) -> None:
        """Anonymous GET redirects to login."""
        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 302)
        self.assertIn("/login", response.url)


class TestProviderEditView(TestCase):
    """Tests for the provider_edit view."""

    def setUp(self) -> None:
        vault_module._vault_instance = None
        self.superuser = User.objects.create_superuser(
            email="admin@test.com",
            password="testpass123",
        )
        self.provider = CloudProvider.objects.create(
            name="Edit Provider",
            provider_type="hetzner",
            code="EDT",
            is_active=True,
        )
        self.url = reverse("infrastructure:provider_edit", args=[self.provider.pk])

    def test_get_renders_form_with_provider(self) -> None:
        """GET returns 200 with provider data in form."""
        self.client.force_login(self.superuser)
        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 200)
        self.assertIn("form", response.context)

    def test_post_updates_provider_without_touching_token(self) -> None:
        """POST without api_token updates provider but creates no vault entry."""
        self.client.force_login(self.superuser)
        data = {
            "name": "Renamed Provider",
            "provider_type": "hetzner",
            "code": "EDT",
            "is_active": True,
            "config": "{}",
        }
        response = self.client.post(self.url, data)

        self.assertEqual(response.status_code, 302)
        self.provider.refresh_from_db()
        self.assertEqual(self.provider.name, "Renamed Provider")
        self.assertEqual(EncryptedCredential.objects.count(), 0)

    def test_post_updates_token_in_vault(self) -> None:
        """POST with api_token stores a new token in the vault."""
        self.client.force_login(self.superuser)
        data = {
            "name": "Edit Provider",
            "provider_type": "hetzner",
            "code": "EDT",
            "is_active": True,
            "config": "{}",
            "api_token": "new-secret-token",
        }
        response = self.client.post(self.url, data)

        self.assertEqual(response.status_code, 302)
        self.provider.refresh_from_db()
        self.assertTrue(self.provider.credential_identifier)
        self.assertTrue(
            EncryptedCredential.objects.filter(
                service_type="cloud_provider",
            ).exists()
        )

    def test_404_for_nonexistent_provider(self) -> None:
        """GET with bad pk returns 404."""
        self.client.force_login(self.superuser)
        url = reverse("infrastructure:provider_edit", args=[99999])
        response = self.client.get(url)

        self.assertEqual(response.status_code, 404)

    def test_requires_login(self) -> None:
        """Anonymous GET redirects to login."""
        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 302)
        self.assertIn("/login", response.url)
