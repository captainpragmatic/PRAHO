"""Staff API-token management UI tests (ADR-0031 Gap 7)."""

from datetime import datetime, timedelta

from django.test import Client, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from apps.users.forms import APITokenCreateForm
from apps.users.models import APIToken, User


def _create_token(
    user: User,
    *,
    name: str,
    description: str = "",
    expires_at: datetime | None = None,
) -> tuple[APIToken, str]:
    raw_key = APIToken.generate_key()
    token = APIToken.objects.create(
        user=user,
        key_hash=APIToken.hash_key(raw_key),
        key_prefix=raw_key[:8],
        name=name,
        description=description,
        expires_at=expires_at,
    )
    return token, raw_key


class APITokenManagementAccessTests(TestCase):
    def setUp(self) -> None:
        self.url = reverse("settings:api_tokens")

    def test_unauthenticated_user_is_redirected_to_login(self) -> None:
        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 302)
        self.assertIn("/auth/login/", response.url)

    def test_non_staff_user_cannot_access_token_management(self) -> None:
        user = User.objects.create_user(email="customer@example.com", password="StrongPass123!")
        self.client.force_login(user)

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 302)
        self.assertNotEqual(response.url, self.url)

    def test_create_requires_csrf(self) -> None:
        user = User.objects.create_user(
            email="csrf-admin@example.com",
            password="StrongPass123!",
            staff_role="admin",
        )
        csrf_client = Client(enforce_csrf_checks=True)
        csrf_client.force_login(user)

        response = csrf_client.post(self.url, {"name": "no-csrf"})

        self.assertEqual(response.status_code, 403)
        self.assertFalse(APIToken.objects.filter(user=user).exists())

    def test_token_page_prevents_secret_caching(self) -> None:
        user = User.objects.create_user(
            email="cache-admin@example.com",
            password="StrongPass123!",
            staff_role="admin",
        )
        self.client.force_login(user)

        response = self.client.get(self.url)

        self.assertIn("no-store", response.headers["Cache-Control"])


class APITokenManagementFormTests(TestCase):
    @override_settings(API_TOKEN_DEFAULT_TTL_DAYS=0)
    def test_non_expiring_deployment_default_leaves_ttl_blank(self) -> None:
        form = APITokenCreateForm()

        self.assertIsNone(form["ttl_days"].value())


class APITokenManagementTests(TestCase):
    def setUp(self) -> None:
        self.user = User.objects.create_user(
            email="token-admin@example.com",
            password="StrongPass123!",
            staff_role="admin",
        )
        self.other_user = User.objects.create_user(
            email="other-admin@example.com",
            password="StrongPass123!",
            staff_role="admin",
        )
        self.client.force_login(self.user)
        self.url = reverse("settings:api_tokens")

    def test_list_contains_only_callers_active_tokens(self) -> None:
        own_token, _ = _create_token(
            self.user,
            name="deploy",
            description="Production deployment",
            expires_at=timezone.now() + timedelta(days=10),
        )
        expired_token, _ = _create_token(
            self.user,
            name="expired",
            expires_at=timezone.now() - timedelta(seconds=1),
        )
        other_token, _ = _create_token(self.other_user, name="other-user")

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "settings/api_tokens.html")
        self.assertEqual(list(response.context["tokens"]), [own_token])
        self.assertContains(response, "Production deployment")
        self.assertNotContains(response, other_token.key_prefix)
        self.assertNotContains(response, expired_token.key_prefix)

    def test_create_shows_raw_key_once_and_persists_metadata(self) -> None:
        response = self.client.post(
            self.url,
            {
                "name": "nightly-sync",
                "description": "Synchronizes customer data",
                "ttl_days": "30",
            },
        )

        self.assertEqual(response.status_code, 200)
        token = APIToken.objects.get(user=self.user)
        raw_key = response.context["new_raw_token"]
        self.assertEqual(len(raw_key), 40)
        self.assertEqual(token.key_hash, APIToken.hash_key(raw_key))
        self.assertEqual(token.name, "nightly-sync")
        self.assertEqual(token.description, "Synchronizes customer data")
        self.assertIsNotNone(token.expires_at)
        self.assertContains(response, raw_key)
        self.assertContains(response, "navigator.clipboard.writeText")
        self.assertIn("no-store", response.headers["Cache-Control"])

        follow_up = self.client.get(self.url)
        self.assertNotIn("new_raw_token", follow_up.context)
        self.assertNotContains(follow_up, raw_key)
        self.assertNotContains(follow_up, token.key_hash)

    @override_settings(API_TOKEN_MAX_ACTIVE_PER_USER=1)
    def test_create_enforces_shared_active_token_cap(self) -> None:
        _create_token(self.user, name="existing")

        response = self.client.post(
            self.url,
            {"name": "too-many", "description": "", "ttl_days": "30"},
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Maximum of 1 active tokens per user")
        self.assertEqual(APIToken.objects.filter(user=self.user).count(), 1)

    def test_create_rejects_oversized_description(self) -> None:
        response = self.client.post(
            self.url,
            {"name": "oversized", "description": "x" * 501, "ttl_days": "30"},
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Ensure this value has at most 500 characters")
        self.assertFalse(APIToken.objects.filter(user=self.user).exists())

    def test_revoke_deletes_only_callers_selected_token(self) -> None:
        own_token, _ = _create_token(self.user, name="own")
        other_token, _ = _create_token(self.other_user, name="other")

        response = self.client.post(reverse("settings:api_token_revoke", args=[own_token.pk]))

        self.assertRedirects(response, self.url)
        self.assertFalse(APIToken.objects.filter(pk=own_token.pk).exists())
        self.assertTrue(APIToken.objects.filter(pk=other_token.pk).exists())

    def test_revoke_cannot_delete_another_users_token(self) -> None:
        other_token, _ = _create_token(self.other_user, name="other")

        response = self.client.post(reverse("settings:api_token_revoke", args=[other_token.pk]))

        self.assertEqual(response.status_code, 404)
        self.assertTrue(APIToken.objects.filter(pk=other_token.pk).exists())

    def test_revoke_endpoint_rejects_get(self) -> None:
        token, _ = _create_token(self.user, name="own")

        response = self.client.get(reverse("settings:api_token_revoke", args=[token.pk]))

        self.assertEqual(response.status_code, 405)
        self.assertTrue(APIToken.objects.filter(pk=token.pk).exists())
