"""Credential lifecycle payload failures preserve their triggering writes."""

from django.db.models.signals import post_save
from django.test import override_settings

from apps.users.mfa import WebAuthnCredential
from apps.users.models import APIToken, User
from tests.common._deferred_audit_reads import DeferredAuditReadTestCase


@override_settings(DISABLE_AUDIT_SIGNALS=False)
class DeferredCredentialPayloadTests(DeferredAuditReadTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.user = User.objects.create_user(email="deferred-credential@example.com", password="test")
        self.credential = WebAuthnCredential.objects.create(
            user=self.user, credential_id="credential", public_key="key", name="Before"
        )
        self.token = APIToken.objects.create(user=self.user, key_hash="1" * 64, key_prefix="12345678")

    def test_credential_update_commits_when_deferred_preview_fetch_fails(self) -> None:
        credential = WebAuthnCredential.objects.defer("credential_id").get(pk=self.credential.pk)
        credential.name = "Persisted"
        self.run_deferred_read(credential, lambda: credential.save(update_fields=["name"]))
        self.assertEqual(WebAuthnCredential.objects.get(pk=credential.pk).name, "Persisted")

    def test_credential_deletion_commits_when_deferred_preview_fetch_fails(self) -> None:
        credential = WebAuthnCredential.objects.defer("credential_id").get(pk=self.credential.pk)
        credential_id = credential.pk
        self.run_deferred_read(credential, credential.delete)
        self.assertFalse(WebAuthnCredential.objects.filter(pk=credential_id).exists())

    def test_token_creation_signal_preserves_write_when_deferred_expiry_fetch_fails(self) -> None:
        token = APIToken.objects.defer("expires_at").get(pk=self.token.pk)

        def trigger() -> None:
            self.user.first_name = "Persisted"
            self.user.save(update_fields=["first_name"])
            # Re-dispatch creation with a deferred instance to exercise the issuance payload.
            post_save.send(sender=APIToken, instance=token, created=True)

        self.run_deferred_read(token, trigger)
        self.assertEqual(User.objects.get(pk=self.user.pk).first_name, "Persisted")

    def test_token_deletion_commits_when_deferred_expiry_fetch_fails(self) -> None:
        token = APIToken.objects.defer("expires_at").get(pk=self.token.pk)
        token_id = token.pk
        self.run_deferred_read(token, token.delete)
        self.assertFalse(APIToken.objects.filter(pk=token_id).exists())
