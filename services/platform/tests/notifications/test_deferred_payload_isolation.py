"""Post-send payload preparation stays inside the optional logging boundary."""

from django.test import override_settings

from apps.notifications.models import EmailLog
from apps.notifications.signals import handle_anymail_post_send
from apps.users.models import User
from tests.common._deferred_audit_reads import DeferredAuditReadTestCase


@override_settings(DISABLE_AUDIT_SIGNALS=False)
class DeferredPostSendPayloadTests(DeferredAuditReadTestCase):
    def test_post_send_preserves_write_when_deferred_status_fetch_fails(self) -> None:
        user = User.objects.create_user(email="deferred-post-send@example.com", password="test")
        status = EmailLog.objects.create(to_addr=user.email, subject="Test")
        status = EmailLog.objects.defer("status").get(pk=status.pk)
        status.__dict__["message_id"] = "test-message"

        def trigger() -> None:
            user.first_name = "Persisted"
            user.save(update_fields=["first_name"])
            handle_anymail_post_send(sender=object(), message=None, status=status, esp_name="test")

        self.run_deferred_read(status, trigger)
        self.assertEqual(User.objects.get(pk=user.pk).first_name, "Persisted")
