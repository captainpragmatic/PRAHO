"""User notification senders follow the stored company identity."""

from collections.abc import Callable

from django.core import mail
from django.core.cache import cache
from django.test import TestCase, override_settings

from apps.customers.models import Customer
from apps.settings.models import SystemSetting
from apps.settings.services import SettingsService
from apps.users.models import CustomerMembership, User
from apps.users.services import (
    SecureCustomerUserService,
    SecureUserRegistrationService,
    _render_and_send_welcome_email,
)


@override_settings(
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
    EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend",
    DEFAULT_FROM_EMAIL="deployment@example.test",
)
class UserEmailSenderTests(TestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        self.user = User.objects.create_user(email="member@example.test", password="Test-password-2099!")
        self.owner = User.objects.create_user(email="owner@example.test", password="Test-password-2099!")
        self.customer = Customer.objects.create(
            name="Sender test", company_name="Sender Test SRL", primary_email="customer@example.test"
        )
        CustomerMembership.objects.create(user=self.owner, customer=self.customer, role="owner")
        self.membership = CustomerMembership.objects.create(user=self.user, customer=self.customer, role="viewer")

    def assert_sender(self, send: Callable[[], object]) -> None:
        for stored, expected in (
            ("runtime@example.test", "runtime@example.test"),
            (None, "deployment@example.test"),
        ):
            with self.subTest(stored=stored):
                cache.clear()
                with self.captureOnCommitCallbacks(execute=True):
                    if stored is None:
                        SystemSetting.objects.filter(key="company.email_noreply").delete()
                    else:
                        result = SettingsService.update_setting("company.email_noreply", stored)
                        self.assertTrue(result.is_ok(), result)
                mail.outbox.clear()
                send()
                self.assertEqual(len(mail.outbox), 1)
                self.assertEqual(mail.outbox[0].from_email, expected)

    def test_welcome_sender_uses_runtime_identity(self) -> None:
        self.assert_sender(lambda: _render_and_send_welcome_email(self.user, self.customer))

    def test_registration_join_request_sender_uses_runtime_identity(self) -> None:
        self.assert_sender(
            lambda: SecureUserRegistrationService._notify_owners_of_join_request_secure(self.customer, self.user)
        )

    def test_customer_join_request_sender_uses_runtime_identity(self) -> None:
        self.assert_sender(
            lambda: SecureCustomerUserService._notify_owners_of_join_request_secure(self.customer, self.user)
        )

    def test_invitation_sender_uses_runtime_identity(self) -> None:
        self.assert_sender(lambda: SecureCustomerUserService._send_invitation_email_secure(self.membership, self.owner))
