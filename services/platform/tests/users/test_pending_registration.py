"""A pending registration is mailed, confirmed by its mailbox holder, or cleaned up."""

from datetime import timedelta
from unittest.mock import patch

from django.core import mail
from django.core.cache import cache
from django.test import TestCase, override_settings
from django.utils import timezone
from django_q.models import Schedule

from apps.audit.models import AuditEvent
from apps.common import counters
from apps.common.types import Err
from apps.customers.models import Customer
from apps.settings.models import SystemSetting
from apps.users import registration_confirmation
from apps.users.models import CustomerMembership, User
from apps.users.pending_registration import PendingRegistration
from apps.users.tasks import (
    cleanup_pending_registrations,
    deliver_registration,
    setup_user_security_scheduled_tasks,
)
from tests.helpers.hmac import HMAC_TEST_MIDDLEWARE, HMAC_TEST_SECRET, HMACTestMixin

PORTAL = "https://customers.example.test"
PASSWORD = " Chosen-at-confirm-2026! "


def pending_customer_data() -> dict[str, str]:
    return {
        "customer_type": "company",
        "company_name": "Quill Lantern SRL",
        "vat_number": "",
        "billing_address": "Str. Exemplu 1",
        "billing_city": "Cluj-Napoca",
        "billing_postal_code": "400001",
    }


def pending(email: str = "new@example.test", **overrides: object) -> PendingRegistration:
    fields = {
        "email": email,
        "user_data": {"first_name": "Zedrick", "last_name": "Marlowe", "phone": ""},
        "customer_data": pending_customer_data(),
        "language": "en",
        **overrides,
    }
    return PendingRegistration.objects.create(**fields)


class PortalOriginMixin:
    def setUp(self) -> None:
        cache.clear()
        SystemSetting.objects.update_or_create(
            key="portal.public_base_url",
            defaults={
                "name": "Portal URL",
                "category": "platform",
                "data_type": "string",
                "value": PORTAL,
                "default_value": "",
            },
        )


class DeliverRegistrationTests(PortalOriginMixin, TestCase):
    def test_a_new_address_gets_its_confirmation_link_and_no_submitted_text(self) -> None:
        row = pending()
        self.assertEqual(deliver_registration(str(row.pk)), {"sent": True, "kind": "confirm"})
        [message] = mail.outbox
        self.assertEqual(message.to, ["new@example.test"])
        self.assertEqual(message.subject, "Confirm your PRAHO account")
        self.assertIn(f"{PORTAL}/register/confirm/{row.pk}/{row.token()}/", message.body)
        self.assertIn(f'href="{PORTAL}/register/confirm/{row.pk}/{row.token()}/"', message.alternatives[0][0])
        for submitted in ("Zedrick", "Marlowe", "Quill Lantern"):
            self.assertNotIn(submitted, message.body)
            self.assertNotIn(submitted, message.alternatives[0][0])
        row.refresh_from_db()
        self.assertIsNotNone(row.sent_at)

    def test_an_existing_account_is_told_so_and_the_row_is_dropped(self) -> None:
        User.objects.create_user(email="Owner@Example.test", password="Existing-password-2026!")
        row = pending("owner@example.test")
        self.assertEqual(deliver_registration(str(row.pk)), {"sent": True, "kind": "existing_account"})
        [message] = mail.outbox
        self.assertEqual(message.subject, "You already have a PRAHO account")
        self.assertIn(f"{PORTAL}/login/", message.body)
        self.assertIn(f"{PORTAL}/password-reset/", message.body)
        self.assertNotIn("/register/confirm/", message.body)
        self.assertFalse(PendingRegistration.objects.filter(pk=row.pk).exists())

    def test_the_mail_is_in_the_submitted_language(self) -> None:
        row = pending(language="ro")
        deliver_registration(str(row.pk))
        self.assertEqual(mail.outbox[0].subject, "Confirmați contul dumneavoastră PRAHO")

    def test_one_mail_per_address_in_the_cooldown_whatever_it_would_say(self) -> None:
        User.objects.create_user(email="owner@example.test", password="Existing-password-2026!")
        for first, second in (("new@example.test", "NEW@example.test"), ("owner@example.test", "owner@example.test")):
            with self.subTest(address=first):
                mail.outbox.clear()
                one, two = pending(first), pending(second)
                self.assertTrue(deliver_registration(str(one.pk))["sent"])
                self.assertEqual(deliver_registration(str(two.pk)), {"sent": False, "reason": "cooldown"})
                self.assertEqual(len(mail.outbox), 1)

    def test_a_late_request_a_resend_and_a_missing_row_send_nothing(self) -> None:
        late = pending()
        PendingRegistration.objects.filter(pk=late.pk).update(created_at=timezone.now() - timedelta(minutes=16))
        sent = pending("sent@example.test", sent_at=timezone.now())
        with self.assertLogs("apps.users.registration_confirmation", level="WARNING"):
            self.assertEqual(deliver_registration(str(late.pk)), {"sent": False, "reason": "stale"})
        self.assertEqual(deliver_registration(str(sent.pk)), {"sent": False, "reason": "already_sent"})
        self.assertEqual(
            deliver_registration("00000000-0000-0000-0000-000000000000"), {"sent": False, "reason": "missing"}
        )
        self.assertEqual(len(mail.outbox), 0)

    def test_failures_are_returned_never_raised_and_leave_the_row_unsent(self) -> None:
        row = pending()
        with (
            patch("apps.users.registration_confirmation.send_mail", side_effect=OSError("SMTP down")),
            self.assertLogs("apps.users.tasks", level="ERROR") as diagnostics,
        ):
            self.assertEqual(deliver_registration(str(row.pk)), {"sent": False, "reason": "error"})
        self.assertTrue(any("OSError" in entry and "SMTP down" in entry for entry in diagnostics.output))
        row.refresh_from_db()
        self.assertIsNone(row.sent_at)

    def test_a_backend_that_accepts_nothing_leaves_the_row_unsent(self) -> None:
        row = pending()
        with (
            patch("apps.users.registration_confirmation.send_mail", return_value=0),
            self.assertLogs("apps.users.tasks", level="ERROR"),
        ):
            self.assertEqual(deliver_registration(str(row.pk)), {"sent": False, "reason": "error"})
        row.refresh_from_db()
        self.assertIsNone(row.sent_at)

    def test_the_row_is_marked_sent_before_the_link_leaves(self) -> None:
        row = pending()
        seen = []

        def record_then_send(**kwargs: object) -> int:
            seen.append(PendingRegistration.objects.get(pk=row.pk).sent_at)
            return 1

        with patch("apps.users.registration_confirmation.send_mail", side_effect=record_then_send):
            self.assertTrue(deliver_registration(str(row.pk))["sent"])
        self.assertIsNotNone(seen[0])

    def test_an_address_gets_a_few_registration_mails_a_day_at_most(self) -> None:
        recipient = registration_confirmation._recipient_key("new@example.test")
        results = []
        for _ in range(registration_confirmation.RECIPIENT_DAILY_LIMIT + 1):
            counters.reset(f"registration_mail:{recipient}")  # as if the 10-minute cooldown had passed
            results.append(deliver_registration(str(pending().pk)))
        self.assertEqual(results[-1], {"sent": False, "reason": "daily_limit"})
        self.assertEqual(len(mail.outbox), registration_confirmation.RECIPIENT_DAILY_LIMIT)

    def test_a_broken_portal_origin_sends_nothing(self) -> None:
        SystemSetting.objects.filter(key="portal.public_base_url").update(value="http://customers.example.test")
        cache.clear()
        row = pending()
        with self.assertLogs("apps.users.registration_confirmation", level="ERROR"):
            self.assertEqual(deliver_registration(str(row.pk)), {"sent": False, "reason": "configuration"})
        self.assertEqual(len(mail.outbox), 0)


class ConfirmRegistrationTests(PortalOriginMixin, TestCase):
    def sent(self, email: str = "new@example.test", **overrides: object) -> PendingRegistration:
        return pending(email, **{"sent_at": timezone.now(), **overrides})

    def confirm(self, row: PendingRegistration, token: str | None = None, password: str = PASSWORD):
        return registration_confirmation.confirm(
            str(row.pk),
            row.token() if token is None else token,
            password,
            accepts_marketing=True,
            data_processing_consent=True,
        )

    def test_the_confirmer_chooses_the_password_and_the_link_works_once(self) -> None:
        row = self.sent()
        result = self.confirm(row)
        self.assertTrue(result.is_ok(), result)
        user, customer = result.unwrap()
        user.refresh_from_db()
        self.assertTrue(user.is_active)
        self.assertTrue(user.check_password(PASSWORD))
        self.assertTrue(user.accepts_marketing)
        self.assertIsNotNone(user.gdpr_consent_date)
        self.assertEqual(customer.company_name, "Quill Lantern SRL")
        self.assertTrue(CustomerMembership.objects.filter(user=user, customer=customer, role="owner").exists())
        row.refresh_from_db()
        self.assertIsNotNone(row.consumed_at)
        again = self.confirm(row)
        self.assertEqual(again.unwrap_err().code, "invalid_link")
        self.assertEqual(User.objects.filter(email="new@example.test").count(), 1)

    def test_wrong_unsent_and_expired_links_are_refused(self) -> None:
        cases = {
            "wrong token": (self.sent("a@example.test"), "0" * 64),
            "never sent": (pending("b@example.test"), None),
            "expired": (self.sent("c@example.test", sent_at=timezone.now() - timedelta(hours=24, seconds=1)), None),
        }
        for name, (row, token) in cases.items():
            with self.subTest(name):
                self.assertEqual(self.confirm(row, token).unwrap_err().code, "invalid_link")
        self.assertFalse(User.objects.filter(email__in=["a@example.test", "b@example.test", "c@example.test"]).exists())

    def test_a_rejected_password_leaves_the_link_usable(self) -> None:
        row = self.sent()
        refused = self.confirm(row, password="new@example.test")
        self.assertEqual(refused.unwrap_err().code, "password_rejected")
        self.assertTrue(refused.unwrap_err().messages)
        row.refresh_from_db()
        self.assertTrue(row.is_usable())
        self.assertTrue(self.confirm(row).is_ok())

    def test_details_taken_since_the_request_are_refused(self) -> None:
        own_company = {**pending_customer_data(), "company_name": "Unrelated Ferry SRL"}
        email_row = self.sent("taken@example.test", customer_data=own_company)
        company_row = self.sent("other@example.test")
        User.objects.create_user(email="TAKEN@example.test", password="Existing-password-2026!")
        Customer.objects.create(
            name="Quill",
            company_name="quill lantern srl",
            customer_type="company",
            primary_email="x@example.test",
            status="active",
        )
        for row in (email_row, company_row):
            with self.subTest(row.email):
                self.assertEqual(self.confirm(row).unwrap_err().code, "details_unavailable")
        self.assertFalse(User.objects.filter(email="other@example.test").exists())
        self.assertFalse(Customer.objects.filter(company_name="Unrelated Ferry SRL").exists())

    def test_consent_is_required_and_recorded_as_given(self) -> None:
        row = self.sent()
        refused = registration_confirmation.confirm(
            str(row.pk), row.token(), PASSWORD, accepts_marketing=True, data_processing_consent=False
        )
        self.assertEqual(refused.unwrap_err().code, "consent_required")
        row.refresh_from_db()
        self.assertTrue(row.is_usable())
        user, customer = registration_confirmation.confirm(
            str(row.pk), row.token(), PASSWORD, accepts_marketing=False, data_processing_consent=True
        ).unwrap()
        user.refresh_from_db()
        customer.refresh_from_db()
        self.assertFalse(user.accepts_marketing)
        self.assertFalse(customer.marketing_consent)
        self.assertTrue(customer.data_processing_consent)

    def test_an_account_that_cannot_be_created_now_keeps_the_link(self) -> None:
        row = self.sent()
        with patch(
            "apps.users.services.SecureUserRegistrationService.create_customer_owner_unchecked",
            return_value=Err("database busy"),
        ):
            self.assertEqual(self.confirm(row).unwrap_err().code, "unavailable")
        row.refresh_from_db()
        self.assertIsNone(row.consumed_at)
        self.assertTrue(self.confirm(row).is_ok())

    def test_a_failure_part_way_through_creating_the_account_leaves_nothing_and_keeps_the_link(self) -> None:
        row = self.sent()
        with patch(
            "apps.users.services.CustomerAddress.objects.create", side_effect=RuntimeError("address store down")
        ):
            self.assertEqual(self.confirm(row).unwrap_err().code, "unavailable")
        self.assertFalse(User.objects.filter(email="new@example.test").exists())
        self.assertFalse(Customer.objects.filter(company_name="Quill Lantern SRL").exists())
        row.refresh_from_db()
        self.assertTrue(row.is_usable())
        # Discarding the partial user and customer must not discard the record of the failure.
        self.assertTrue(AuditEvent.objects.filter(action="registration_system_error").exists())
        self.assertTrue(self.confirm(row).is_ok())

    def test_confirming_does_not_spend_the_registration_budget(self) -> None:
        row = self.sent()
        before = counters.peek("rate_limit:registration:203.0.113.7"), counters.peek("rate_limit:registration:")
        result = registration_confirmation.confirm(
            str(row.pk),
            row.token(),
            PASSWORD,
            accepts_marketing=False,
            data_processing_consent=True,
            request_ip="203.0.113.7",
        )
        self.assertTrue(result.is_ok(), result)
        after = counters.peek("rate_limit:registration:203.0.113.7"), counters.peek("rate_limit:registration:")
        self.assertEqual(before, after)

    def test_the_token_survives_a_reload_and_binds_to_its_row(self) -> None:
        row, other = self.sent(), self.sent("other@example.test")
        self.assertEqual(PendingRegistration.objects.get(pk=row.pk).token(), row.token())
        self.assertNotEqual(row.token(), other.token())
        self.assertEqual(self.confirm(row, other.token()).unwrap_err().code, "invalid_link")


class CleanupPendingRegistrationTests(TestCase):
    def test_only_finished_and_expired_rows_are_deleted(self) -> None:
        now = timezone.now()
        keep = [
            pending("fresh@example.test"),
            pending("recent@example.test", sent_at=now - timedelta(hours=24)),
            pending("waiting@example.test"),
        ]
        drop = [
            pending("used@example.test", sent_at=now, consumed_at=now),
            pending("expired@example.test", sent_at=now - timedelta(hours=25, seconds=1)),
            pending("unsent@example.test"),
        ]
        # Unsent rows can only be sent within 15 minutes; cleanup waits a further hour.
        PendingRegistration.objects.filter(pk=keep[2].pk).update(created_at=now - timedelta(minutes=74))
        PendingRegistration.objects.filter(pk=drop[2].pk).update(created_at=now - timedelta(minutes=76))
        self.assertEqual(cleanup_pending_registrations(), {"deleted": 3})
        self.assertEqual(set(PendingRegistration.objects.values_list("pk", flat=True)), {row.pk for row in keep})

    def test_cleanup_is_scheduled_hourly(self) -> None:
        setup_user_security_scheduled_tasks()
        scheduled = Schedule.objects.get(name="user-pending-registration-cleanup")
        self.assertEqual(
            (scheduled.func, scheduled.schedule_type),
            ("apps.users.tasks.cleanup_pending_registrations", Schedule.HOURLY),
        )


@override_settings(
    PLATFORM_API_SECRET=HMAC_TEST_SECRET,
    MIDDLEWARE=HMAC_TEST_MIDDLEWARE,
    HMAC_ALLOW_LEGACY_SECRET=True,
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
)
class RegistrationConfirmAPITests(HMACTestMixin, TestCase):
    path = "/api/users/register/confirm/"

    def setUp(self) -> None:
        cache.clear()
        self.row = pending(sent_at=timezone.now())

    def body(self, **overrides: object) -> dict[str, object]:
        return {
            "registration_id": str(self.row.pk),
            "token": self.row.token(),
            "password": PASSWORD,
            "password_confirm": PASSWORD,
            "data_processing_consent": True,
            "marketing_consent": False,
            **overrides,
        }

    def test_a_signed_confirmation_creates_the_account(self) -> None:
        response = self.portal_post(self.path, self.body())
        self.assertEqual(response.status_code, 201, response.content)
        self.assertEqual(response.json(), {"success": True, "email": "new@example.test"})
        user = User.objects.get(email="new@example.test")
        self.assertTrue(user.check_password(PASSWORD))
        self.assertFalse(user.accepts_marketing)
        self.assertFalse(Customer.objects.get(company_name="Quill Lantern SRL").marketing_consent)

    def test_marketing_consent_is_passed_through(self) -> None:
        self.assertEqual(self.portal_post(self.path, self.body(marketing_consent=True)).status_code, 201)
        self.assertTrue(User.objects.get(email="new@example.test").accepts_marketing)

    def test_an_unexpected_failure_answers_503_and_keeps_the_link(self) -> None:
        with (
            patch("apps.users.registration_confirmation.confirm", side_effect=RuntimeError("boom")),
            self.assertLogs("apps.api.users.views", level="ERROR"),
        ):
            response = self.portal_post(self.path, self.body())
        self.assertEqual((response.status_code, response.json()["code"]), (503, "unavailable"))
        self.row.refresh_from_db()
        self.assertTrue(self.row.is_usable())

    def test_refusals_have_their_own_codes(self) -> None:
        cases = [
            ({"token": "0" * 64}, 400, "invalid_link"),
            ({"password_confirm": "Something-else-2026!"}, 400, "validation_failed"),
            ({"data_processing_consent": False}, 400, "validation_failed"),
            ({"password": "new@example.test12", "password_confirm": "new@example.test12"}, 400, "validation_failed"),
        ]
        for overrides, status, code in cases:
            with self.subTest(overrides=overrides):
                response = self.portal_post(self.path, self.body(**overrides))
                self.assertEqual((response.status_code, response.json()["code"]), (status, code), response.content)
        User.objects.create_user(email="new@example.test", password="Existing-password-2026!")
        response = self.portal_post(self.path, self.body())
        self.assertEqual((response.status_code, response.json()["code"]), (409, "details_unavailable"))

    def test_a_valid_link_shows_what_it_would_create(self) -> None:
        response = self.portal_post(
            "/api/users/register/pending/", {"registration_id": str(self.row.pk), "token": self.row.token()}
        )
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(
            response.json()["registration"],
            {
                "email": "new@example.test",
                "first_name": "Zedrick",
                "last_name": "Marlowe",
                "company_name": "Quill Lantern SRL",
                "vat_number": "",
            },
        )
        self.assertIsNone(PendingRegistration.objects.get(pk=self.row.pk).consumed_at)

    def test_a_bad_used_or_expired_link_shows_nothing(self) -> None:
        used = pending("used@example.test", sent_at=timezone.now(), consumed_at=timezone.now())
        expired = pending("old@example.test", sent_at=timezone.now() - timedelta(hours=24, seconds=1))
        for registration_id, token in (
            (str(self.row.pk), "0" * 64),
            (str(used.pk), used.token()),
            (str(expired.pk), expired.token()),
            ("not-a-uuid", self.row.token()),
        ):
            with self.subTest(registration_id=registration_id):
                response = self.portal_post(
                    "/api/users/register/pending/", {"registration_id": registration_id, "token": token}
                )
                self.assertEqual(response.status_code, 400)
                self.assertEqual(response.json()["code"], "invalid_link")
                self.assertNotIn("registration", response.json())

    def test_an_unsigned_request_is_refused(self) -> None:
        response = self.client.post(self.path, self.body(), content_type="application/json")
        self.assertIn(response.status_code, (401, 403))
        self.assertFalse(User.objects.filter(email="new@example.test").exists())
