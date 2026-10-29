"""Changes to a company's team, contact details and legal identity, and data exports, are told by email.

A stolen session acts as the person it belongs to, so a notice goes where the rightful person
reads it: every owner of the company (the one who made the change included), the member a role
change or removal touched, the old contact address when the contact email changed, and the person
who asked for their personal data. Notices name the fields that changed, never their values, and
are queued emails written with the change (tests/users/test_security_notices.py).
"""

from __future__ import annotations

from typing import Any
from unittest import skipUnless
from unittest.mock import patch

from django.core import mail
from django.db import connection
from django.test import TestCase, TransactionTestCase, override_settings
from django.test.utils import CaptureQueriesContext
from django.urls import reverse
from django.utils import translation

from apps.customers.models import Customer, CustomerTaxProfile
from apps.notifications.models import EmailLog
from apps.notifications.services import EmailService
from apps.notifications.tasks import send_email_task
from apps.users.models import CustomerMembership, User, UserProfile
from tests.helpers.hmac import HMAC_TEST_MIDDLEWARE, HMAC_TEST_SECRET, HMACTestMixin

PASSWORD = "Original-secure123!"  # test fixture, not a credential


def notices(event: str) -> set[str]:
    return set(EmailLog.objects.filter(template_key=f"security_notice:{event}").values_list("to_addr", flat=True))


def deliver(event: str) -> None:
    for pk in EmailLog.objects.filter(template_key=f"security_notice:{event}").values_list("pk", flat=True):
        send_email_task(str(pk))


@override_settings(PLATFORM_API_SECRET=HMAC_TEST_SECRET, MIDDLEWARE=HMAC_TEST_MIDDLEWARE)
class CompanySecurityNoticeTests(HMACTestMixin, TestCase):
    def setUp(self) -> None:
        self.customer = Customer.objects.create(
            name="Notice Co", customer_type="company", status="active", primary_email="office@old.example"
        )
        self.owner = self.person("owner@notice.example", "owner")
        self.co_owner = self.person("co-owner@notice.example", "owner")
        self.member = self.person("member@notice.example", "tech")
        self.outsider = User.objects.create_user(email="outsider@notice.example", password=PASSWORD)
        UserProfile.objects.filter(user__in=[self.owner, self.co_owner, self.member]).update(preferred_language="ro")

    def person(self, email: str, role: str) -> User:
        user = User.objects.create_user(email=email, password=PASSWORD)
        CustomerMembership.objects.create(customer=self.customer, user=user, role=role, is_active=True)
        return user

    def call(self, path: str, **data: Any) -> Any:
        body = {"customer_id": self.customer.pk, "user_id": self.owner.pk, **data}
        response = self.portal_post("/api/customers/" + path, body)
        self.assertLess(response.status_code, 300, response.content)
        return response

    def test_a_new_member_is_told_to_every_owner(self) -> None:
        self.call("users/create/", email="new@notice.example", first_name="New", last_name="Member", role="tech")
        self.assertEqual(notices("team_member_added"), {self.owner.email, self.co_owner.email})

    def test_a_role_change_is_told_to_every_owner_and_the_member(self) -> None:
        self.call("users/role/", target_user_id=self.member.pk, new_role="billing")
        self.assertEqual(notices("team_role_changed"), {self.owner.email, self.co_owner.email, self.member.email})

    def test_a_removal_is_told_to_every_owner_and_the_removed_member(self) -> None:
        self.call("users/remove/", target_user_id=self.member.pk)
        self.assertEqual(notices("team_member_removed"), {self.owner.email, self.co_owner.email, self.member.email})

    def test_a_new_contact_email_is_told_to_the_owners_and_the_old_address_by_field_name_only(self) -> None:
        self.call("update/", primary_email="office@new.example", website="https://new.example")
        self.assertEqual(
            notices("company_contact_changed"), {self.owner.email, self.co_owner.email, "office@old.example"}
        )
        deliver("company_contact_changed")
        to_owner = next(message for message in mail.outbox if message.to == [self.owner.email])
        with translation.override("ro"):  # the owner's language
            labels = [str(Customer._meta.get_field(field).verbose_name) for field in ("primary_email", "website")]
        self.assertIn(", ".join(labels), to_owner.body)
        # In the owner's language: Romanian subject and sentence, not the English source.
        self.assertEqual(to_owner.subject, "Datele de contact pentru Notice Co au fost modificate")
        self.assertIn("Datele de contact pentru Notice Co au fost modificate: ", to_owner.body)
        for message in mail.outbox:
            self.assertNotIn("office@new.example", message.body)
            self.assertNotIn("https://new.example", message.body)

    def test_details_sent_again_unchanged_are_told_to_nobody(self) -> None:
        self.call("update/", primary_email="office@old.example", name="Notice Co")
        self.assertEqual(notices("company_contact_changed"), set())

    def test_a_legal_or_tax_change_is_told_to_every_owner(self) -> None:
        CustomerTaxProfile.objects.create(customer=self.customer)
        self.call("tax-profile/", registration_number="J40/123/2020")
        self.assertEqual(notices("company_tax_changed"), {self.owner.email, self.co_owner.email})
        deliver("company_tax_changed")
        with translation.override("ro"):
            label = str(CustomerTaxProfile._meta.get_field("registration_number").verbose_name)
        self.assertIn(label, mail.outbox[0].body)
        self.assertNotIn("J40/123/2020", mail.outbox[0].body)

    def test_a_data_export_request_is_told_to_the_person_once(self) -> None:
        def export(action: str) -> None:
            response = self.portal_post("/api/gdpr/data-export/", {"user_id": self.owner.pk, "action": action})
            self.assertLess(response.status_code, 300, response.content)

        export("status")
        self.assertEqual(notices("data_export_requested"), set())
        export("request")
        export("request")  # the export already pending: nothing new was requested
        self.assertEqual(
            list(
                EmailLog.objects.filter(template_key="security_notice:data_export_requested").values_list(
                    "to_addr", flat=True
                )
            ),
            [self.owner.email],
        )

    # --- Paths the first version missed ------------------------------------------------------------

    def test_the_billing_address_endpoint_tells_contact_and_registration_changes(self) -> None:
        CustomerTaxProfile.objects.create(customer=self.customer)
        self.call("billing-address/", email="billing@new.example", registration_number="J40/1/2021")
        self.assertEqual(
            notices("company_contact_changed"), {self.owner.email, self.co_owner.email, "office@old.example"}
        )
        self.assertEqual(notices("company_tax_changed"), {self.owner.email, self.co_owner.email})

    def test_adding_an_existing_account_and_suspending_a_member_are_told(self) -> None:
        self.call("users/add/", target_user_id=self.outsider.pk, role="viewer")
        self.assertEqual(notices("team_member_added"), {self.owner.email, self.co_owner.email})
        self.call("users/toggle-status/", target_user_id=self.member.pk)
        self.assertEqual(notices("team_member_removed"), {self.owner.email, self.co_owner.email, self.member.email})

    def test_a_contact_change_is_judged_against_the_row_as_it_is_when_written(self) -> None:
        from apps.api.customers import views as customer_views  # noqa: PLC0415

        real = customer_views._get_request_data

        def changed_meanwhile(request: Any) -> Any:
            # Another request commits a new address after this one loaded the customer.
            Customer.objects.filter(pk=self.customer.pk).update(primary_email="office@meanwhile.example")
            return real(request)

        with patch.object(customer_views, "_get_request_data", changed_meanwhile):
            self.call("update/", primary_email="office@old.example")  # puts back the address it first saw
        self.assertEqual(
            notices("company_contact_changed"), {self.owner.email, self.co_owner.email, "office@meanwhile.example"}
        )

    def test_a_role_change_and_its_notice_commit_together(self) -> None:
        with (
            patch("apps.api.customers.views.notify_team_change", side_effect=RuntimeError("interrupted")),
            self.assertRaises(RuntimeError),
        ):
            self.portal_post(
                "/api/customers/users/role/",
                {
                    "customer_id": self.customer.pk,
                    "user_id": self.owner.pk,
                    "target_user_id": self.member.pk,
                    "new_role": "billing",
                },
            )
        self.assertEqual(CustomerMembership.objects.get(customer=self.customer, user=self.member).role, "tech")

    def test_a_company_name_too_long_for_a_subject_still_sends_the_notice(self) -> None:
        Customer.objects.filter(pk=self.customer.pk).update(name="N" * 200)
        self.call("users/role/", target_user_id=self.member.pk, new_role="billing")
        self.assertEqual(notices("team_role_changed"), {self.owner.email, self.co_owner.email, self.member.email})


class StaffTeamNoticeTests(TestCase):
    def setUp(self) -> None:
        self.customer = Customer.objects.create(name="Staffed Co", customer_type="company", status="active")
        self.owner = User.objects.create_user(email="owner@staffed.example", password=PASSWORD)
        CustomerMembership.objects.create(customer=self.customer, user=self.owner, role="owner", is_active=True)
        self.member = User.objects.create_user(email="member@staffed.example", password=PASSWORD)
        self.membership = CustomerMembership.objects.create(
            customer=self.customer, user=self.member, role="tech", is_active=True
        )
        staff = User.objects.create_user(email="staff@praho.example", password=PASSWORD, staff_role="admin")
        self.client.force_login(staff)

    def test_a_staff_role_change_and_its_notice_commit_together(self) -> None:
        url = reverse("customers:change_user_role", args=[self.customer.pk, self.membership.pk])
        with (
            patch("apps.customers.user_management_views.notify_team_change", side_effect=RuntimeError("interrupted")),
            self.assertRaises(RuntimeError),
        ):
            self.client.post(url, {"role": "billing"})
        self.membership.refresh_from_db()
        self.assertEqual(self.membership.role, "tech")

    def test_staff_team_changes_are_told_to_the_owners(self) -> None:
        joiner = User.objects.create_user(email="joiner@staffed.example", password=PASSWORD)
        self.client.post(
            reverse("customers:add_user", args=[self.customer.pk]), {"user_email": joiner.email, "role": "viewer"}
        )
        self.assertEqual(notices("team_member_added"), {self.owner.email})
        self.client.post(
            reverse("customers:change_user_role", args=[self.customer.pk, self.membership.pk]), {"role": "billing"}
        )
        self.assertEqual(notices("team_role_changed"), {self.owner.email, self.member.email})
        self.client.post(reverse("customers:remove_user", args=[self.customer.pk, self.membership.pk]))
        self.assertEqual(notices("team_member_removed"), {self.owner.email, self.member.email})


@override_settings(PLATFORM_API_SECRET=HMAC_TEST_SECRET, MIDDLEWARE=HMAC_TEST_MIDDLEWARE)
class ExportNoticeCommitTests(HMACTestMixin, TransactionTestCase):
    """Autocommit, as in production: the export job is queued as soon as the export commits."""

    def test_an_export_whose_job_cannot_be_queued_is_still_told_once(self) -> None:
        user = User.objects.create_user(email="exporter@notice.example", password=PASSWORD)
        with patch("apps.api.gdpr.views.async_task", side_effect=RuntimeError("queue down")):
            response = self.portal_post("/api/gdpr/data-export/", {"user_id": user.pk, "action": "request"})
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(notices("data_export_requested"), {user.email})


@skipUnless(connection.vendor == "postgresql", "an aborted transaction is PostgreSQL's")
class NoticeWriteIsolationTests(HMACTestMixin, TestCase):
    """A notice whose write fails in the database leaves the change's own transaction usable."""

    def test_the_tax_update_locks_the_customer_before_its_profile(self) -> None:
        customer = Customer.objects.create(name="Ordered Co", customer_type="company", status="active")
        owner = User.objects.create_user(email="owner@ordered.example", password=PASSWORD)
        CustomerMembership.objects.create(customer=customer, user=owner, role="owner", is_active=True)
        CustomerTaxProfile.objects.create(customer=customer)
        with (
            override_settings(PLATFORM_API_SECRET=HMAC_TEST_SECRET, MIDDLEWARE=HMAC_TEST_MIDDLEWARE),
            CaptureQueriesContext(connection) as queries,
        ):
            response = self.portal_post(
                "/api/customers/tax-profile/",
                {"customer_id": customer.pk, "user_id": owner.pk, "registration_number": "J40/9/2022"},
            )
        self.assertEqual(response.status_code, 200, response.content)
        locks = [q["sql"] for q in queries.captured_queries if " FOR " in q["sql"] and "UPDATE" in q["sql"]]
        customer_lock = next(i for i, sql in enumerate(locks) if "customers" in sql and "FOR NO KEY UPDATE" in sql)
        profile_lock = next(i for i, sql in enumerate(locks) if "tax_profile" in sql)
        self.assertLess(customer_lock, profile_lock)

    def test_a_failed_notice_write_does_not_abort_the_change(self) -> None:
        customer = Customer.objects.create(name="Isolated Co", customer_type="company", status="active")
        owner = User.objects.create_user(email="owner@isolated.example", password=PASSWORD)
        CustomerMembership.objects.create(customer=customer, user=owner, role="owner", is_active=True)
        member = User.objects.create_user(email="member@isolated.example", password=PASSWORD)
        CustomerMembership.objects.create(customer=customer, user=member, role="tech", is_active=True)

        def failing_write(*_args: Any, **_kwargs: Any) -> Any:
            with connection.cursor() as cursor:
                cursor.execute("SELECT * FROM a_table_that_does_not_exist")

        with (
            override_settings(PLATFORM_API_SECRET=HMAC_TEST_SECRET, MIDDLEWARE=HMAC_TEST_MIDDLEWARE),
            patch.object(EmailService, "_create_email_log", side_effect=failing_write),
        ):
            response = self.portal_post(
                "/api/customers/users/role/",
                {"customer_id": customer.pk, "user_id": owner.pk, "target_user_id": member.pk, "new_role": "billing"},
            )
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(CustomerMembership.objects.get(customer=customer, user=member).role, "billing")
