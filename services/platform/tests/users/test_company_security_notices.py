"""Changes to a company's team, contact details and legal identity, and data exports, are told by email.

A stolen session acts as the person it belongs to, so a notice goes where the rightful person
reads it: every owner of the company (the one who made the change included), the member a role
change or removal touched, the old contact address when the contact email changed, and the person
who asked for their personal data. Notices name the fields that changed, never their values, and
are queued emails written with the change (tests/users/test_security_notices.py).
"""

from __future__ import annotations

from typing import Any

from django.core import mail
from django.test import TestCase, override_settings
from django.utils import translation

from apps.customers.models import Customer, CustomerTaxProfile
from apps.notifications.models import EmailLog
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
