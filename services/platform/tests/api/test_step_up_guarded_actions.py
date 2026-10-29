"""Every sensitive customer action needs an identity check from the last 300 seconds.

Changing who belongs to a company, its contact or legal details, the person's name or phone, and
asking for or downloading a GDPR export are refused from a stale session with nothing written, and
done from a fresh one. Reads, preferences, a first fill of a tax identity and the export status
never ask.
"""

from __future__ import annotations

import json
import shutil
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import timedelta
from typing import Any
from unittest.mock import patch

from django.db import transaction
from django.test import TestCase, override_settings
from django.utils import timezone

from apps.audit.models import DataExport
from apps.customers.models import Customer, CustomerAddress, CustomerTaxProfile
from apps.users import portal_sessions
from apps.users.models import CustomerMembership, PortalSession, User
from tests.helpers.hmac import HMAC_TEST_MIDDLEWARE, HMAC_TEST_SECRET, HMACTestMixin, hmac_headers

REAUTH = {"success": False, "code": "reauth_required"}


@dataclass(frozen=True)
class Action:
    name: str
    path: str
    payload: Callable[[StepUpCoverageTests], dict[str, Any]]


ACTIONS = (
    Action(
        "create a member",
        "customers/users/create/",
        lambda t: {
            "email": "new-member@example.ro",
            "role": "viewer",
            "first_name": "Ana",
            "last_name": "Pop",
        },
    ),
    Action(
        "add an existing account",
        "customers/users/add/",
        lambda t: {
            "target_user_id": t.outsider.pk,
            "role": "viewer",
        },
    ),
    Action("change a role", "customers/users/role/", lambda t: {"target_user_id": t.member.pk, "new_role": "billing"}),
    Action("remove a member", "customers/users/remove/", lambda t: {"target_user_id": t.member.pk}),
    Action("suspend a member", "customers/users/toggle-status/", lambda t: {"target_user_id": t.member.pk}),
    Action("change the company", "customers/update/", lambda t: {"name": "Renamed SRL"}),
    Action("add an address", "customers/addresses/add/", lambda t: {"address_line1": "Str. Noua 2", "city": "Cluj"}),
    Action(
        "change an address",
        "customers/addresses/update/",
        lambda t: {
            "address_id": t.second.pk,
            "address_line1": "Str. Alta 3",
            "city": "Cluj",
        },
    ),
    Action("delete an address", "customers/addresses/delete/", lambda t: {"address_id": t.second.pk}),
    Action("make an address primary", "customers/addresses/set-primary/", lambda t: {"address_id": t.second.pk}),
    Action(
        "make an address the billing one", "customers/addresses/set-billing/", lambda t: {"address_id": t.second.pk}
    ),
    Action(
        "change the billing address",
        "customers/billing-address/",
        lambda t: {
            "address_line1": "Str. Facturare 4",
            "city": "București",
            "county": "Sector 1",
            "postal_code": "010001",
        },
    ),
    Action("change the legal identity", "customers/tax-profile/", lambda t: {"cui": "18547290"}),
)


@override_settings(PLATFORM_API_SECRET=HMAC_TEST_SECRET, MIDDLEWARE=HMAC_TEST_MIDDLEWARE, HMAC_ALLOW_LEGACY_SECRET=True)
class StepUpCoverageTests(HMACTestMixin, TestCase):
    def setUp(self) -> None:
        self.owner = User.objects.create_user(
            email="owner@example.ro", password="Owner-secure123!", phone="+40722123456"
        )
        self.member = User.objects.create_user(email="member@example.ro")
        self.outsider = User.objects.create_user(email="outsider@example.ro")
        self.customer = Customer.objects.create(
            name="Acme SRL",
            company_name="Acme SRL",
            customer_type="company",
            primary_email="office@acme.ro",
            status="active",
        )
        CustomerMembership.objects.create(customer=self.customer, user=self.owner, role="owner", is_primary=True)
        CustomerMembership.objects.create(customer=self.customer, user=self.member, role="tech")
        CustomerAddress.objects.create(
            customer=self.customer, is_primary=True, is_billing=True, address_line1="Str. Veche 1", city="Cluj"
        )
        self.second = CustomerAddress.objects.create(customer=self.customer, address_line1="Str. Doi 2", city="Cluj")
        CustomerTaxProfile.objects.create(customer=self.customer, cui="14399840", is_vat_payer=False)
        self.session = portal_sessions.open_session(self.owner)

    def stale(self) -> None:
        PortalSession.objects.filter(pk=self.session.pk).update(reauth_at=timezone.now() - timedelta(seconds=301))

    def fresh(self) -> None:
        PortalSession.objects.filter(pk=self.session.pk).update(reauth_at=timezone.now())

    def call(self, path: str, data: dict[str, Any], *, method: str = "post") -> Any:
        body = {"user_id": self.owner.pk, "customer_id": self.customer.pk, "session_id": str(self.session.pk), **data}
        if method == "put":
            body["timestamp"] = time.time()
            raw = json.dumps(body).encode()
            return self.client.put(
                "/api/" + path, raw, content_type="application/json", **hmac_headers("PUT", "/api/" + path, raw)
            )
        return self.portal_post("/api/" + path, body)

    def state(self) -> tuple[Any, ...]:
        """Every row a guarded action could write, as stored."""
        return (
            list(Customer.objects.filter(pk=self.customer.pk).values()),
            list(CustomerMembership.objects.filter(customer=self.customer).order_by("pk").values()),
            list(CustomerAddress.objects.filter(customer=self.customer).order_by("pk").values()),
            list(CustomerTaxProfile.objects.filter(customer=self.customer).values()),
            list(User.objects.order_by("pk").values("pk", "first_name", "last_name", "phone")),
            DataExport.objects.count(),
        )

    def test_each_action_is_refused_when_stale_and_done_when_fresh(self) -> None:
        for action in ACTIONS:
            with self.subTest(action=action.name), transaction.atomic():
                self.stale()
                before = self.state()
                refused = self.call(action.path, action.payload(self))
                self.assertEqual(refused.status_code, 403, refused.content)
                self.assertEqual(refused.json(), REAUTH)
                self.assertEqual(self.state(), before)
                self.fresh()
                done = self.call(action.path, action.payload(self))
                self.assertLess(done.status_code, 300, done.content)
                self.assertNotEqual(self.state(), before)  # the fresh call really did it
                transaction.set_rollback(True)

    def test_a_first_legal_identity_needs_no_check(self) -> None:
        CustomerTaxProfile.objects.filter(customer=self.customer).update(cui="", vat_number="", registration_number="")
        self.stale()
        response = self.call("customers/tax-profile/", {"cui": "18547290"})
        self.assertLess(response.status_code, 300, response.content)
        self.assertEqual(CustomerTaxProfile.objects.get(customer=self.customer).cui, "18547290")

    def test_resubmitting_the_same_identity_in_another_form_needs_no_check(self) -> None:
        self.stale()
        response = self.call("customers/tax-profile/", {"cui": "RO14399840"})
        self.assertLess(response.status_code, 300, response.content)

    def test_the_name_or_phone_needs_a_check_and_preferences_do_not(self) -> None:
        self.stale()
        cases = {
            "a new phone": ({"phone": "+40733000111"}, 403),
            "a new first name": ({"first_name": "Other"}, 403),
            "the same phone, formatted": ({"phone": "+40 722 123 456"}, 200),
            "a language": ({"preferred_language": "ro"}, 200),
        }
        for name, (fields, expected) in cases.items():
            with self.subTest(change=name), transaction.atomic():
                before = self.state()
                response = self.call("users/profile/", fields, method="put")
                self.assertEqual(response.status_code, expected, response.content)
                if expected == 403:
                    self.assertEqual(self.state(), before)
                transaction.set_rollback(True)

    def test_a_name_changed_meanwhile_is_not_written_back_unchecked(self) -> None:
        from apps.api.users.serializers import ProfileUpdateSerializer  # noqa: PLC0415

        self.stale()
        original = User.objects.get(pk=self.owner.pk).first_name
        validate = ProfileUpdateSerializer.is_valid

        def valid_then_renamed(serializer: Any, *args: Any, **kwargs: Any) -> bool:
            valid = validate(serializer, *args, **kwargs)
            User.objects.filter(pk=self.owner.pk).update(first_name="Changed")  # another request saves first
            return valid

        with patch.object(ProfileUpdateSerializer, "is_valid", valid_then_renamed):
            response = self.call("users/profile/", {"first_name": original}, method="put")
        self.assertEqual(response.status_code, 403, response.content)
        self.assertEqual(User.objects.get(pk=self.owner.pk).first_name, "Changed")

    def test_a_stored_number_in_another_format_is_no_change(self) -> None:
        User.objects.filter(pk=self.owner.pk).update(phone="+40 722 123 456")  # stored before normalising
        self.stale()
        response = self.call("users/profile/", {"phone": "+40 722 123 456", "preferred_language": "ro"}, method="put")
        self.assertEqual(response.status_code, 200, response.content)

    def test_an_export_request_needs_a_check_and_its_status_does_not(self) -> None:
        self.stale()
        cases = {
            "omitted, so a request": ({}, 403),
            "request": ({"action": "request"}, 403),
            "status": ({"action": "status"}, 200),
            "unknown": ({"action": "purge"}, 400),
            "null": ({"action": None}, 400),
        }
        for name, (fields, expected) in cases.items():
            with self.subTest(action=name):
                response = self.call("gdpr/data-export/", fields)
                self.assertEqual(response.status_code, expected, response.content)
        self.assertEqual(DataExport.objects.count(), 0)

    def test_an_unbound_request_is_refused_as_an_ended_session(self) -> None:
        for required in (False, True):
            with self.subTest(required=required), override_settings(PORTAL_SESSION_REQUIRED=required):
                response = self.portal_post(
                    "/api/customers/users/remove/",
                    {"user_id": self.owner.pk, "customer_id": self.customer.pk, "target_user_id": self.member.pk},
                )
                self.assertEqual(response.status_code, 401)
                self.assertFalse(response.json()["active"])
        self.assertTrue(CustomerMembership.objects.filter(customer=self.customer, user=self.member).exists())


@override_settings(PLATFORM_API_SECRET=HMAC_TEST_SECRET, MIDDLEWARE=HMAC_TEST_MIDDLEWARE, HMAC_ALLOW_LEGACY_SECRET=True)
class ExportDownloadStepUpTests(HMACTestMixin, TestCase):
    def setUp(self) -> None:
        from apps.audit.services import GDPRExportService  # noqa: PLC0415

        media = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, media, ignore_errors=True)
        media_root = override_settings(MEDIA_ROOT=media)
        media_root.enable()
        self.addCleanup(media_root.disable)
        self.user = User.objects.create_user(email="exporter@example.ro")
        self.export = GDPRExportService.create_data_export_request(self.user).unwrap()
        self.assertTrue(GDPRExportService.process_data_export(self.export).is_ok())
        self.session = portal_sessions.open_session(self.user)

    def download(self) -> Any:
        return self.portal_post(
            f"/api/gdpr/data-export/{self.export.pk}/download/",
            {"user_id": self.user.pk, "session_id": str(self.session.pk)},
        )

    def test_a_download_needs_a_check(self) -> None:
        PortalSession.objects.filter(pk=self.session.pk).update(reauth_at=timezone.now() - timedelta(seconds=301))
        refused = self.download()
        self.assertEqual((refused.status_code, refused.json()), (403, REAUTH))
        self.assertEqual(DataExport.objects.get(pk=self.export.pk).download_count, 0)
        PortalSession.objects.filter(pk=self.session.pk).update(reauth_at=timezone.now())
        self.assertEqual(self.download().status_code, 200)
        self.assertEqual(DataExport.objects.get(pk=self.export.pk).download_count, 1)
