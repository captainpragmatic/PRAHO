"""Registrar identity requirements and the write-only, fiscal CNP intake."""
from __future__ import annotations

import json
from unittest.mock import patch

from django.core.cache import cache
from django.test import TestCase, override_settings

from apps.audit.models import AuditEvent
from apps.billing.proforma_service import ProformaService
from apps.customers.models import Customer, CustomerTaxProfile
from apps.domains.gateways.errors import RegistrarAPIError
from apps.domains.gateways.gandi import GandiGateway
from apps.domains.gateways.rotld import ROTLDGateway
from apps.domains.models import Registrar
from apps.domains.services import DomainLifecycleService
from apps.users.models import CustomerMembership, User
from tests.customers.test_tax_profile_cnp_encryption import stored_cnp
from tests.helpers.hmac import HMAC_TEST_MIDDLEWARE, HMAC_TEST_SECRET, HMACTestMixin
from tests.helpers.portal_session import BoundSessionMixin

from .test_domain_order_flow import DomainOrderLineFixture
from .test_registrar_contracts import CONTACT

CNP = "1850101123451"
PATH = "/api/customers/tax-profile/"


class RegistrantRequirementsTests(TestCase):
    def test_requirements_follow_the_registrant_entity_normalisation(self) -> None:
        rotld = ROTLDGateway(Registrar(name="rotld", api_endpoint="https://rest2-test.rotld.ro:6080"))
        gandi = GandiGateway(Registrar(name="gandi"))
        for kind in ("individual", "company", "pfa", "ngo"):
            for country in ("RO", "DE"):
                expected = frozenset({"cui", "registration_number"} if kind == "company" else {"cnp"}) if country == "RO" else frozenset()
                self.assertEqual(rotld.registrant_requirements(kind, country), expected)
                self.assertEqual(gandi.registrant_requirements(kind, country), frozenset())
        with patch.object(rotld, "registrant_requirements", return_value=frozenset({"cnp"})) as requirements:
            with self.assertRaises(RegistrarAPIError):
                rotld.validate_registration_data(CONTACT)
            requirements.assert_called_once_with("company", "RO")


@override_settings(PLATFORM_API_SECRET=HMAC_TEST_SECRET, MIDDLEWARE=HMAC_TEST_MIDDLEWARE)
class RegistrantCNPAPITests(BoundSessionMixin, HMACTestMixin, DomainOrderLineFixture, TestCase):
    def setUp(self) -> None:
        super().setUp()
        cache.clear()
        Customer.objects.filter(pk=self.customer.pk).update(status="active")
        self.customer.customer_type = "individual"
        self.customer.save(update_fields=["customer_type"])
        self.users: dict[str, User] = {}
        for role in ("owner", "billing", "tech", "viewer"):
            user = User.objects.create_user(email=f"cnp-{role}@example.test")
            CustomerMembership.objects.create(customer=self.customer, user=user, role=role, is_active=True)
            self.users[role] = user

    def payload(self, cnp: object = CNP, role: str = "owner") -> dict[str, object]:
        return {"customer_id": self.customer.pk, "user_id": self.users[role].pk, "cnp": cnp}

    def test_owner_and_billing_write_encrypted_without_echo_audit_value_or_anaf_refresh(self) -> None:
        for existing in (False, True):
            for role in ("owner", "billing"):
                with self.subTest(existing=existing, role=role):
                    CustomerTaxProfile.objects.filter(customer=self.customer).delete()
                    if existing:
                        CustomerTaxProfile.objects.create(customer=self.customer, cui="12345678")
                    with patch("apps.customers.signals._refresh_anaf_evidence") as refresh:
                        response = self.portal_post(PATH, self.payload(f" {CNP} ", role))
                    self.assertEqual(response.status_code, 200, response.content)
                    self.assertTrue(response.json()["success"])
                    profile = CustomerTaxProfile.objects.get(customer=self.customer)
                    self.assertEqual(profile.cnp, CNP)
                    ciphertext = stored_cnp(profile.pk)
                    self.assertIsNotNone(ciphertext)
                    self.assertNotIn(CNP, str(ciphertext))
                    self.assertIn("aes:v2:", str(ciphertext))
                    refresh.assert_not_called()
                    event = AuditEvent.objects.filter(action="tax_profile_cnp_set").latest("timestamp")
                    self.assertEqual(event.user, self.users[role])
                    evidence = json.dumps(list(AuditEvent.objects.values("metadata", "old_values", "new_values", "description")), default=str)
                    self.assertNotIn(CNP, evidence + response.content.decode())
                    # Use the same public customer response consumed by the portal.
                    details = self.portal_post("/api/customers/details/", {"customer_id": self.customer.pk, "user_id": self.users[role].pk})
                    self.assertNotIn(CNP, details.content.decode())
                    self.assertNotIn('"cnp":', details.content.decode())

    def test_invalid_cnp_has_one_fixed_error_and_creates_no_profile(self) -> None:
        CustomerTaxProfile.objects.filter(customer=self.customer).delete()
        for value in (None, 1850101123451, "", "123", "1851332123453", "1850101123450"):
            with self.subTest(value=value):
                response = self.portal_post(PATH, self.payload(value))
                self.assertEqual(response.status_code, 400, response.content)
                self.assertEqual(response.json(), {"success": False, "error": "Enter a valid CNP."})
                self.assertFalse(CustomerTaxProfile.objects.filter(customer=self.customer).exists())
        self.assertFalse(AuditEvent.objects.filter(action="tax_profile_cnp_set").exists())

    def test_unsigned_nonbilling_outsider_and_inactive_members_cannot_write(self) -> None:
        response = self.client.post(PATH, self.payload(), content_type="application/json")
        self.assertEqual(response.status_code, 401)
        for role in ("tech", "viewer"):
            response = self.portal_post(PATH, self.payload(role=role))
            self.assertEqual(response.status_code, 403)
        CustomerMembership.objects.filter(user=self.users["owner"]).update(is_active=False)
        response = self.portal_post(PATH, self.payload())
        self.assertEqual(response.status_code, 403)
        outsider = User.objects.create_user(email="cnp-outsider@example.test")
        response = self.portal_post(PATH, {**self.payload(), "user_id": outsider.pk})
        self.assertEqual(response.status_code, 403)
        self.assertEqual(CustomerTaxProfile.objects.get(customer=self.customer).cnp, "")
        self.assertFalse(AuditEvent.objects.filter(action="tax_profile_cnp_set").exists())

    def test_cnp_received_by_api_is_the_next_proformas_buyer_identifier(self) -> None:
        CustomerTaxProfile.objects.filter(customer=self.customer).delete()
        response = self.portal_post(PATH, self.payload())
        self.assertEqual(response.status_code, 200, response.content)
        order, _line = self._domain_order()
        proforma = ProformaService.create_from_order(order).unwrap()
        proforma.refresh_from_db()
        self.assertEqual(proforma.bill_to_cnp, CNP)
        data = DomainLifecycleService._build_registrant_data(Customer.objects.get(pk=self.customer.pk)).unwrap()
        self.assertEqual(data["cnp"], CNP)
        self.assertEqual(data["entity_type"], "individual")
