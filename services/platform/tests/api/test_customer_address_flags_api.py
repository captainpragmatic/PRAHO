"""Regression coverage for address boolean validation and designation changes."""

import json
import time
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import RequestFactory, TestCase
from rest_framework.response import Response

from apps.api.customers.views import customer_addresses_add, customer_addresses_update
from apps.customers.contact_models import CustomerAddress
from apps.customers.models import Customer
from apps.users.models import CustomerMembership

User = get_user_model()


class CustomerAddressBooleanAPITests(TestCase):
    """Address flags must be validated before model designation side effects."""

    def setUp(self) -> None:
        self.factory = RequestFactory()
        self.owner = User.objects.create_user(email="address-owner@example.com", password="pass123")
        self.customer = Customer.objects.create(name="Boolean Co", customer_type="company", status="active")
        CustomerMembership.objects.create(customer=self.customer, user=self.owner, role="owner")
        self.current = CustomerAddress.objects.create(
            customer=self.customer,
            is_primary=True,
            is_billing=True,
            address_line1="Current address",
            city="Cluj",
        )
        self.other = CustomerAddress.objects.create(
            customer=self.customer,
            is_current=False,
            address_line1="Other address",
            city="Cluj",
        )
        auth = patch("apps.api.secure_auth.get_authenticated_customer", return_value=(self.customer, None))
        auth.start()
        self.addCleanup(auth.stop)

    def _post(self, action: str, **fields: object) -> Response:
        data = {
            "customer_id": self.customer.pk,
            "user_id": self.owner.pk,
            "address_line1": "New address",
            "city": "Cluj",
            "timestamp": int(time.time()),
            **fields,
        }
        if action == "update":
            data.setdefault("address_id", self.other.pk)
        request = self.factory.post(
            f"/api/customers/addresses/{action}/", data=json.dumps(data), content_type="application/json"
        )
        return customer_addresses_add(request) if action == "add" else customer_addresses_update(request)

    def test_create_normalizes_boolean_representations(self) -> None:
        for value, expected in (
            (False, False),
            ("false", False),
            ("FALSE", False),
            ("off", False),
            ("0", False),
            (0, False),
            (True, True),
            ("true", True),
            ("TRUE", True),
            ("on", True),
            ("1", True),
            (1, True),
            ("yes", True),
            ("no", False),
            ("t", True),
            ("f", False),
            ("y", True),
            ("n", False),
        ):
            with self.subTest(value=value):
                response = self._post("add", is_primary=value, is_billing=value, is_current=value)
                self.assertEqual(response.status_code, 201)
                address = CustomerAddress.objects.get(pk=response.data["address_id"])
                self.assertEqual((address.is_primary, address.is_billing, address.is_current), (expected,) * 3)
                # Release each test address so the next case does not hit the address limit.
                address.soft_delete()

    def test_update_normalizes_boolean_representations(self) -> None:
        for value, expected in (
            (False, False),
            ("false", False),
            ("FALSE", False),
            ("off", False),
            ("0", False),
            (0, False),
            (True, True),
            ("true", True),
            ("TRUE", True),
            ("on", True),
            ("1", True),
            (1, True),
            ("yes", True),
            ("no", False),
            ("t", True),
            ("f", False),
            ("y", True),
            ("n", False),
        ):
            with self.subTest(value=value):
                response = self._post("update", is_primary=value, is_billing=value, is_current=value)
                self.assertEqual(response.status_code, 200)
                self.other.refresh_from_db()
                self.assertEqual(
                    (self.other.is_primary, self.other.is_billing, self.other.is_current),
                    (expected,) * 3,
                )

    def test_create_omitted_flags_keep_defaults(self) -> None:
        response = self._post("add")
        self.assertEqual(response.status_code, 201)
        address = CustomerAddress.objects.get(pk=response.data["address_id"])
        self.assertEqual((address.is_primary, address.is_billing, address.is_current), (False, False, True))

    def test_update_omitted_flags_preserves_designations(self) -> None:
        for address, expected in ((self.current, True), (self.other, False)):
            with self.subTest(address=address.pk):
                response = self._post("update", address_id=address.pk, label="Updated label")
                self.assertEqual(response.status_code, 200)
                address.refresh_from_db()
                self.assertEqual((address.is_primary, address.is_billing, address.is_current), (expected,) * 3)
                self.assertEqual(address.label, "Updated label")

    def test_false_flags_preserve_existing_designations(self) -> None:
        for action in ("add", "update"):
            with self.subTest(action=action):
                response = self._post(action, is_primary="false", is_billing="false")
                self.assertEqual(response.status_code, 201 if action == "add" else 200)
                self.current.refresh_from_db()
                self.assertTrue(self.current.is_primary)
                self.assertTrue(self.current.is_billing)

    def test_true_flags_transfer_existing_designations(self) -> None:
        for action in ("add", "update"):
            with self.subTest(action=action):
                self.current.is_primary = self.current.is_billing = True
                self.current.save()
                response = self._post(action, is_primary="true", is_billing="on")
                self.assertEqual(response.status_code, 201 if action == "add" else 200)
                address_id = response.data["address_id"] if action == "add" else self.other.pk
                address = CustomerAddress.objects.get(pk=address_id)
                self.assertTrue(address.is_primary)
                self.assertTrue(address.is_billing)
                self.current.refresh_from_db()
                self.assertFalse(self.current.is_primary)
                self.assertFalse(self.current.is_billing)

    def test_invalid_flags_rejected_before_any_save(self) -> None:
        for action in ("add", "update"):
            for field in ("is_primary", "is_billing", "is_current"):
                for value in (None, "", "maybe", [], {}, 2):
                    with self.subTest(action=action, field=field, value=value):
                        before = list(CustomerAddress.objects.filter(customer=self.customer).order_by("pk").values())
                        fields = {"is_primary": True, "is_billing": True, "is_current": True, "label": "Changed"}
                        fields[field] = value
                        with patch.object(CustomerAddress, "save", autospec=True) as save:
                            response = self._post(action, **fields)
                        self.assertEqual(response.status_code, 400)
                        self.assertFalse(response.data["success"])
                        self.assertEqual(response.data["error"], "Validation failed")
                        self.assertIn(field, response.data["errors"])
                        save.assert_not_called()
                        self.assertEqual(
                            list(CustomerAddress.objects.filter(customer=self.customer).order_by("pk").values()),
                            before,
                        )
