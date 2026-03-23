"""
Tests for F02 + F03 fixes in update_customer_billing_address API view.

F03: Address creation must go through ContactService.create_address() for proper
     versioning (version increments, old current addresses marked non-current).

F02: Customer save() must only include fields that were actually provided in the
     request — not unconditionally write all 4 fields.

These tests use real HMAC signing identical to the middleware canonicalization
to avoid mocking at the wrong layer. Nonces must be >= 32 chars (HMAC_NONCE_MIN_LENGTH).
"""

import base64
import hashlib
import hmac
import json
import secrets
import time
import urllib.parse

from django.test import Client, TestCase, override_settings

from apps.customers.contact_models import CustomerAddress
from apps.customers.models import Customer
from apps.users.models import CustomerMembership, User

HMAC_MIDDLEWARE_STACK = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.locale.LocaleMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "apps.common.middleware.PortalServiceHMACMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

TEST_SECRET = "unit-test-secret"
TEST_PORTAL_ID = "portal-billing-addr-test"
API_PATH = "/api/customers/billing-address/"


def _unique_nonce() -> str:
    """Generate a cryptographically random 32-char hex nonce (meets HMAC_NONCE_MIN_LENGTH)."""
    return secrets.token_hex(16)  # 32 hex chars


def _sign(method: str, path: str, body: bytes, portal_id: str, nonce: str, timestamp: str) -> str:  # noqa: PLR0913
    """Compute HMAC-SHA256 signature matching the middleware canonicalization."""
    parsed = urllib.parse.urlsplit(path)
    pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    pairs.sort(key=lambda kv: (kv[0], kv[1]))
    normalized_query = urllib.parse.urlencode(pairs, doseq=True)
    normalized_path = parsed.path + ("?" + normalized_query if normalized_query else "")

    content_type = "application/json"
    body_hash = base64.b64encode(hashlib.sha256(body).digest()).decode("ascii")

    canonical = "\n".join(
        [method, normalized_path, content_type, body_hash, portal_id, nonce, timestamp]
    )
    return hmac.new(TEST_SECRET.encode(), canonical.encode(), hashlib.sha256).hexdigest()


def _make_headers(method: str, path: str, body: bytes, nonce: str, timestamp: str) -> dict[str, str]:
    sig = _sign(method, path, body, TEST_PORTAL_ID, nonce, timestamp)
    return {
        "HTTP_X_PORTAL_ID": TEST_PORTAL_ID,
        "HTTP_X_NONCE": nonce,
        "HTTP_X_TIMESTAMP": timestamp,
        "HTTP_X_BODY_HASH": base64.b64encode(hashlib.sha256(body).digest()).decode("ascii"),
        "HTTP_X_SIGNATURE": sig,
    }


def _post_billing_address(client: Client, user: User, customer: Customer, payload: dict) -> object:
    """Helper: POST to the billing address API with valid HMAC auth."""
    ts = str(int(time.time()))
    nonce = _unique_nonce()
    body_dict = {
        "timestamp": int(ts),
        "user_id": user.id,
        "customer_id": customer.id,
        **payload,
    }
    body = json.dumps(body_dict).encode()
    headers = _make_headers("POST", API_PATH, body, nonce=nonce, timestamp=ts)
    return client.post(API_PATH, data=body, content_type="application/json", **headers)


@override_settings(
    PLATFORM_API_SECRET=TEST_SECRET,
    MIDDLEWARE=HMAC_MIDDLEWARE_STACK,
)
class TestBillingAddressAPIAddressVersioning(TestCase):
    """F03: Address updates must use ContactService.create_address() for versioning."""

    def setUp(self) -> None:
        self.client = Client()
        self.user = User.objects.create_user(
            email="owner@versioning.test", password="testpass", is_active=True
        )
        self.customer = Customer.objects.create(
            name="Versioning Test SRL",
            company_name="Versioning Test SRL",
            customer_type="company",
            primary_email="contact@versioning.test",
            status="active",
        )
        CustomerMembership.objects.create(
            customer=self.customer, user=self.user, role="owner", is_primary=True
        )

    def test_first_address_creation_sets_version_one(self) -> None:
        """Creating the first address via the API must produce version=1."""
        payload = {
            "address_line1": "Str. Primei Nr. 1",
            "city": "București",
            "county": "Sector 1",
            "postal_code": "010001",
        }
        resp = _post_billing_address(self.client, self.user, self.customer, payload)
        self.assertEqual(resp.status_code, 200, resp.content)

        addr = CustomerAddress.objects.get(customer=self.customer, is_primary=True, is_current=True)
        self.assertEqual(addr.version, 1)

    def test_second_update_increments_version(self) -> None:
        """Posting a new address when one already exists must create version=2."""
        payload_v1 = {
            "address_line1": "Str. Veche Nr. 10",
            "city": "Cluj-Napoca",
            "county": "Cluj",
            "postal_code": "400001",
        }
        _post_billing_address(self.client, self.user, self.customer, payload_v1)

        payload_v2 = {
            "address_line1": "Str. Noua Nr. 20",
            "city": "Cluj-Napoca",
            "county": "Cluj",
            "postal_code": "400002",
        }
        resp = _post_billing_address(self.client, self.user, self.customer, payload_v2)
        self.assertEqual(resp.status_code, 200, resp.content)

        # Version 2 is current
        current = CustomerAddress.objects.get(customer=self.customer, is_primary=True, is_current=True)
        self.assertEqual(current.version, 2)

    def test_old_address_marked_non_current_after_update(self) -> None:
        """After a second address update, the first address must have is_current=False."""
        payload_v1 = {
            "address_line1": "Str. Veche Nr. 10",
            "city": "Timișoara",
            "county": "Timiș",
            "postal_code": "300001",
        }
        _post_billing_address(self.client, self.user, self.customer, payload_v1)

        # Capture the first address pk while it is still current
        addr_v1 = CustomerAddress.objects.get(customer=self.customer, is_primary=True, is_current=True)
        addr_v1_pk = addr_v1.pk

        payload_v2 = {
            "address_line1": "Str. Noua Nr. 99",
            "city": "Timișoara",
            "county": "Timiș",
            "postal_code": "300002",
        }
        _post_billing_address(self.client, self.user, self.customer, payload_v2)

        addr_v1.refresh_from_db()
        self.assertFalse(
            addr_v1.is_current,
            "The previous address must be marked non-current after a new one is created.",
        )

        # History is preserved — the old address row still exists
        self.assertTrue(CustomerAddress.objects.filter(pk=addr_v1_pk).exists())

    def test_at_most_one_current_address_per_type(self) -> None:
        """There must never be more than one current primary address for a customer."""
        for i in range(3):
            payload = {
                "address_line1": f"Str. Test Nr. {i + 1}",
                "city": "Iași",
                "county": "Iași",
                "postal_code": f"70000{i + 1}",
            }
            _post_billing_address(self.client, self.user, self.customer, payload)

        current_count = CustomerAddress.objects.filter(
            customer=self.customer, is_primary=True, is_current=True
        ).count()
        self.assertEqual(current_count, 1, "Exactly one current primary address must exist after multiple updates.")


@override_settings(
    PLATFORM_API_SECRET=TEST_SECRET,
    MIDDLEWARE=HMAC_MIDDLEWARE_STACK,
)
class TestBillingAddressAPIPartialCustomerSave(TestCase):
    """F02: customer.save() must only write fields actually provided in the request."""

    def setUp(self) -> None:
        self.client = Client()
        self.user = User.objects.create_user(
            email="owner@partial.test", password="testpass", is_active=True
        )
        self.customer = Customer.objects.create(
            name="Partial Save SRL",
            company_name="Original Company SRL",
            customer_type="company",
            primary_email="original@partial.test",
            primary_phone="+40700000000",
            status="active",
        )
        CustomerMembership.objects.create(
            customer=self.customer, user=self.user, role="owner", is_primary=True
        )

    def test_only_company_name_updated_when_only_company_name_provided(self) -> None:
        """When only company_name is in the request, email and phone must be untouched."""
        original_email = self.customer.primary_email
        original_phone = self.customer.primary_phone

        payload = {
            "company_name": "New Company SRL",
            "address_line1": "Str. Test Nr. 1",
            "city": "București",
            "county": "Sector 1",
            "postal_code": "010001",
        }
        resp = _post_billing_address(self.client, self.user, self.customer, payload)
        self.assertEqual(resp.status_code, 200, resp.content)

        self.customer.refresh_from_db()
        self.assertEqual(self.customer.company_name, "New Company SRL")
        self.assertEqual(self.customer.primary_email, original_email, "Email must not be overwritten.")
        self.assertEqual(self.customer.primary_phone, original_phone, "Phone must not be overwritten.")

    def test_only_email_updated_when_only_email_provided(self) -> None:
        """When only email is in the request, company_name and phone must be untouched."""
        original_company = self.customer.company_name
        original_phone = self.customer.primary_phone

        payload = {
            "email": "new@partial.test",
            "address_line1": "Str. Test Nr. 1",
            "city": "București",
            "county": "Sector 1",
            "postal_code": "010001",
        }
        resp = _post_billing_address(self.client, self.user, self.customer, payload)
        self.assertEqual(resp.status_code, 200, resp.content)

        self.customer.refresh_from_db()
        self.assertEqual(self.customer.primary_email, "new@partial.test")
        self.assertEqual(self.customer.company_name, original_company, "Company name must not be overwritten.")
        self.assertEqual(self.customer.primary_phone, original_phone, "Phone must not be overwritten.")

    def test_no_customer_save_when_no_customer_fields_provided(self) -> None:
        """When only address fields are provided, customer model must not be saved at all."""
        original_name = self.customer.name
        original_email = self.customer.primary_email

        payload = {
            "address_line1": "Str. Test Nr. 1",
            "city": "București",
            "county": "Sector 1",
            "postal_code": "010001",
        }
        resp = _post_billing_address(self.client, self.user, self.customer, payload)
        self.assertEqual(resp.status_code, 200, resp.content)

        self.customer.refresh_from_db()
        self.assertEqual(self.customer.name, original_name, "Name must not change when not provided.")
        self.assertEqual(self.customer.primary_email, original_email, "Email must not change when not provided.")

    def test_all_four_fields_updated_when_all_provided(self) -> None:
        """When all four customer fields are provided, all four must be saved."""
        payload = {
            "company_name": "Updated Company SRL",
            "contact_name": "Ion Popescu",
            "email": "updated@partial.test",
            "phone": "+40799999999",
            "address_line1": "Str. Test Nr. 1",
            "city": "București",
            "county": "Sector 1",
            "postal_code": "010001",
        }
        resp = _post_billing_address(self.client, self.user, self.customer, payload)
        self.assertEqual(resp.status_code, 200, resp.content)

        self.customer.refresh_from_db()
        self.assertEqual(self.customer.company_name, "Updated Company SRL")
        self.assertEqual(self.customer.name, "Ion Popescu")
        self.assertEqual(self.customer.primary_email, "updated@partial.test")
        self.assertEqual(self.customer.primary_phone, "+40799999999")


@override_settings(
    PLATFORM_API_SECRET=TEST_SECRET,
    MIDDLEWARE=HMAC_MIDDLEWARE_STACK,
)
class TestBillingAddressAPISkipsAddressWhenDataMissing(TestCase):
    """Address creation must be skipped when mandatory address fields are absent."""

    def setUp(self) -> None:
        self.client = Client()
        self.user = User.objects.create_user(
            email="owner@skip.test", password="testpass", is_active=True
        )
        self.customer = Customer.objects.create(
            name="Skip Address SRL",
            company_name="Skip Address SRL",
            customer_type="company",
            primary_email="contact@skip.test",
            status="active",
        )
        CustomerMembership.objects.create(
            customer=self.customer, user=self.user, role="owner", is_primary=True
        )

    def test_no_address_created_when_address_line1_absent(self) -> None:
        """No CustomerAddress must be created when address_line1 is not provided."""
        payload = {
            "company_name": "Skip Address SRL",
            "city": "București",
        }
        resp = _post_billing_address(self.client, self.user, self.customer, payload)
        self.assertEqual(resp.status_code, 200, resp.content)

        address_count = CustomerAddress.objects.filter(customer=self.customer).count()
        self.assertEqual(address_count, 0, "No address should be created without address_line1.")

    def test_no_address_created_when_city_absent(self) -> None:
        """No CustomerAddress must be created when city is not provided."""
        payload = {
            "company_name": "Skip Address SRL",
            "address_line1": "Str. Test Nr. 1",
        }
        resp = _post_billing_address(self.client, self.user, self.customer, payload)
        self.assertEqual(resp.status_code, 200, resp.content)

        address_count = CustomerAddress.objects.filter(customer=self.customer).count()
        self.assertEqual(address_count, 0, "No address should be created without city.")
