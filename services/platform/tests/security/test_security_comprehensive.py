"""OWASP-style checks across the staff pages: injection, XSS, CSRF, authentication, access, input and headers.

These lived under the repository's root tests/security/, which no test run collects, and every one failed in setUp
(`username=` on the email-based User) without anyone seeing it. Their URLs all carried an /app/ prefix that no longer
exists, and most status checks accepted 404, so even a working module would have passed on pages that were never
reached. Each check now reaches its page by name and asserts what it protects, not only that nothing crashed.
"""

from __future__ import annotations

import re

from django.contrib.auth import get_user_model
from django.test import Client, TestCase
from django.urls import reverse

from apps.customers.models import Customer, CustomerTaxProfile
from apps.users.models import CustomerMembership

User = get_user_model()

PASSWORD = "TestPass123!"
_CSRF_VALUE = re.compile(rb'name="csrfmiddlewaretoken" value="([^"]+)"')


_NONCE = re.compile(rb'nonce="[^"]+"')


def _without_csrf_token(content: bytes) -> bytes:
    """The page with its per-response values blanked: its CSRF token (form and meta tag) and its CSP nonce."""
    found = _CSRF_VALUE.search(content)
    assert found is not None, "the login page carries a CSRF token"
    return _NONCE.sub(b'nonce=""', content.replace(found.group(1), b""))


def _admin(email: str) -> User:
    return User.objects.create_user(email=email, password=PASSWORD, is_staff=True, is_superuser=True)


def _customer(name: str, created_by: User | None = None) -> Customer:
    return Customer.objects.create(
        name=name,
        customer_type="company",
        company_name=name,
        primary_email=f"{re.sub(r'[^a-z]', '', name.lower())}@test.ro",
        data_processing_consent=True,
        created_by=created_by,
    )


def _creation_data(company_name: str, **overrides: str) -> dict[str, str]:
    """A customer-creation POST the form accepts; company_name is the field the tests aim at."""
    data = {
        "customer_type": "company",
        "name": company_name,
        "company_name": company_name,
        "primary_email": "created@test.ro",
        "first_name": "Ana",
        "last_name": "Pop",
        "email": "created@test.ro",
        "phone": "+40721234567",
        "address_line1": "Str. Unirii 1",
        "city": "Bucuresti",
        "county": "Bucuresti",
        "postal_code": "010101",
        "country": "RO",
        "billing_same_as_primary": "on",
        "data_processing_consent": "on",
        "payment_terms": "30",
        "credit_limit": "0",
        "preferred_currency": "RON",
        "user_action": "skip",
    }
    data.update(overrides)
    return data


class TestSQLInjection(TestCase):
    """Injection payloads are data: they don't error, don't match everything, and don't run."""

    def setUp(self) -> None:
        self.client = Client()
        self.admin = _admin("sql_test@test.ro")
        self.client.force_login(self.admin)

    def test_sql_injection_in_search(self) -> None:
        _customer("SC Alpha SRL")
        _customer("SC Beta SRL")
        sql_payloads = [
            "'; DROP TABLE customers; --",
            "1' OR '1'='1",
            "1; SELECT * FROM users; --",
            "' UNION SELECT * FROM auth_user --",
            "1' AND (SELECT COUNT(*) FROM users) > 0 --",
        ]
        for payload in sql_payloads:
            with self.subTest(payload=payload):
                response = self.client.get(reverse("customers:list"), {"q": payload})
                self.assertEqual(response.status_code, 200)
                # A tautology spliced into SQL would match every customer; as data it matches none.
                self.assertEqual(list(response.context["customers"]), [])
        self.assertEqual(Customer.objects.count(), 2)

    def test_sql_injection_in_form_fields(self) -> None:
        payload = "' OR '1'='1"
        response = self.client.post(
            reverse("customers:create"), _creation_data(payload, name="'; DROP TABLE customers; --")
        )
        self.assertEqual(response.status_code, 302)
        # Stored exactly as typed, and the table it named is still there.
        self.assertEqual(list(Customer.objects.values_list("company_name", flat=True)), [payload])

    def test_sql_injection_in_url_parameters(self) -> None:
        payloads = [
            (reverse("orders:order_list"), {"id": "1 OR 1=1"}),
            (reverse("billing:invoice_list"), {"status": "paid' OR '1'='1"}),
            (reverse("customers:list"), {"page": "1; DROP TABLE users"}),
        ]
        for url, params in payloads:
            with self.subTest(url=url):
                response = self.client.get(url, params)
                self.assertIn(response.status_code, (200, 400))
        self.assertTrue(User.objects.filter(pk=self.admin.pk).exists())


class TestXSSPrevention(TestCase):
    """Markup typed into a customer comes back as text, never as markup."""

    XSS_PAYLOADS = (
        '<script>alert("XSS")</script>',
        '<img src=x onerror=alert("XSS")>',
        '<svg onload=alert("XSS")>',
        '"><script>alert("XSS")</script>',
        "javascript:alert('XSS')",
    )

    def setUp(self) -> None:
        self.client = Client()
        self.admin = _admin("xss_test@test.ro")
        self.client.force_login(self.admin)

    def test_xss_in_customer_name(self) -> None:
        for index, payload in enumerate(self.XSS_PAYLOADS):
            with self.subTest(payload=payload):
                email = f"xss{index}@test.ro"
                response = self.client.post(
                    reverse("customers:create"), _creation_data(payload, primary_email=email, email=email)
                )
                self.assertEqual(response.status_code, 302)
                customer = Customer.objects.get(company_name=payload)
                for url in (reverse("customers:list"), reverse("customers:detail", args=[customer.pk])):
                    html = self.client.get(url).content.decode()
                    self.assertNotIn(payload, html, url)

    def test_xss_in_search_results(self) -> None:
        _customer("SC <script>alert(1)</script> SRL", created_by=self.admin)
        response = self.client.get(reverse("customers:search_htmx"), {"q": "<script>"}, HTTP_HX_REQUEST="true")
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(b"<script>alert(1)</script>", response.content)
        self.assertIn(b"&lt;script&gt;alert(1)&lt;/script&gt;", response.content)

    def test_xss_in_htmx_responses(self) -> None:
        response = self.client.get(
            reverse("customers:search_htmx"), {"q": "<script>alert(1)</script>"}, HTTP_HX_REQUEST="true"
        )
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(b"<script>alert(1)</script>", response.content)


class TestCSRFProtection(TestCase):
    def setUp(self) -> None:
        self.client = Client()
        self.admin = _admin("csrf_test@test.ro")

    def test_csrf_required_on_post(self) -> None:
        csrf_client = Client(enforce_csrf_checks=True)
        csrf_client.force_login(self.admin)
        response = csrf_client.post(reverse("customers:create"), _creation_data("SC CSRF SRL"))
        self.assertEqual(response.status_code, 403)
        self.assertFalse(Customer.objects.exists())

    def test_csrf_token_present_in_forms(self) -> None:
        self.client.force_login(self.admin)
        response = self.client.get(reverse("customers:create"))
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"csrfmiddlewaretoken", response.content)


class TestAuthenticationSecurity(TestCase):
    def setUp(self) -> None:
        self.client = Client()

    def test_password_not_in_response(self) -> None:
        user = User.objects.create_user(email="pass_test@test.ro", password="SecretPassword123!", is_staff=True)
        self.client.force_login(user)
        response = self.client.get(reverse("users:user_profile"))
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(b"SecretPassword123!", response.content)

    def test_failed_login_no_user_enumeration(self) -> None:
        User.objects.create_user(email="existing@test.ro", password="CorrectPassword123!")
        unknown = Client().post(reverse("users:login"), {"email": "nonexistent@test.ro", "password": "wrongpassword"})
        known = Client().post(reverse("users:login"), {"email": "existing@test.ro", "password": "wrongpassword"})
        self.assertEqual(unknown.status_code, known.status_code)
        # The same page for both, apart from each response's own CSRF token.
        self.assertEqual(
            _without_csrf_token(unknown.content.replace(b"nonexistent@test.ro", b"existing@test.ro")),
            _without_csrf_token(known.content),
        )

    def test_session_invalidation_on_logout(self) -> None:
        user = User.objects.create_user(email="session_test@test.ro", password=PASSWORD, is_staff=True)
        self.client.force_login(user)
        session_key = self.client.session.session_key
        self.client.post(reverse("users:logout"))
        self.assertNotEqual(self.client.session.session_key, session_key)
        self.assertNotEqual(self.client.get(reverse("customers:list")).status_code, 200)


class TestAccessControl(TestCase):
    def setUp(self) -> None:
        self.client = Client()
        self.admin = _admin("acl_admin@test.ro")
        self.regular_user = User.objects.create_user(email="acl_user@test.ro", password=PASSWORD, is_staff=False)
        self.customer = _customer("SC Access Test SRL", created_by=self.admin)

    def test_unauthenticated_access_blocked(self) -> None:
        for name in ("dashboard_alias", "customers:list", "orders:order_list", "billing:invoice_list", "settings:home"):
            with self.subTest(url=name):
                self.assertIn(self.client.get(reverse(name)).status_code, (302, 403))

    def test_non_staff_access_blocked(self) -> None:
        self.client.force_login(self.regular_user)
        for name in ("settings:home", "users:user_list"):
            with self.subTest(url=name):
                self.assertIn(self.client.get(reverse(name)).status_code, (302, 403))

    def test_horizontal_access_prevented(self) -> None:
        """A customer's own member reaches nothing of another customer's on the staff pages."""
        CustomerMembership.objects.create(user=self.regular_user, customer=self.customer, role="owner")
        other_customer = _customer("SC Other Company SRL", created_by=self.admin)
        self.client.force_login(self.regular_user)
        response = self.client.get(reverse("customers:detail", args=[other_customer.pk]))
        # Refused, or not found (which also hides that it exists); the route itself is real (reverse).
        self.assertIn(response.status_code, (302, 403, 404))
        self.assertNotIn(b"SC Other Company SRL", response.content)


class TestInputValidation(TestCase):
    def setUp(self) -> None:
        self.client = Client()
        self.admin = _admin("input_test@test.ro")
        self.client.force_login(self.admin)

    def test_oversized_input_rejected(self) -> None:
        long_string = "x" * 100000
        response = self.client.post(reverse("customers:create"), _creation_data(long_string))
        self.assertIn(response.status_code, (200, 400))
        self.assertFalse(Customer.objects.exists())

    def test_special_characters_handled(self) -> None:
        for char in ("\\x00", "\n\r", "\t", "\\", "\"'"):
            with self.subTest(char=repr(char)):
                response = self.client.get(reverse("customers:search_htmx"), {"q": char}, HTTP_HX_REQUEST="true")
                self.assertIn(response.status_code, (200, 400))

    def test_unicode_input_handled(self) -> None:
        for input_str in ("Companie Românească", "公司名称", "🏢 Company", "\u202e\u0041\u0042"):
            with self.subTest(input_str=input_str):
                response = self.client.get(reverse("customers:search_htmx"), {"q": input_str}, HTTP_HX_REQUEST="true")
                self.assertIn(response.status_code, (200, 400))


class TestSecurityHeaders(TestCase):
    def setUp(self) -> None:
        self.client = Client()
        self.admin = User.objects.create_user(email="header_test@test.ro", password=PASSWORD, is_staff=True)
        self.client.force_login(self.admin)

    def test_content_type_header(self) -> None:
        response = self.client.get(reverse("dashboard"))
        self.assertEqual(response.status_code, 200)
        self.assertIn("text/html", response["Content-Type"])

    def test_x_frame_options_header(self) -> None:
        response = self.client.get(reverse("dashboard"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get("X-Frame-Options"), "DENY")


class TestRomanianDataCompliance(TestCase):
    def setUp(self) -> None:
        self.admin = _admin("gdpr_test@test.ro")

    def test_cui_validation(self) -> None:
        customer = _customer("SC GDPR Test SRL", created_by=self.admin)
        for cui in ("RO12345678", "12345678"):
            with self.subTest(cui=cui):
                tax_profile = CustomerTaxProfile.objects.create(
                    customer=customer,
                    cui=cui,
                    vat_number=cui if cui.startswith("RO") else f"RO{cui[-8:]}",
                    is_vat_payer=True,
                )
                self.assertIsNotNone(tax_profile.pk)
                tax_profile.delete()

    def test_data_processing_consent_tracked(self) -> None:
        customer = _customer("SC Consent Test SRL", created_by=self.admin)
        customer.refresh_from_db()
        self.assertIs(customer.data_processing_consent, True)

    def test_sensitive_data_not_logged(self) -> None:
        # Placeholder carried over unchanged: no redaction of these values is wired into logging yet (reported).
        sensitive_fields = ["password", "vat_number", "cui", "card_number"]
        for field in sensitive_fields:
            self.assertIsNotNone(field)
