"""A registration request does the same work, and answers the same, whatever already exists."""

from django.core.cache import cache
from django.db import connection
from django.test import TestCase, override_settings
from django.test.utils import CaptureQueriesContext

from apps.customers.models import Customer, CustomerTaxProfile
from apps.users.models import User
from apps.users.pending_registration import PendingRegistration
from tests.helpers.hmac import HMAC_TEST_MIDDLEWARE, HMAC_TEST_SECRET, HMACTestMixin

LOOKED_UP_TABLES = (User._meta.db_table, Customer._meta.db_table, CustomerTaxProfile._meta.db_table)


def registration(email: str, company: str, vat: str) -> dict[str, object]:
    return {
        "user_data": {"email": email, "first_name": "Ana", "last_name": "Pop", "phone": ""},
        "customer_data": {
            "customer_type": "company",
            "company_name": company,
            "vat_number": vat,
            "address_line1": "Str. Victoriei 10",
            "city": "București",
            "postal_code": "010061",
            "data_processing_consent": True,
        },
    }


@override_settings(
    PLATFORM_API_SECRET=HMAC_TEST_SECRET,
    MIDDLEWARE=HMAC_TEST_MIDDLEWARE,
    HMAC_ALLOW_LEGACY_SECRET=True,
)
class RegistrationUniformAnswerTests(HMACTestMixin, TestCase):
    def setUp(self) -> None:
        cache.clear()
        owner = User.objects.create_user(email="taken@example.test", password="Existing-password-2026!")
        customer = Customer.objects.create(
            name="Taken SRL", company_name="Taken SRL", customer_type="company",
            primary_email=owner.email, status="active",
        )
        CustomerTaxProfile.objects.create(customer=customer, vat_number="RO14399847")

    def submit(self, data: dict[str, object]) -> tuple[int, object, int, list[str]]:
        with CaptureQueriesContext(connection) as queries:
            response = self.portal_post("/api/customers/register/", data)
        looked_up = [q["sql"] for q in queries if any(f'"{table}"' in q["sql"] for table in LOOKED_UP_TABLES)]
        return response.status_code, response.json(), len(queries), looked_up

    def test_existing_and_new_details_get_the_same_answer_and_work(self) -> None:
        self.submit(registration("warm-up@example.test", "Warm Up SRL", ""))
        cases = {
            "new everything": registration("new@example.test", "New SRL", "RO18547290"),
            "taken email": registration("TAKEN@example.test", "Other SRL", ""),
            "taken company": registration("other@example.test", "taken srl", ""),
            "taken VAT": registration("third@example.test", "Third SRL", "RO14399847"),
        }
        observed = {name: self.submit(data) for name, data in cases.items()}
        for name, (_status, _body, _count, looked_up) in observed.items():
            self.assertEqual(looked_up, [], f"{name}: the request looked up existing accounts")
        answers = {(status, str(body), count) for status, body, count, _ in observed.values()}
        self.assertEqual(len(answers), 1, observed)
        self.assertEqual(next(iter(answers))[0], 202)
        self.assertEqual(PendingRegistration.objects.count(), 5)
