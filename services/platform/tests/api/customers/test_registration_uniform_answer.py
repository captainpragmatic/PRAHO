"""A registration request does the same work, and answers the same, whatever already exists."""

from unittest.mock import patch

from django.core.cache import cache
from django.db import connection
from django.test import TestCase, override_settings
from django.test.utils import CaptureQueriesContext

from apps.customers.models import Customer, CustomerTaxProfile
from apps.users.models import User
from apps.users.pending_registration import PendingRegistration
from tests.helpers.hmac import HMAC_TEST_MIDDLEWARE, HMAC_TEST_SECRET, HMACTestMixin
from tests.helpers.legal import publish_release

LOOKED_UP_TABLES = (User._meta.db_table, Customer._meta.db_table, CustomerTaxProfile._meta.db_table)


TAKEN_CNP = "1900101123457"
TAKEN_CUI = "18189442"


def registration(email: str, company: str, vat: str, **customer: object) -> dict[str, object]:
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
            # A Romanian company gives a VAT number or a CUI.
            **({} if vat else {"cui": "18547290"}),
            **customer,
        },
    }


def individual(email: str, cnp: str) -> dict[str, object]:
    return registration(email, "Ana Pop", "", customer_type="individual", country="RO", cnp=cnp)


@override_settings(
    PLATFORM_API_SECRET=HMAC_TEST_SECRET,
    MIDDLEWARE=HMAC_TEST_MIDDLEWARE,
    HMAC_ALLOW_LEGACY_SECRET=True,
)
class RegistrationUniformAnswerTests(HMACTestMixin, TestCase):
    @classmethod
    def setUpTestData(cls) -> None:
        publish_release()  # Registration needs Terms of Service in force

    def setUp(self) -> None:
        cache.clear()
        owner = User.objects.create_user(email="taken@example.test", password="Existing-password-2026!")
        customer = Customer.objects.create(
            name="Taken SRL", company_name="Taken SRL", customer_type="company",
            primary_email=owner.email, status="active",
        )
        CustomerTaxProfile.objects.create(customer=customer, vat_number="RO14399840", cui=TAKEN_CUI)
        person = Customer.objects.create(
            name="Ion Popescu", customer_type="individual", primary_email="ion@example.test", status="active"
        )
        CustomerTaxProfile.objects.create(customer=person, cnp=TAKEN_CNP)

    def submit(self, data: dict[str, object]) -> tuple[int, object, int, list[str]]:
        with CaptureQueriesContext(connection) as queries:
            response = self.portal_post("/api/customers/register/", data)
        looked_up = [q["sql"] for q in queries if any(f'"{table}"' in q["sql"] for table in LOOKED_UP_TABLES)]
        return response.status_code, response.json(), len(queries), looked_up

    def test_existing_and_new_details_get_the_same_answer_and_work(self) -> None:
        # The counter store deletes expired rows on 1 write in 200, at random and whatever was
        # submitted: hold that still so the counts compare only what depends on the submission.
        self.enterContext(patch("apps.common.counters.randbelow", return_value=1))
        self.submit(registration("warm-up@example.test", "Warm Up SRL", ""))
        cases = {
            "new everything": registration("new@example.test", "New SRL", "RO18547290"),
            "taken email": registration("TAKEN@example.test", "Other SRL", ""),
            "taken company": registration("other@example.test", "taken srl", ""),
            "taken VAT": registration("third@example.test", "Third SRL", "RO14399840"),
        }
        observed = {name: self.submit(data) for name, data in cases.items()}
        for name, (_status, _body, _count, looked_up) in observed.items():
            self.assertEqual(looked_up, [], f"{name}: the request looked up existing accounts")
        answers = {(status, str(body), count) for status, body, count, _ in observed.values()}
        self.assertEqual(len(answers), 1, observed)
        self.assertEqual(next(iter(answers))[0], 202)
        self.assertEqual(PendingRegistration.objects.count(), 5)

    def assert_uniform(self, warm_up: dict[str, object], cases: dict[str, dict[str, object]]) -> None:
        # Compared within one customer type: an individual's country is resolved and a company's
        # is not, which depends on what was submitted, not on what exists.
        self.enterContext(patch("apps.common.counters.randbelow", return_value=1))
        self.submit(warm_up)
        observed = {name: self.submit(data) for name, data in cases.items()}
        for name, (_status, _body, _count, looked_up) in observed.items():
            self.assertEqual(looked_up, [], f"{name}: the request looked up existing accounts")
        answers = {(status, str(body), count) for status, body, count, _ in observed.values()}
        self.assertEqual(len(answers), 1, observed)
        self.assertEqual(next(iter(answers))[0], 202)
        self.assertEqual(PendingRegistration.objects.count(), 1 + len(cases))

    def test_a_taken_cui_gets_the_same_answer_and_works(self) -> None:
        self.assert_uniform(
            registration("warm-up@example.test", "Warm Up SRL", "", cui="14399840"),
            {
                "new CUI": registration("new@example.test", "New SRL", "", cui="18547290"),
                "taken CUI": registration("other@example.test", "Other SRL", "", cui=TAKEN_CUI),
            },
        )

    def test_a_taken_cnp_gets_the_same_answer_and_works(self) -> None:
        self.assert_uniform(
            individual("warm-up@example.test", "2900505123403"),
            {
                "new CNP": individual("person@example.test", "6000101123459"),
                "taken CNP": individual("taken-cnp@example.test", TAKEN_CNP),
            },
        )

    def test_the_submitted_language_is_kept_for_the_mail(self) -> None:
        response = self.portal_post(
            "/api/customers/register/", {**registration("ro@example.test", "Limba SRL", ""), "language": "ro"}
        )
        self.assertEqual(response.status_code, 202, response.content)
        self.assertEqual(PendingRegistration.objects.get(email="ro@example.test").language, "ro")
