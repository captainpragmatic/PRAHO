"""A write that read the customer before its erasure cannot bring the person back.

The erasure anonymises an individual customer and marks it with `anonymized_at`, under a lock on
the customer row. A writer that loaded the customer earlier and saves afterwards is refused when
the save would add the person's identity again: a new order, proforma, address or membership, or
an identity field on the customer, an address, a proforma or the tax profile. Saves that touch no
identity (credit, status) and invoice issuance (payment convergence, ADR-0038) are not refused.
"""

from __future__ import annotations

import ast
import inspect
import textwrap
import threading
import time
from datetime import timedelta

from django.db import connection
from django.test import TestCase, TransactionTestCase
from django.utils import timezone

from apps.audit.services import GDPRDeletionService
from apps.billing.invoice_models import Invoice
from apps.billing.proforma_models import ProformaInvoice
from apps.customers.contact_models import CustomerAddress
from apps.customers.credit_service import CustomerCreditService
from apps.customers.customer_models import Customer
from apps.customers.erasure_guard import GUARDED_MODELS, UNGUARDED_SCRUBS, CustomerErasedError
from apps.customers.profile_models import CustomerTaxProfile
from apps.orders.models import Order
from apps.users.models import CustomerMembership, User
from tests.factories.billing_factories import create_currency, create_invoice
from tests.factories.core_factories import create_individual_customer

EMAIL = "ioana.rowe@example.test"


def _make_person() -> tuple[User, Customer]:
    person = User.objects.create_user(email=EMAIL, password="x-pass-123", first_name="Ioana")
    customer = create_individual_customer(first_name="Ioana", last_name="Rowe", email=EMAIL)
    CustomerMembership.objects.create(user=person, customer=customer, role="owner", is_primary=True)
    return person, customer


def _erase(person: User) -> None:
    request = GDPRDeletionService.create_deletion_request(user=person, deletion_type="anonymize").unwrap()
    result = GDPRDeletionService.process_deletion_request(request)
    assert result.is_ok(), result


class StaleWritersAreRefusedTests(TestCase):
    def setUp(self) -> None:
        self.person, self.customer = _make_person()
        # Every instance below is loaded before the erasure, as a slow request would hold it.
        self.stale_customer = Customer.objects.get(pk=self.customer.pk)
        self.stale_address = CustomerAddress.objects.filter(customer=self.customer).first()
        self.currency = create_currency()

    def test_the_erasure_marks_the_customer(self) -> None:
        _erase(self.person)
        self.assertIsNotNone(Customer.all_objects.get(pk=self.customer.pk).anonymized_at)

    def test_a_stale_customer_save_is_refused_and_the_marker_survives(self) -> None:
        _erase(self.person)
        with self.assertRaises(CustomerErasedError):
            self.stale_customer.save()
        row = Customer.all_objects.get(pk=self.customer.pk)
        self.assertIsNotNone(row.anonymized_at)
        self.assertNotIn("ioana", f"{row.name} {row.primary_email}".lower())

    def test_a_stale_order_is_refused_and_nothing_is_written(self) -> None:
        _erase(self.person)
        with self.assertRaises(CustomerErasedError):
            Order.objects.create(
                customer=self.stale_customer,
                currency=self.currency,
                customer_email=EMAIL,
                customer_name="Ioana Rowe",
                billing_address={"address_line1": "Str. Rowe 7", "city": "Cluj-Napoca"},
            )
        self.assertFalse(Order.objects.filter(customer=self.customer).exists())

    def test_a_new_proforma_is_refused(self) -> None:
        _erase(self.person)
        with self.assertRaises(CustomerErasedError):
            ProformaInvoice.objects.create(
                customer=self.stale_customer,
                number="PRO-STALE-1",
                currency=self.currency,
                valid_until=timezone.now() + timedelta(days=30),
                bill_to_name="Ioana Rowe",
                bill_to_email=EMAIL,
            )

    def test_a_proforma_buyer_edit_is_refused_but_a_status_save_is_not(self) -> None:
        proforma = ProformaInvoice.objects.create(
            customer=self.customer,
            number="PRO-EDIT-1",
            currency=self.currency,
            valid_until=timezone.now() + timedelta(days=30),
        )
        stale = ProformaInvoice.objects.get(pk=proforma.pk)
        _erase(self.person)
        stale.bill_to_name = "Ioana Rowe"
        with self.assertRaises(CustomerErasedError):
            stale.save(update_fields=["bill_to_name"])
        fresh = ProformaInvoice.objects.get(pk=proforma.pk)
        fresh.save(update_fields=["status"])  # No identity field: never refused, never locked

    def test_a_stale_address_edit_and_a_new_address_are_refused(self) -> None:
        self.assertIsNotNone(self.stale_address)
        _erase(self.person)
        with self.assertRaises(CustomerErasedError):
            self.stale_address.save()
        with self.assertRaises(CustomerErasedError):
            CustomerAddress.objects.create(
                customer=self.stale_customer, address_line1="Str. Rowe 7", city="Cluj-Napoca", postal_code="400001"
            )

    def test_a_new_member_is_refused(self) -> None:
        other = User.objects.create_user(email="second.owner@example.test", password="x-pass-123")
        _erase(self.person)
        with self.assertRaises(CustomerErasedError):
            CustomerMembership.objects.create(user=other, customer=self.stale_customer, role="owner")

    def test_a_stale_tax_profile_cannot_restore_the_cnp(self) -> None:
        profile, _ = CustomerTaxProfile.objects.get_or_create(customer=self.customer)
        profile.cnp = "1960101123456"
        profile.save()
        stale = CustomerTaxProfile.objects.get(pk=profile.pk)
        _erase(self.person)
        with self.assertRaises(CustomerErasedError):
            stale.save()

    def test_identity_free_saves_and_invoice_issuance_still_work(self) -> None:
        _erase(self.person)
        CustomerCreditService.update_credit_score(self.stale_customer, "positive_payment", timezone.now())
        self.assertIn("credit_score", Customer.all_objects.get(pk=self.customer.pk).meta)
        invoice = create_invoice(self.customer, number="INV-AFTER-ERASURE")  # Payment convergence is never refused
        self.assertTrue(Invoice.objects.filter(pk=invoice.pk).exists())

    def test_a_customer_left_for_staff_is_not_marked(self) -> None:
        other = User.objects.create_user(email="second.owner@example.test", password="x-pass-123")
        CustomerMembership.objects.create(user=other, customer=self.customer, role="owner")
        _erase(self.person)
        self.assertIsNone(Customer.all_objects.get(pk=self.customer.pk).anonymized_at)
        self.stale_customer.save()  # Still someone else's record: nothing refuses it


class EveryScrubHasItsGuardTests(TestCase):
    def test_every_model_the_erasure_scrubs_is_guarded_or_named_exempt(self) -> None:
        """A model the erasure scrubs with a queryset update needs a guard, or a stated reason why not."""
        scrubbed: set[str] = set()
        for function in (
            GDPRDeletionService._anonymize_user_records,
            GDPRDeletionService._anonymize_individual_customers,
        ):
            for node in ast.walk(ast.parse(textwrap.dedent(inspect.getsource(function)))):
                if (
                    isinstance(node, ast.Attribute)
                    and node.attr in {"objects", "all_objects"}
                    and isinstance(node.value, ast.Name)
                    and node.value.id[0].isupper()
                ):
                    scrubbed.add(node.value.id)
        scrubbed -= {"CustomerMembership", "User"}  # Read for ownership and locked, not customer copies
        guarded = {model.__name__ for model in GUARDED_MODELS}
        self.assertEqual(scrubbed - guarded, set(UNGUARDED_SCRUBS))


class ErasureLockTests(TransactionTestCase):
    """On PostgreSQL a writer waits for the erasure's customer lock, then is refused."""

    def test_an_autocommit_writer_waits_for_the_erasure_and_is_then_refused(self) -> None:
        """A save outside any transaction (the proforma edit view's plain save()) still holds the lock."""
        if connection.vendor != "postgresql":
            self.skipTest("row locks need PostgreSQL")
        from django.db import transaction  # noqa: PLC0415

        _person, customer = _make_person()
        proforma = ProformaInvoice.objects.create(
            customer=customer,
            number="PRO-AUTOCOMMIT-1",
            currency=create_currency(),
            valid_until=timezone.now() + timedelta(days=30),
            bill_to_name="Ioana Rowe",
        )
        stale = ProformaInvoice.objects.get(pk=proforma.pk)
        locked = threading.Event()
        outcome: list[str] = []

        def writer() -> None:
            locked.wait(5)
            try:
                stale.save()  # Autocommit: no caller transaction
                outcome.append("saved")
            except CustomerErasedError:
                outcome.append("refused")
            finally:
                connection.close()

        thread = threading.Thread(target=writer)
        thread.start()
        with transaction.atomic():
            list(Customer.all_objects.select_for_update().filter(pk=customer.pk))
            ProformaInvoice.objects.filter(pk=proforma.pk).update(bill_to_name="Anonymized User")
            locked.set()
            time.sleep(0.5)
            Customer.all_objects.filter(pk=customer.pk).update(name="Anonymized User", anonymized_at=timezone.now())
        thread.join(10)
        self.assertEqual(outcome, ["refused"])
        self.assertEqual(ProformaInvoice.objects.get(pk=proforma.pk).bill_to_name, "Anonymized User")

    def test_a_writer_waits_for_the_erasure_and_is_then_refused(self) -> None:
        if connection.vendor != "postgresql":
            self.skipTest("row locks need PostgreSQL")
        from django.db import transaction  # noqa: PLC0415

        person, customer = _make_person()
        stale = Customer.objects.get(pk=customer.pk)
        locked = threading.Event()
        outcome: list[str] = []

        def writer() -> None:
            locked.wait(5)
            try:
                with transaction.atomic():
                    stale.save()
                outcome.append("saved")
            except CustomerErasedError:
                outcome.append("refused")
            finally:
                connection.close()

        thread = threading.Thread(target=writer)
        thread.start()
        with transaction.atomic():
            list(Customer.all_objects.select_for_update().filter(pk=customer.pk))  # The erasure's first lock
            locked.set()
            time.sleep(0.5)
            self.assertEqual(outcome, [], "the writer must wait for the erasure")
            Customer.all_objects.filter(pk=customer.pk).update(name="Anonymized User", anonymized_at=timezone.now())
        thread.join(10)
        self.assertEqual(outcome, ["refused"])
        self.assertIsNotNone(person.pk)
