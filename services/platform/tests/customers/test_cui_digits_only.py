"""A CUI is stored as its digits, whoever writes it, and nothing reads "RO" off it.

An "RO" prefix asserts VAT registration, which a CUI alone does not: a company can hold a CUI
without being a VAT payer. The VAT number (vat_number) carries the prefix, not the CUI.
"""

from unittest.mock import patch

from django import forms
from django.core.exceptions import ValidationError
from django.test import SimpleTestCase, TestCase

from apps.audit.models import ComplianceLog
from apps.audit.services import CustomersAuditService
from apps.common.cui_validator import CUIValidator
from apps.customers.customer_service import CustomerService
from apps.customers.forms import CustomerCreationForm, CustomerEditForm, CustomerTaxProfileForm
from apps.customers.models import Customer, CustomerTaxProfile
from apps.customers.profile_service import ProfileService
from apps.ui.templatetags.formatting import cui_format
from apps.users.models import User

CUI = "14399840"  # a published CUI (Dante International); passes the ANAF check digit
BAD_CHECK_DIGIT = "14399847"


def customer(name: str = "Digits SRL") -> Customer:
    return Customer.objects.create(
        name=name, company_name=name, customer_type="company", primary_email="digits@example.test", status="active"
    )


class StoredCUITests(TestCase):
    def test_every_spelling_is_stored_as_digits(self) -> None:
        for index, written in enumerate((f"RO{CUI}", f"ro{CUI}", f" RO{CUI} ", CUI)):
            with self.subTest(written=written):
                profile = CustomerTaxProfile.objects.create(customer=customer(f"Digits {index} SRL"), cui=written)
                profile.refresh_from_db()
                self.assertEqual(profile.cui, CUI)

    def test_a_save_limited_to_the_cui_field_still_stores_digits(self) -> None:
        profile = CustomerTaxProfile.objects.create(customer=customer())
        profile.cui = f"RO{CUI}"
        profile.save(update_fields=["cui"])
        profile.refresh_from_db()
        self.assertEqual(profile.cui, CUI)

    def test_the_profile_service_stores_digits(self) -> None:
        staff = User.objects.create_user(email="staff@example.test", password="Staff-only-2026!", is_staff=True)
        profile = CustomerTaxProfile.objects.create(customer=customer())
        ProfileService.update_tax_profile(profile, staff, cui=f"RO{CUI}")
        profile.refresh_from_db()
        self.assertEqual(profile.cui, CUI)

    def test_a_digits_cui_is_a_romanian_registration(self) -> None:
        profile = CustomerTaxProfile.objects.create(customer=customer(), cui=CUI)
        self.assertTrue(
            ComplianceLog.objects.filter(compliance_type="romanian_tax_registration", reference_id=CUI).exists()
        )
        event = CustomersAuditService.log_tax_profile_event("customer_tax_profile_updated", profile)
        self.assertTrue(event.metadata["is_romanian_entity"])

    def test_a_foreign_tax_id_is_left_as_entered_and_is_not_romanian(self) -> None:
        profile = CustomerTaxProfile.objects.create(customer=customer(), cui="DE999999999")
        profile.refresh_from_db()
        self.assertEqual(profile.cui, "DE999999999")
        event = CustomersAuditService.log_tax_profile_event("customer_tax_profile_updated", profile)
        self.assertFalse(event.metadata["is_romanian_entity"])

    def test_staff_search_finds_a_cui_typed_with_or_without_ro(self) -> None:
        staff = User.objects.create_user(
            email="search@example.test", password="Staff-only-2026!", is_staff=True, staff_role="admin"
        )
        found = customer()
        CustomerTaxProfile.objects.create(customer=found, cui=CUI)
        for query in (CUI, f"RO{CUI}", f"ro{CUI}"):
            with self.subTest(query=query):
                self.assertIn(found, CustomerService.search_customers(query, staff))


class CUIFormTests(SimpleTestCase):
    FORMS = (CustomerTaxProfileForm, CustomerCreationForm, CustomerEditForm)

    def clean_cui(self, form_class: type, value: str) -> str:
        form = form_class.__new__(form_class)
        form.cleaned_data = {"cui": value}
        return form.clean_cui()

    def test_staff_forms_take_the_cui_with_or_without_ro_and_return_digits(self) -> None:
        for form_class in self.FORMS:
            for value in (CUI, f"RO{CUI}"):
                with self.subTest(form=form_class.__name__, value=value):
                    self.assertEqual(self.clean_cui(form_class, value), CUI)

    def test_staff_forms_refuse_a_bad_check_digit(self) -> None:
        for form_class in self.FORMS:
            with self.subTest(form=form_class.__name__), self.assertRaises(ValidationError):
                self.clean_cui(form_class, BAD_CHECK_DIGIT)


class CUIFormValidityTests(TestCase):
    """Through each form's whole validation, not just clean_cui."""

    def test_the_tax_profile_form_accepts_digits_and_stores_them(self) -> None:
        for value in (CUI, f"RO{CUI}"):
            with self.subTest(value=value):
                form = CustomerTaxProfileForm(data={
                    "cui": value, "registration_number": "J40/1234/2020", "is_vat_payer": False,
                    "vat_rate": 21, "reverse_charge_eligible": False,
                })
                self.assertTrue(form.is_valid(), form.errors)
                self.assertEqual(form.cleaned_data["cui"], CUI)

    def test_the_creation_form_no_longer_demands_an_ro_prefix(self) -> None:
        form = CustomerCreationForm.__new__(CustomerCreationForm)
        form.cleaned_data = {"customer_type": "company", "company_name": "Digits SRL", "cui": CUI}
        # Only the form's own clean(), with Django's base clean() returning the data as is.
        with patch.object(forms.Form, "clean", lambda self: self.cleaned_data):
            self.assertEqual(form.clean()["cui"], CUI)


class OrderSnapshotTests(TestCase):
    """A staff order's buyer VAT ID is the VAT number, never the CUI."""

    def test_staff_orders_do_not_carry_a_cui_as_the_vat_id(self) -> None:
        from django.urls import reverse  # noqa: PLC0415

        from tests.orders.test_staff_selling_currency import StaffSellingCurrencyTests  # noqa: PLC0415

        case = StaffSellingCurrencyTests(methodName="setUp")
        case.client = self.client
        case.setUp()
        CustomerTaxProfile.objects.create(customer=case.customer, cui=CUI, is_vat_payer=True)
        for view in ("orders:order_create", "orders:order_create_with_item"):
            with self.subTest(view=view):
                policy = case.switch("RON")
                response = self.client.post(reverse(view), case.order_payload("RON", policy.revision))
                self.assertEqual(response.status_code, 302)
                order = case.customer.orders.order_by("-created_at").first()
                self.assertEqual(order.customer_vat_id, "")
                self.assertEqual(order.billing_address.get("vat_id", ""), "")


class CUIDisplayAndValidationTests(SimpleTestCase):
    def test_display_does_not_add_a_vat_prefix(self) -> None:
        self.assertEqual(cui_format(CUI), CUI)
        self.assertEqual(cui_format(f"RO{CUI}"), CUI)

    def test_an_all_digit_foreign_number_longer_than_a_cui_is_not_romanian(self) -> None:
        from apps.common.cui_validator import is_romanian_cui  # noqa: PLC0415

        self.assertTrue(is_romanian_cui(CUI))
        self.assertTrue(is_romanian_cui(f"RO{CUI}"))
        self.assertFalse(is_romanian_cui("1234567890123"))  # e.g. a 13-digit foreign company number

    def test_the_one_normaliser_returns_digits(self) -> None:
        self.assertEqual(CUIValidator.normalize(f"ro{CUI}"), CUI)


class CUIFollowUpTests(TestCase):
    def test_a_partial_save_stores_the_normalised_cui_it_reports(self) -> None:
        customer = Customer.objects.create(name="Legacy SRL", customer_type="company", status="active")
        profile = CustomerTaxProfile.objects.create(customer=customer, cui="14399840")
        CustomerTaxProfile.objects.filter(pk=profile.pk).update(cui="RO14399840")  # Written before #665
        profile.refresh_from_db()
        profile.is_vat_payer = False
        profile.save(update_fields=["is_vat_payer"])
        self.assertEqual(CustomerTaxProfile.objects.values_list("cui", flat=True).get(pk=profile.pk), "14399840")
