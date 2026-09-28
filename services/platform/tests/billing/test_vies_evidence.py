"""Exercise evidence policy through document, task and reporting services."""

from __future__ import annotations

from datetime import timedelta
from decimal import Decimal
from io import StringIO
from unittest.mock import patch

from django.core.cache import cache
from django.core.management import call_command
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from apps.audit.models import AuditEvent
from apps.billing.ec_sales_service import ReportingPeriod, aggregate_ec_services
from apps.billing.gateways.vies_gateway import VIESResponse
from apps.billing.invoice_models import Invoice
from apps.billing.models import Currency
from apps.billing.services import InvoiceService, _build_customer_vat_info
from apps.billing.tasks import reverify_expired_vat_validations, validate_vat_number
from apps.billing.tax_models import VATValidation
from apps.billing.vies_evidence import normalize_vat_number, vat_number_matches_country, vies_refusal_reason
from apps.common.tax_service import CustomerVATInfo, TaxService, VATScenario
from apps.customers.models import Customer, CustomerAddress, CustomerTaxProfile
from apps.orders.models import Order, OrderItem
from apps.products.models import Product
from apps.settings.models import SystemSetting
from tests.factories.core_factories import create_staff_user


class VIESEvidenceTests(TestCase):
    def _profile(self, *, vat_number: str, vies_verification_status: str) -> CustomerTaxProfile:
        return CustomerTaxProfile(
            customer=Customer(name="Evidence GmbH"),
            vat_number=vat_number,
            vies_verification_status=vies_verification_status,
            vies_verified_at=timezone.now(),
            vies_consultation_reference="test-reference",
        )

    def _verified(self, profile: CustomerTaxProfile | None, number: object) -> bool:
        return vies_refusal_reason(profile, number, billing_name="Evidence GmbH") == ""

    def test_valid_matching_number(self) -> None:
        profile = self._profile(vat_number="DE123456789", vies_verification_status="valid")
        self.assertTrue(self._verified(profile, "DE123456789"))

    def test_valid_different_number(self) -> None:
        profile = self._profile(vat_number="DE123456789", vies_verification_status="valid")
        self.assertFalse(self._verified(profile, "DE999999999"))

    def test_unconfirmed_statuses(self) -> None:
        for status in ("format_only", "pending", "invalid", "not_applicable"):
            with self.subTest(status=status):
                profile = self._profile(vat_number="DE123456789", vies_verification_status=status)
                self.assertFalse(self._verified(profile, "DE123456789"))

    def test_separators_and_case_are_ignored(self) -> None:
        profile = self._profile(vat_number="de 123-456.789", vies_verification_status="valid")
        self.assertTrue(self._verified(profile, "DE123456789"))

    def test_other_separators_do_not_match_evidence(self) -> None:
        for separator in ("/", "\t", "\n", "_"):
            with self.subTest(separator=repr(separator)):
                number = f"DE123{separator}456789"
                self.assertEqual(normalize_vat_number(number), number)
                profile = self._profile(vat_number=number, vies_verification_status="valid")
                self.assertFalse(self._verified(profile, "DE123456789"))

    def test_number_issuing_country_matches_billing_country(self) -> None:
        for number, country, expected in (
            ("RO18189442", "DE", False),
            ("DE136695976", "DE", True),
            ("EL094259216", "GR", True),
            ("GR094259216", "EL", True),
            ("123456789B01", "NL", True),
            ("de 136-695.976", "de", True),
            ("", "DE", False),
            (None, "DE", False),
            ("DE136695976", "", False),
        ):
            with self.subTest(number=number, country=country):
                self.assertEqual(vat_number_matches_country(number, country), expected)

    def test_none_profile(self) -> None:
        self.assertFalse(self._verified(None, "DE123456789"))

    def test_empty_normalized_number_is_not_evidence(self) -> None:
        profile = self._profile(vat_number="---", vies_verification_status="valid")
        self.assertFalse(self._verified(profile, ""))
        for value in (None, False, 0, ""):
            self.assertEqual(normalize_vat_number(value), "")


@override_settings(COMPANY_COUNTRY_CODE="RO", COMPANY_CUI="RO16397040")
class VATEvidenceHardeningTests(TestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        self.customer = Customer.objects.create(
            name="Evidence GmbH", company_name="Evidence GmbH", customer_type="company",
            primary_email="hardening@example.test", status="active",
        )
        CustomerAddress.objects.create(
            customer=self.customer, is_billing=True, is_current=True,
            country="DE", city="Berlin", address_line1="Teststrasse 1",
        )
        self.profile = CustomerTaxProfile.objects.create(
            customer=self.customer, vat_number="DE136695976", is_vat_payer=True,
            vies_verification_status="valid", vies_verified_at=timezone.now(),
            vies_consultation_reference="original-reference", vies_verified_name="Evidence GmbH",
        )
        self.validation = VATValidation.objects.create(
            country_code="DE", vat_number="136695976", full_vat_number="DE136695976",
            is_valid=True, is_active=True, validation_source="vies",
            consultation_reference="original-reference", company_name="Evidence GmbH",
            validation_date=timezone.now() - timedelta(hours=1),
            expires_at=timezone.now() + timedelta(hours=23),
        )
        self.currency, _ = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei"})
        self.product = Product.objects.create(
            name="Hosting", slug="evidence-hardening", product_type="shared_hosting",
        )

    def _setting(self, key: str, value: bool | int) -> None:
        SystemSetting.objects.update_or_create(
            key=key,
            defaults={
                "value": value, "default_value": value,
                "data_type": "boolean" if isinstance(value, bool) else "integer",
                "name": key, "is_active": True,
            },
        )
        cache.clear()

    def _invoice(self, billing_name: str = "Evidence GmbH") -> Invoice:
        order = Order.objects.create(
            customer=Customer.objects.get(pk=self.customer.pk), currency=self.currency,
            customer_name=billing_name, customer_email=self.customer.primary_email,
            subtotal_cents=10000, tax_cents=0, total_cents=10000,
            billing_address={
                "country": "DE", "company_name": billing_name, "vat_number": "DE136695976",
                "address_line1": "Teststrasse 1", "city": "Berlin", "postal_code": "10115",
            },
        )
        OrderItem.objects.create(
            order=order, product=self.product, product_name="Hosting", product_type="shared_hosting",
            quantity=1, unit_price_cents=10000, tax_rate=0, tax_cents=0, line_total_cents=10000,
        )
        result = InvoiceService().create_from_order(order)
        self.assertTrue(result.is_ok(), result)
        return result.unwrap()

    def _assert_refused(self, reason: str) -> None:
        invoice = self._invoice()
        self.assertEqual(invoice.vat_evidence["scenario"], VATScenario.EU_B2C.value)
        self.assertEqual(invoice.tax_cents, int(Decimal(10000) * TaxService.get_vat_rate("DE") / 100))
        event = AuditEvent.objects.filter(action="vies_evidence_refused").latest("timestamp")
        self.assertEqual(event.metadata["reason"], reason)
        self.assertEqual(event.metadata["customer_id"], str(self.customer.pk))
        self.assertEqual(event.metadata["vat_number"], "DE136695976")

    def test_stale_verification_refuses_document_and_records_reason(self) -> None:
        CustomerTaxProfile.objects.filter(pk=self.profile.pk).update(
            vies_verified_at=timezone.now() - timedelta(days=31)
        )
        self._assert_refused("stale_evidence")

    def test_null_verification_refuses_document_and_records_reason(self) -> None:
        CustomerTaxProfile.objects.filter(pk=self.profile.pk).update(vies_verified_at=None)
        self._assert_refused("missing_timestamp")

    def test_reference_policy_on_refuses_and_off_allows(self) -> None:
        CustomerTaxProfile.objects.filter(pk=self.profile.pk).update(vies_consultation_reference="")
        self._assert_refused("missing_consultation_reference")
        self._setting("billing.reverse_charge_requires_consultation_reference", False)
        self.assertEqual(self._invoice().vat_evidence["category"], "AE")

    def test_name_normalization_and_distinctive_subset_use_invoice_identity(self) -> None:
        cases = (
            ("", "Zeta", True), ("---", "Zeta", True), ("-", "Zeta", True), ("n/a", "Zeta", True),
            ("Evidence GmbH", "EVIDENCE G.m.b.H.", True),
            ("Acme Trading GmbH", "Zeta Trading GmbH", False),
            ("Acme Europe GmbH", "Zeta Europe GmbH", False),
            ("Acme Europe GmbH", "Acme", True),
            ("Acme", "Acme Hosting", False),
            ("Acme SRL", "Zeta", False),
            ("Services GmbH", "Zeta", True),
            ("Évidence GmbH", "Evidence", True),
            ("A & B Consulting SRL", "A and B Consulting SRL", True),
            ("A and B Consulting SRL", "A & B Consulting SRL", True),
            ("ACME SRL", "Acme S. R. L.", True),
            ("Novak s.r.o.", "NOVAK S.R.O.", True),
            ("Firma d.o.o.", "Firma", True),
            ("Balti UAB", "Balti", True),
        )
        for verified, invoiced, allowed in cases:
            with self.subTest(verified=verified, invoiced=invoiced):
                CustomerTaxProfile.objects.filter(pk=self.profile.pk).update(vies_verified_name=verified)
                invoice = self._invoice(invoiced)
                self.assertEqual(invoice.vat_evidence["category"], "AE" if allowed else "S")
                self.assertEqual(invoice.bill_to_name, invoiced)

    def test_name_policy_off_skips_mismatch(self) -> None:
        self._setting("billing.reverse_charge_requires_name_match", False)
        self.assertEqual(self._invoice("Zeta GmbH").vat_evidence["category"], "AE")

    def test_twenty_five_hour_evidence_is_entitled_and_clean_in_d390(self) -> None:
        verified_at = timezone.now() - timedelta(hours=25)
        CustomerTaxProfile.objects.filter(pk=self.profile.pk).update(vies_verified_at=verified_at)
        VATValidation.objects.filter(pk=self.validation.pk).update(
            validation_date=verified_at, expires_at=verified_at + timedelta(hours=24),
        )
        invoice = self._invoice()
        self.assertEqual(invoice.vat_evidence["version"], 2)
        self.assertEqual(invoice.vat_evidence["evidence_max_age_days"], 30)
        self.assertEqual(invoice.vat_evidence["category"], "AE")
        invoice.issue()
        invoice.save()
        period = ReportingPeriod(invoice.tax_point_date.year, invoice.tax_point_date.month)
        report = aggregate_ec_services(period)
        self.assertTrue(report.can_export, report.exceptions)
        self.assertEqual(len(report.contributions), 1)

    def test_thirty_one_day_evidence_is_neither_entitled_nor_clean_in_d390(self) -> None:
        verified_at = timezone.now() - timedelta(days=31)
        CustomerTaxProfile.objects.filter(pk=self.profile.pk).update(vies_verified_at=verified_at)
        self.assertEqual(self._invoice().vat_evidence["category"], "S")
        CustomerTaxProfile.objects.filter(pk=self.profile.pk).update(vies_verified_at=timezone.now())
        VATValidation.objects.filter(pk=self.validation.pk).update(
            validation_date=verified_at, expires_at=timezone.now() + timedelta(days=1),
        )
        invoice = self._invoice()
        invoice.issue()
        invoice.save()
        report = aggregate_ec_services(ReportingPeriod(invoice.tax_point_date.year, invoice.tax_point_date.month))
        self.assertFalse(report.can_export)
        self.assertTrue(any("conflicting_vat_validation" in item.codes for item in report.exceptions))

    def test_d390_absent_snapshot_is_not_a_missing_reference(self) -> None:
        """No cache row at capture time is the version-1 'not recorded' shape, not a policy failure."""
        invoice = self._invoice()
        invoice.vat_evidence["vies"] = None
        invoice.issue()
        invoice.save()
        report = aggregate_ec_services(ReportingPeriod(invoice.tax_point_date.year, invoice.tax_point_date.month))
        codes = {code for item in report.exceptions for code in item.codes}
        self.assertNotIn("missing_consultation_reference", codes)

    def test_d390_requires_reference_only_for_version_two_ae(self) -> None:
        for version, blocked in ((1, False), (2, True)):
            with self.subTest(version=version):
                invoice = self._invoice()
                invoice.vat_evidence["version"] = version
                invoice.vat_evidence["vies"].pop("consultation_reference")
                invoice.vat_evidence.pop("evidence_max_age_days")
                invoice.issue()
                invoice.save()
                period = ReportingPeriod(invoice.tax_point_date.year, invoice.tax_point_date.month)
                report = aggregate_ec_services(period)
                codes = {code for item in report.exceptions for code in item.codes}
                self.assertEqual("missing_consultation_reference" in codes, blocked)
                self.assertEqual(report.can_export, not blocked)

    def test_new_response_replaces_reference_name_and_timestamp_together(self) -> None:
        response = VIESResponse(
            is_valid=True, country_code="DE", vat_number="136695976",
            company_name="New Evidence GmbH", request_identifier="new-reference",
        )
        with patch("apps.billing.gateways.vies_gateway.VIESGateway.check_vat", return_value=response):
            result = validate_vat_number(str(self.profile.pk))
        self.assertTrue(result["success"], result)
        self.profile.refresh_from_db()
        self.validation.refresh_from_db()
        self.assertEqual(self.profile.vies_verification_status, "valid")
        self.assertEqual(self.profile.vies_consultation_reference, "new-reference")
        self.assertEqual(self.validation.consultation_reference, "new-reference")
        self.assertEqual(self.profile.vies_verified_name, "New Evidence GmbH")
        self.assertEqual(self.profile.vies_verified_at, self.validation.validation_date)

    def test_valid_response_without_identifier_is_format_only_and_keeps_prior_proof(self) -> None:
        verified_at = self.profile.vies_verified_at
        response = VIESResponse(is_valid=True, country_code="DE", vat_number="136695976", company_name="New GmbH")
        with patch("apps.billing.gateways.vies_gateway.VIESGateway.check_vat", return_value=response):
            result = validate_vat_number(str(self.profile.pk))
        self.assertTrue(result["success"], result)
        self.profile.refresh_from_db()
        self.validation.refresh_from_db()
        self.assertEqual(self.profile.vies_verification_status, "format_only")
        self.assertFalse(self.profile.reverse_charge_eligible)
        self.assertEqual(self.profile.vies_verified_at, verified_at)
        self.assertEqual(self.profile.vies_consultation_reference, "original-reference")
        self.assertEqual(self.profile.vies_verified_name, "Evidence GmbH")
        self.assertEqual(self.validation.consultation_reference, "")
        self.assertFalse(self.validation.is_valid)
        self.assertEqual(self._invoice().vat_evidence["category"], "S")

    def test_configured_outage_grace_revokes_evidence_outside_the_window(self) -> None:
        self._setting("billing.vies_outage_grace_days", 2)
        CustomerTaxProfile.objects.filter(pk=self.profile.pk).update(
            vies_verified_at=timezone.now() - timedelta(days=3)
        )
        response = VIESResponse(is_valid=False, country_code="DE", vat_number="136695976", api_available=False)
        with patch("apps.billing.gateways.vies_gateway.VIESGateway.check_vat", return_value=response):
            result = validate_vat_number(str(self.profile.pk))
        self.assertTrue(result["success"], result)
        self.profile.refresh_from_db()
        self.validation.refresh_from_db()
        self.assertEqual(self.profile.vies_verification_status, "format_only")
        self.assertEqual(self.profile.vies_consultation_reference, "")
        self.assertEqual(self.validation.consultation_reference, "")

    def test_refusals_are_visible_on_staff_tax_page(self) -> None:
        CustomerTaxProfile.objects.filter(pk=self.profile.pk).update(vies_consultation_reference="")
        self._assert_refused("missing_consultation_reference")
        self.client.force_login(create_staff_user(staff_role="admin"))
        response = self.client.get(reverse("customers:tax_profile", args=[self.customer.pk]))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "missing_consultation_reference")
        self.assertContains(response, "DE136695976")
        self.assertContains(response, "Evidence GmbH")

    def test_sweep_and_command_enqueue_missing_evidence_without_expired_rows(self) -> None:
        queued: set[str] = set()

        def record(_task: str, profile_id: str) -> str:
            queued.add(profile_id)
            return profile_id

        for label in ("timestamp", "reference", "stale", "row"):
            with self.subTest(label=label):
                CustomerTaxProfile.objects.filter(pk=self.profile.pk).update(
                    vies_verified_at=None if label == "timestamp" else timezone.now() - timedelta(
                        days=31 if label == "stale" else 0
                    ),
                    vies_consultation_reference="" if label == "reference" else "reference",
                )
                if label == "row":
                    VATValidation.objects.filter(pk=self.validation.pk).delete()
                queued.clear()
                with patch("apps.billing.tasks.async_task", side_effect=record):
                    result = reverify_expired_vat_validations()
                self.assertTrue(result["success"])
                self.assertEqual(queued, {str(self.profile.pk)})
                queued.clear()
                with patch("django_q.tasks.async_task", side_effect=record):
                    call_command("validate_vat_numbers", stdout=StringIO())
                self.assertEqual(queued, {str(self.profile.pk)})

    def test_command_reports_valid_profile_name_reference_and_timestamp_problems(self) -> None:
        for field, value, reason in (
            ("vies_verified_name", "Zeta GmbH", "name_mismatch"),
            ("vies_consultation_reference", "", "missing_consultation_reference"),
            ("vies_verified_at", None, "missing_timestamp"),
        ):
            with self.subTest(reason=reason):
                CustomerTaxProfile.objects.filter(pk=self.profile.pk).update(
                    vies_verified_name="Evidence GmbH", vies_consultation_reference="reference",
                    vies_verified_at=timezone.now(),
                )
                CustomerTaxProfile.objects.filter(pk=self.profile.pk).update(**{field: value})
                output = StringIO()
                with patch("django_q.tasks.async_task", return_value="queued"):
                    call_command("validate_vat_numbers", "--blocked-orders", stdout=output)
                self.assertIn(f"Blocked profile {self.profile.pk}: {reason}", output.getvalue())

    def test_command_lists_zero_overrides_without_a_reason_and_records_nothing(self) -> None:
        CustomerTaxProfile.objects.filter(pk=self.profile.pk).update(
            vat_rate=0, vat_rate_reason="", vies_verification_status="pending", vies_consultation_reference=""
        )
        output = StringIO()
        with patch("django_q.tasks.async_task", return_value="queued"):
            call_command("validate_vat_numbers", "--blocked-orders", stdout=output)
        self.assertIn(f"Zero override without a reason: profile {self.profile.pk} (DE)", output.getvalue())
        self.assertFalse(AuditEvent.objects.filter(action="vies_evidence_refused").exists())

    def test_exemption_reason_reaches_resolver_from_profile(self) -> None:
        CustomerTaxProfile.objects.filter(pk=self.profile.pk).update(
            vat_rate=0, vat_rate_reason="diplomatic", vies_verification_status="pending",
        )
        info = _build_customer_vat_info(Customer.objects.get(pk=self.customer.pk), country="DE")
        result = TaxService.calculate_vat_for_document(10000, info)
        self.assertEqual(result.scenario, VATScenario.CUSTOM_RATE_OVERRIDE)
        self.assertIn("diplomatic", result.reasoning)
        self.assertEqual(result.notes, ["custom rate exemption reason: diplomatic"])


@override_settings(COMPANY_COUNTRY_CODE="RO")
class ZeroOverrideHardeningTests(TestCase):
    def test_cross_border_zero_override_requires_evidence_or_reason(self) -> None:
        for country, vat_number, verified, reason, expected in (
            ("DE", "DE136695976", False, "", VATScenario.EU_B2C),
            ("DE", "DE136695976", True, "", VATScenario.CUSTOM_RATE_OVERRIDE),
            ("DE", "DE136695976", False, "diplomatic", VATScenario.CUSTOM_RATE_OVERRIDE),
            ("DE", "DE136695976", False, "exempt_body", VATScenario.CUSTOM_RATE_OVERRIDE),
            ("DE", "DE136695976", False, "other", VATScenario.CUSTOM_RATE_OVERRIDE),
            ("DE", "RO18189442", False, "", VATScenario.CUSTOM_RATE_OVERRIDE),
            ("RO", "RO18189442", False, "", VATScenario.CUSTOM_RATE_OVERRIDE),
        ):
            with self.subTest(country=country, vat_number=vat_number, verified=verified, reason=reason):
                info: CustomerVATInfo = {
                    "country": country, "vat_number": vat_number, "is_business": True, "is_vat_payer": True,
                    "vies_verified": verified, "custom_vat_rate": Decimal(0), "vat_rate_reason": reason,
                }
                result = TaxService.calculate_vat_for_document(10000, info)
                self.assertEqual(result.scenario, expected)
                if expected == VATScenario.EU_B2C:
                    self.assertEqual(result.vat_rate, TaxService.get_vat_rate("DE"))
                    self.assertEqual(result.notes, ["custom rate override refused: no VIES evidence"])
                    self.assertIn(result.notes[0], result.reasoning)
                else:
                    self.assertEqual(result.vat_cents, 0)
