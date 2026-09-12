"""D390 services-only reconciliation, offline XML validation and authorization."""

from __future__ import annotations

import csv
import hashlib
import io
from dataclasses import replace
from datetime import UTC, date, datetime
from decimal import Decimal
from unittest.mock import patch

from django.test import Client, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone
from lxml import etree

from apps.audit.models import AuditEvent
from apps.billing.d390 import (
    NAMESPACE,
    SCHEMA_DIR,
    D390ExportError,
    Declarant,
    render_d390_xml,
    render_reconciliation_csv,
    validate_d390_xml,
)
from apps.billing.ec_sales_service import ReportingPeriod, aggregate_ec_services
from apps.billing.invoice_models import Invoice, InvoiceLine
from apps.billing.models import Currency, FXRate, Payment
from apps.billing.refund_models import Refund
from apps.billing.tax_evidence import capture_vat_evidence
from apps.common.tax_service import TaxService
from apps.customers.models import Customer
from tests.factories.core_factories import create_staff_user

PERIOD = ReportingPeriod(2026, 8)
DECLARANT = Declarant("Popescu", "Ana", "Contabil")
SUPPLIER = {
    "COMPANY_NAME": "Example Hosting SRL",
    "EFACTURA_COMPANY_CUI": "RO16397040",
    "COMPANY_STREET": "Strada Exemplu 1",
    "COMPANY_CITY": "Bucuresti",
    "COMPANY_POSTAL_CODE": "010101",
    "COMPANY_COUNTRY_CODE": "RO",
}


class D390FixtureMixin:
    def make_invoice(  # noqa: PLR0913  # Independent fiscal fixture dimensions used by the regression matrix.
        self,
        *,
        amounts=(10000,),
        country="DE",
        vat="DE136695976",
        name="Example GmbH",
        discount=0,
        tax_point=date(2026, 8, 15),
        issue=True,
        evidence=True,
        currency="RON",
        **overrides,
    ):
        customer = Customer.objects.create(
            name=name, company_name=name, customer_type="company", primary_email="d390@example.com", status="active"
        )
        money, _ = Currency.objects.get_or_create(code=currency, defaults={"symbol": currency, "decimals": 2})
        if currency != "RON":
            ron, _ = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei", "decimals": 2})
            FXRate.objects.get_or_create(
                base_code=money,
                quote_code=ron,
                as_of=date(2026, 8, 14),
                defaults={
                    "rate": Decimal("5.12345678"),
                    "source": "bnr",
                    "source_reference": "https://bnr.ro/test",
                    "fetched_at": timezone.now(),
                },
            )
        net = sum(amounts) - discount
        result = TaxService.calculate_vat_for_document(
            net,
            {
                "country": country,
                "vat_number": vat,
                "is_business": True,
                "is_vat_payer": True,
            },
        )
        data = {
            "customer": customer,
            "currency": money,
            "number": f"D390-{Invoice.objects.count() + 1}",
            "bill_to_name": name,
            "bill_to_country": country,
            "bill_to_tax_id": vat,
            "bill_to_address1": "Example Street 1",
            "bill_to_city": "Berlin",
            "bill_to_postal": "10115",
            "subtotal_cents": net,
            "tax_cents": 0,
            "total_cents": net,
            "discount_cents": discount,
            "tax_point_date": tax_point,
            "vat_evidence": capture_vat_evidence(result) if evidence else {},
            "issued_at": datetime(2026, 8, 15, 12, tzinfo=UTC),
        }
        data.update(overrides)
        if evidence:
            data["vat_evidence"]["calculated_at"] = (data["issued_at"] or timezone.now()).isoformat()
        invoice = Invoice.objects.create(**data)
        for amount in amounts:
            InvoiceLine.objects.create(
                invoice=invoice,
                kind="service",
                description="Hosting services",
                quantity=1,
                unit_price_cents=amount,
                tax_rate=0,
                tax_category_code="AE",
            )
        if issue:
            invoice.issue()
            invoice.save()
        return invoice

    def assert_blocked(self, code):
        report = aggregate_ec_services(PERIOD)
        self.assertFalse(report.can_export)
        self.assertTrue(any(code in exc.codes for exc in report.exceptions), report.exceptions)
        report.assert_reconciled()
        with self.assertRaises(D390ExportError):
            render_d390_xml(report, DECLARANT)
        return report


@override_settings(**SUPPLIER)
class ECSalesAggregationTests(D390FixtureMixin, TestCase):
    def test_group_multiple_invoices_and_partners_round_after_aggregation(self):
        self.make_invoice(amounts=(1049,))
        self.make_invoice(amounts=(1049,))
        self.make_invoice(amounts=(1050,), country="EL", vat="EL094259216", name="Example Hellas", issue=False)
        greek = Invoice.objects.last()
        # The engine takes the ISO country GR; the VAT identity accepts GR/EL.
        greek.bill_to_country = "GR"
        greek.vat_evidence = capture_vat_evidence(
            TaxService.calculate_vat_for_document(
                1050,
                {
                    "country": "GR",
                    "vat_number": "EL094259216",
                    "is_business": True,
                    "is_vat_payer": True,
                },
            )
        )
        greek.vat_evidence["calculated_at"] = greek.issued_at.isoformat()
        greek.issue()
        greek.save()
        report = aggregate_ec_services(PERIOD)
        self.assertTrue(report.can_export, report.exceptions)
        self.assertEqual(len(report.contributions), 3)
        self.assertEqual([(p.country, p.rounded_ron) for p in report.partners], [("DE", 21), ("EL", 11)])
        self.assertEqual(report.base_ron, Decimal("31.48"))
        self.assertEqual(report.rounding_difference, Decimal("0.52"))
        self.assertEqual(report.partners[1].vat_body, "094259216")

    def test_tax_point_controls_month_including_late_issue_and_overdue(self):
        invoice = self.make_invoice(tax_point=date(2026, 8, 31), issued_at=datetime(2026, 9, 2, tzinfo=UTC))
        invoice.mark_overdue()
        invoice.save(update_fields=["status"])
        self.make_invoice(tax_point=date(2026, 9, 1))
        self.make_invoice(issue=False)
        report = aggregate_ec_services(PERIOD)
        self.assertEqual([line.invoice_id for line in report.contributions], [invoice.pk])

    def test_previous_period_uses_romanian_calendar_and_year_boundary(self):
        with patch(
            "apps.billing.ec_sales_service.timezone.now", return_value=datetime(2026, 1, 31, 22, 30, tzinfo=UTC)
        ):
            self.assertEqual(ReportingPeriod.previous(), ReportingPeriod(2026, 1))
        with patch("apps.billing.ec_sales_service.timezone.now", return_value=datetime(2025, 12, 31, 23, tzinfo=UTC)):
            self.assertEqual(ReportingPeriod.previous(), ReportingPeriod(2025, 12))

    def test_missing_tax_point_is_not_silently_assigned_creation_month(self):
        invoice = self.make_invoice(issue=False, tax_point=None)
        # Represent a historical issued record with no tax-point snapshot.
        Invoice.objects.filter(pk=invoice.pk).update(status="issued")
        self.assert_blocked("missing_tax_point")
        self.assertTrue(aggregate_ec_services(ReportingPeriod(2026, 7)).exceptions)

    def test_legacy_zero_vat_and_manual_documents_remain_unknown(self):
        self.make_invoice(evidence=False)
        self.assert_blocked("missing_reverse_charge_decision")

    def test_eu_zero_vat_without_id_is_an_exception(self):
        self.make_invoice(vat="", evidence=False)
        self.assert_blocked("missing_vat_identity")

    def test_vat_prefix_mismatch_and_bad_checksums_are_blocked(self):
        self.make_invoice(vat="FR40303265045")
        self.assert_blocked("unsupported_country")
        self.make_invoice(vat="DE123456789")
        self.assert_blocked("invalid_vat_number")

    def test_country_and_vat_format_normalization_preserves_leading_zero(self):
        self.make_invoice(country="GR", vat="GR 094.259.216")
        report = aggregate_ec_services(PERIOD)
        self.assertTrue(report.can_export, report.exceptions)
        self.assertEqual(report.partners[0].country, "EL")
        self.assertEqual(report.partners[0].vat_body, "094259216")

    def test_northern_ireland_services_never_qualify(self):
        invoice = self.make_invoice(country="XI", vat="XI123456789", issue=False)
        # Explicit but inconsistent historical AE must be reviewed, not reclassified as goods.
        invoice.issue()
        invoice.save()
        self.assert_blocked("unsupported_country")

    def test_conflicting_names_require_review_without_duplicate_contributions(self):
        self.make_invoice()
        self.make_invoice(name="Different GmbH")
        report = self.assert_blocked("conflicting_partner_names")
        self.assertEqual(len(report.exceptions), 2)
        self.assertFalse(report.contributions)

    def test_supported_discount_allocated_once_across_lines(self):
        self.make_invoice(amounts=(1001, 2002, 3003), discount=101)
        report = aggregate_ec_services(PERIOD)
        self.assertTrue(report.can_export, report.exceptions)
        self.assertEqual(sum(line.discount_cents for line in report.contributions), 101)
        self.assertEqual(report.base_ron, Decimal("59.05"))

    def test_mixed_category_discount_blocks_all_affected_candidates(self):
        invoice = self.make_invoice(amounts=(1000, 2000), discount=100, issue=False)
        invoice.lines.order_by("pk").last().delete()
        InvoiceLine.objects.create(
            invoice=invoice,
            kind="misc",
            description="Goods",
            quantity=1,
            unit_price_cents=2000,
            tax_rate=0,
            tax_category_code="K",
        )
        invoice.issue()
        invoice.save()
        report = self.assert_blocked("mixed_discount")
        self.assertEqual(len(report.exceptions), 2)

    def test_unsupported_adjustments_and_line_kinds_block_export(self):
        invoice = self.make_invoice(issue=False, meta={"allowances": [{"amount": 50}]})
        invoice.lines.update(kind="credit", discount_amount_cents=50)
        invoice.issue()
        invoice.save()
        self.assert_blocked("unsupported_adjustment")
        self.assert_blocked("unsupported_line_kind")

    def test_invoice_line_and_decision_disagreement_is_detected(self):
        invoice = self.make_invoice(issue=False)
        invoice.lines.update(unit_price_cents=10001)
        invoice.vat_evidence["total_cents"] += 1
        invoice.issue()
        invoice.save()
        self.assert_blocked("invalid_evidence")
        self.assert_blocked("line_amount_mismatch")

    def test_snapshot_identity_is_not_rebuilt_from_customer(self):
        invoice = self.make_invoice()
        invoice.customer.company_name = "Changed Company"
        invoice.customer.save(update_fields=["company_name"])
        self.assertTrue(aggregate_ec_services(PERIOD).can_export)

    def test_foreign_currency_uses_snapshot_without_rounding_each_line(self):
        self.make_invoice(amounts=(101, 201), currency="EUR")
        report = aggregate_ec_services(PERIOD)
        self.assertTrue(report.can_export, report.exceptions)
        self.assertEqual(report.base_ron, Decimal("15.4728394756"))
        self.assertEqual(report.rounded_ron, 15)
        FXRate.objects.update(rate=Decimal("9.0"))
        self.assertEqual(aggregate_ec_services(PERIOD).source_fingerprint, report.source_fingerprint)

    def test_missing_foreign_rate_is_blocked_without_network_lookup(self):
        invoice = self.make_invoice(currency="EUR", issue=False)
        Invoice.objects.filter(pk=invoice.pk).update(status="issued", locked_at=timezone.now())
        with patch(
            "apps.billing.exchange_rate_service.ExchangeRateService.resolve",
            side_effect=AssertionError("network lookup"),
        ):
            self.assert_blocked("missing_exchange_rate")

    def test_rounding_to_zero_is_a_visible_exception(self):
        self.make_invoice(amounts=(49,))
        self.assert_blocked("zero_rounded_base")

    def test_refund_event_on_older_supply_blocks_current_month_without_netting(self):
        invoice = self.make_invoice(tax_point=date(2026, 7, 10))
        refund = Refund.objects.create(
            customer=invoice.customer,
            invoice=invoice,
            currency=invoice.currency,
            amount_cents=1000,
            original_amount_cents=10000,
        )
        Refund.objects.filter(pk=refund.pk).update(created_at=datetime(2026, 8, 20, tzinfo=UTC))
        report = self.assert_blocked("outside_period_adjustment")
        self.assertFalse(report.contributions)
        self.assertFalse(report.candidate_line_ids)
        self.assertEqual(report.exceptions[0].invoice_id, invoice.pk)
        another = Refund.objects.create(
            customer=invoice.customer,
            invoice=invoice,
            currency=invoice.currency,
            amount_cents=2000,
            original_amount_cents=10000,
        )
        Refund.objects.filter(pk=another.pk).update(created_at=datetime(2026, 8, 21, tzinfo=UTC))
        changed = aggregate_ec_services(PERIOD)
        self.assertEqual(len(changed.exceptions), 1)
        self.assertNotEqual(report.source_fingerprint, changed.source_fingerprint)

    def test_recorded_consumer_decision_does_not_create_a_business_candidate(self):
        invoice = self.make_invoice(issue=False, vat="")
        decision = TaxService.calculate_vat_for_document(10000, {"country": "DE", "is_business": False})
        invoice.vat_evidence = capture_vat_evidence(decision)
        invoice.vat_evidence["calculated_at"] = invoice.issued_at.isoformat()
        invoice.lines.update(tax_category_code="S")
        invoice.issue()
        invoice.save()
        self.assertFalse(aggregate_ec_services(PERIOD).candidate_line_ids)

    def test_refunded_invoice_is_never_silently_removed_or_netted(self):
        invoice = self.make_invoice()
        invoice.mark_as_paid()
        invoice.refund_invoice()
        invoice.save(update_fields=["status"])
        report = self.assert_blocked("unresolved_fiscal_adjustment")
        self.assertEqual(len(report.candidate_line_ids), 1)

    def test_unresolved_legacy_refund_metadata_is_never_ignored(self):
        self.make_invoice(meta={"refunds": [{"unreadable": True}]})
        self.assert_blocked("unresolved_fiscal_adjustment")

    def test_malformed_refund_link_is_an_exception(self):
        self.make_invoice(meta={"order_id": "invalid"})
        self.assert_blocked("invalid_refund_links")

    def test_captured_negative_vies_result_requires_review(self):
        invoice = self.make_invoice(issue=False)
        invoice.vat_evidence["vies"] = {"is_valid": False}
        invoice.issue()
        invoice.save()
        self.assert_blocked("conflicting_vat_validation")

    def test_captured_inactive_vies_result_requires_review(self):
        invoice = self.make_invoice(issue=False)
        invoice.vat_evidence["vies"] = {"is_valid": True, "is_active": False, "source": "vies"}
        invoice.issue()
        invoice.save()
        self.assert_blocked("conflicting_vat_validation")

    def test_missing_invoice_lines_are_a_document_exception(self):
        invoice = self.make_invoice(issue=False)
        invoice.lines.all().delete()
        invoice.issue()
        invoice.save()
        self.assert_blocked("missing_lines")

    def test_unknown_evidence_version_is_a_visible_exception(self):
        invoice = self.make_invoice(issue=False)
        invoice.vat_evidence["version"] = 99
        invoice.issue()
        invoice.save()
        self.assert_blocked("invalid_evidence")

    def test_refund_on_payment_blocks_unchanged_invoice_status(self):
        invoice = self.make_invoice()
        payment = Payment.objects.create(
            customer=invoice.customer,
            invoice=invoice,
            currency=invoice.currency,
            amount_cents=10000,
            status="succeeded",
            payment_method="bank",
        )
        Refund.objects.create(
            customer=invoice.customer,
            invoice=invoice,
            payment=payment,
            currency=invoice.currency,
            amount_cents=1000,
            original_amount_cents=10000,
        )
        self.assert_blocked("unresolved_fiscal_adjustment")

    def test_void_after_issue_blocks_but_void_draft_is_excluded(self):
        issued = self.make_invoice()
        issued.void()
        issued.save(update_fields=["status"])
        draft = self.make_invoice(issue=False, issued_at=None)
        draft.void()
        draft.save(update_fields=["status"])
        report = self.assert_blocked("unresolved_fiscal_adjustment")
        self.assertEqual(len(report.candidate_line_ids), 1)

    def test_empty_period_does_not_fabricate_a_declaration(self):
        report = aggregate_ec_services(PERIOD)
        self.assertFalse(report.can_export)
        with self.assertRaises(D390ExportError):
            render_d390_xml(report, DECLARANT)

    def test_determinism_and_candidate_duplicate_guard(self):
        self.make_invoice(amounts=(1000, 2000))
        first, second = aggregate_ec_services(PERIOD), aggregate_ec_services(PERIOD)
        self.assertEqual(first, second)
        self.assertEqual(render_d390_xml(first, DECLARANT), render_d390_xml(second, DECLARANT))
        with self.assertRaises(ValueError):
            replace(first, contributions=first.contributions * 2).assert_reconciled()

    def test_local_xml_schema_and_annex_totals_and_partner_identity(self):
        self.make_invoice(country="GR", vat="EL094259216", name="Example Hellas")
        content = render_d390_xml(aggregate_ec_services(PERIOD), DECLARANT)
        validate_d390_xml(content)
        root = etree.fromstring(content)
        self.assertEqual(root.attrib["d_rec"], "0")
        self.assertEqual(root.attrib["totalPlata_A"], "101")
        row = root.find(f"{{{NAMESPACE}}}operatie")
        self.assertEqual((row.attrib["tara"], row.attrib["codO"]), ("EL", "094259216"))
        self.assertIsNone(root.find(f"{{{NAMESPACE}}}cos"))
        original = etree.XMLSchema(etree.parse(str(SCHEMA_DIR / "d390_12022021.xsd")))
        self.assertFalse(original.validate(root), "The official, unmodified cos requirement must remain pinned.")
        for attr, value in (("d_rec", "1"), ("totalPlata_A", "999"), ("nume_declar", ""), ("cui", "12345678")):
            mutated = etree.fromstring(content)
            mutated.set(attr, value)
            with self.subTest(attr=attr), self.assertRaises(D390ExportError):
                validate_d390_xml(etree.tostring(mutated))

    def test_annex_rejects_duplicate_rows_invalid_country_and_zero_base(self):
        self.make_invoice()
        content = render_d390_xml(aggregate_ec_services(PERIOD), DECLARANT)
        for attr, value in (("tara", "XI"), ("codO", "123456789"), ("tip", "L"), ("baza", "0"), ("denO", "Bad & Name")):
            root = etree.fromstring(content)
            root.find(f"{{{NAMESPACE}}}operatie").set(attr, value)
            with self.subTest(attr=attr), self.assertRaises(D390ExportError):
                validate_d390_xml(etree.tostring(root))

    def test_supplier_and_declarant_are_validated_on_server(self):
        self.make_invoice()
        report = aggregate_ec_services(PERIOD)
        with override_settings(COMPANY_CITY=""), self.assertRaises(D390ExportError):
            render_d390_xml(report, DECLARANT)
        with self.assertRaises(D390ExportError):
            render_d390_xml(report, Declarant("", "Ana", "Contabil"))

    def test_csv_retains_exceptions_and_escapes_spreadsheet_formulas(self):
        self.make_invoice(name="=DANGEROUS")
        self.make_invoice(evidence=False)
        report = aggregate_ec_services(PERIOD)
        rows = list(csv.reader(io.StringIO(render_reconciliation_csv(report).decode("utf-8-sig"))))
        self.assertIn("'=DANGEROUS", str(rows))
        self.assertEqual(sum(row[0] == "exception" for row in rows), 1)
        self.assertEqual(sum(row[0] == "included" for row in rows), 1)


@override_settings(**SUPPLIER)
class D390ViewTests(D390FixtureMixin, TestCase):
    def setUp(self):
        self.url = reverse("billing:d390_report")
        self.user = create_staff_user(username="d390_billing", staff_role="billing")
        self.client.force_login(self.user)

    def post_export(self, action="xml", **overrides):
        report = aggregate_ec_services(PERIOD)
        data = {
            "month": PERIOD.label,
            "source_fingerprint": report.source_fingerprint,
            "action": action,
            "surname": "Popescu",
            "given_name": "Ana",
            "role": "Contabil",
        }
        data.update(overrides)
        return self.client.post(self.url, data)

    def test_billing_preview_links_invoices_and_exports_audited_xml(self):
        invoice = self.make_invoice()
        response = self.client.get(self.url, {"month": PERIOD.label})
        self.assertContains(response, "Services-only draft for accountant review.")
        self.assertContains(response, reverse("billing:invoice_detail", args=[invoice.pk]))
        response = self.post_export()
        self.assertEqual(response.status_code, 200)
        validate_d390_xml(response.content)
        event = AuditEvent.objects.get(action="d390_export")
        self.assertEqual(event.user_id, self.user.pk)
        self.assertEqual(event.metadata["export_sha256"], hashlib.sha256(response.content).hexdigest())

    def test_xml_blocking_cannot_be_bypassed_by_post(self):
        self.make_invoice(evidence=False)
        self.assertEqual(self.post_export().status_code, 400)
        self.assertEqual(self.post_export("csv").status_code, 200)

    def test_changed_source_requires_a_new_preview(self):
        self.make_invoice()
        before = aggregate_ec_services(PERIOD).source_fingerprint
        self.make_invoice()
        self.assertEqual(self.post_export(source_fingerprint=before).status_code, 400)

    def test_unauthorized_roles_cannot_preview_or_download(self):
        self.client.logout()
        self.assertEqual(self.client.get(self.url).status_code, 302)
        support = create_staff_user(username="d390_support", staff_role="support")
        self.client.force_login(support)
        self.assertEqual(self.client.get(self.url).status_code, 302)
        self.assertEqual(self.post_export("csv").status_code, 302)

    def test_csrf_and_export_form_validation(self):
        self.make_invoice()
        csrf_client = Client(enforce_csrf_checks=True)
        csrf_client.force_login(self.user)
        self.assertEqual(csrf_client.post(self.url, {"action": "csv", "month": PERIOD.label}).status_code, 403)
        self.assertEqual(self.post_export(surname="").status_code, 400)
        self.assertEqual(self.post_export(month="2026-99").status_code, 400)
        self.assertEqual(self.post_export(action="anything").status_code, 400)
        self.assertEqual(self.client.get(self.url, {"month": "2020-01"}).status_code, 400)

    def test_empty_state_and_method_constraints(self):
        self.assertContains(self.client.get(self.url, {"month": PERIOD.label}), "No candidate supplies")
        self.assertEqual(self.client.put(self.url).status_code, 405)
